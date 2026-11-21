#!/usr/bin/env python3
# joblens — scheduled-job filesystem lens: does every crontab/launchd/systemd line still
# point at something that exists, that runs, whose interpreter is alive?
# cron fires on time forever; if the script was deleted, moved, renamed, un-execute-bit-ed,
# or its shebang interpreter was uninstalled, the job keeps "running" into nothing —
# silently. cronguard audits config syntax, cronlens reads run history, cronproof pins
# crontab text drift. joblens audits the LAST MILE: schedule line -> filesystem entity.
#
# Verdicts
#   P0    GONE            first token (the program) does not exist on disk
#   P1    SCRIPT_GONE     interpreter alive but the script argument is missing
#   P1    NOT_IN_PATH     bare command not found in the PATH this scheduler would use
#   P1    DEADSHEBANG     script exists, its #! interpreter path does not
#   P1    ENVSHEBANG      #! /usr/bin/env X but X is not in the scheduler's PATH
#   P1    NOEXEC          script lost its execute bit (cron would refuse: Permission denied)
#   P1    SYMLINK_GONE    script is a symlink whose target was deleted
#   P1    PIPE_SEG_GONE   a later pipeline/chain segment points at a missing program
#   P2    TILDE           launchd command contains ~ (launchd does NOT expand it)
#   P2    RELPATH         script referenced by relative path (depends on unknown CWD)
#   P2    RAW_UNPARSED    command line too gnarly to tokenize (manual review)
#   BASE  BL-GONE / BL-REBORN / BL-DRIFTED / BL-NEW / BL-REMOVED / BL-TAMPER
# Exit codes: 0 clean, 1 P1/P2 findings, 2 any P0, 3 environment error
#
# Read-only: the only file joblens writes is the --out path you declare.
#
# Usage
#   joblens.py scan                      audit every scheduled job's filesystem targets
#   joblens.py doctor                    only P0/P1 findings
#   joblens.py baseline --out b.json     pin target identities (paths + content hashes)
#   joblens.py check --baseline b.json   GONE / REBORN / DRIFTED / NEW / REMOVED / TAMPER
#   joblens.py watch --rounds 6          live loop, reports deltas per round
#   joblens.py scan --file crontab.txt --launchd-dir ./plists   offline audit mode
#   joblens.py --json scan               machine output
#   joblens.py selftest                  46 invariant checks, no scheduler needed
#
# Version 1.0.0, MIT. Python 3.7+ stdlib only. macOS / Linux.

import argparse
import hashlib
import json
import os
import plistlib
import re
import shlex
import subprocess
import sys
import tempfile
import time
from datetime import datetime

VERSION = "1.0.1"
TOOL = "joblens"
CRON_DEFAULT_PATH = "/usr/bin:/bin"
BIG_FILE = 2 * 1024 * 1024  # identity by stat signature above this size
# flags whose NEXT token is inline code / expression, never a script path
# (sh -c, osascript -e, node -e/-p, perl -e/-E, ruby -e, php -r, sed -e …)
# v1.0.1: without this, osascript -e 'ObjC.import(…)/path/…' fired a false JL-02
INLINE_TAKE_CODE = {"-c", "-e", "-E", "-r", "-p",
                    "--eval", "--print", "--exec", "--code"}

SEV_ORDER = {"P0": 0, "P1": 1, "P2": 2, "BASE": 3}

# ---------------------------------------------------------------- scheduling sources

def _read_text(path):
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return f.read()


def parse_crontab_text(text, origin):
    """crontab text -> (env dict, jobs list). Tolerates CRLF, comments, env lines."""
    env = {}
    jobs = []
    for i, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$", line)
        if m and " " not in m.group(1):
            env[m.group(1)] = m.group(2).strip().strip('"').strip("'")
            continue
        if line.startswith("@"):
            parts = line.split(None, 1)
            if len(parts) == 2:
                jobs.append({"name": "cron:%s" % parts[1][:48], "source": "cron",
                             "schedule": parts[0], "command": parts[1],
                             "origin": "%s:L%d" % (origin, i)})
            continue
        parts = line.split(None, 5)
        if len(parts) == 6:
            jobs.append({"name": "cron:%s" % parts[5][:48], "source": "cron",
                         "schedule": " ".join(parts[0:5]), "command": parts[5],
                         "origin": "%s:L%d" % (origin, i)})
    return env, jobs


def load_cron(file_override=None):
    """Live: crontab -l (+ best-effort /etc/crontab, /etc/cron.d).
    Offline: --file only. Returns (env, jobs, notes[])."""
    env, jobs, notes = {}, [], []
    if file_override:
        try:
            e, j = parse_crontab_text(_read_text(file_override), file_override)
            env.update(e)
            jobs.extend(j)
        except OSError as e:
            notes.append("crontab file unreadable: %s" % e)
        return env, jobs, notes
    try:
        p = subprocess.run(["crontab", "-l"], capture_output=True, text=True, timeout=15)
        if p.returncode == 0:
            e, j = parse_crontab_text(p.stdout, "crontab -l")
            env.update(e)
            jobs.extend(j)
        else:
            notes.append("no user crontab (%s)" % (p.stderr.strip() or "empty"))
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        notes.append("crontab unavailable: %s" % type(e).__name__)
    for sys_path in ("/etc/crontab",):
        if os.path.isfile(sys_path) and os.access(sys_path, os.R_OK):
            e, j = parse_crontab_text(_read_text(sys_path), sys_path)
            for job in j:
                job["name"] = "syscron:" + job["name"][5:]
            jobs.extend(j)
    if os.path.isdir("/etc/cron.d") and os.access("/etc/cron.d", os.R_OK):
        for fn in sorted(os.listdir("/etc/cron.d")):
            fp = os.path.join("/etc/cron.d", fn)
            if os.path.isfile(fp) and os.access(fp, os.R_OK):
                e, j = parse_crontab_text(_read_text(fp), fp)
                for job in j:
                    job["name"] = "cron.d:" + job["name"][5:]
                jobs.extend(j)
    return env, jobs, notes


def load_launchd(dirs=None):
    """launchd plists with a schedule key -> jobs. dirs=None uses the three live dirs."""
    if dirs is None:
        dirs = [os.path.expanduser("~/Library/LaunchAgents"),
                "/Library/LaunchAgents", "/Library/LaunchDaemons"]
    jobs = []
    for d in dirs:
        if not os.path.isdir(d) or not os.access(d, os.R_OK):
            continue
        for fn in sorted(os.listdir(d)):
            if not fn.endswith(".plist"):
                continue
            fp = os.path.join(d, fn)
            try:
                with open(fp, "rb") as f:
                    pl = plistlib.load(f)
            except Exception:
                continue
            pargs = pl.get("ProgramArguments")
            prog = pl.get("Program")
            if pargs and isinstance(pargs, list) and all(isinstance(x, str) for x in pargs):
                cmd = " ".join(shlex.quote(x) for x in pargs)
            elif isinstance(prog, str):
                cmd = prog
            else:
                continue
            sched = pl.get("StartInterval")
            if sched is not None:
                sched_s = "every %ds" % int(sched)
            elif pl.get("StartCalendarInterval") is not None:
                ci = pl["StartCalendarInterval"]
                if isinstance(ci, list):
                    sched_s = "calendar x%d" % len(ci)
                elif isinstance(ci, dict):
                    sched_s = "calendar %s" % json.dumps(ci, sort_keys=True)
                else:
                    sched_s = "calendar"
            else:
                # v1.0.1: RunAtLoad=true 也是真实调度（登录即跑一次）；
                # netdisk_service 真机案例：App Translocation 临时目录被清，
                # 每次登录 launchd 都会去拉一个早已不存在的二进制——
                # 纯 KeepAlive 过滤会把这类幽灵整个漏掉（真机漏报事故，狗粮实捕）
                if pl.get("RunAtLoad") is True:
                    sched_s = "RunAtLoad"
                else:
                    continue  # not scheduled: keepalive-only agents are out of scope
            label = pl.get("Label") or fn[:-6]
            jobs.append({"name": "launchd:%s" % label, "source": "launchd",
                         "schedule": sched_s, "command": cmd, "origin": fp})
    return jobs


def load_systemd_dir(d):
    """Offline systemd fixtures: pairs of x.timer + x.service with ExecStart=."""
    jobs = []
    if not d or not os.path.isdir(d):
        return jobs
    for fn in sorted(os.listdir(d)):
        if not fn.endswith(".service"):
            continue
        svc = os.path.join(d, fn)
        unit = fn[: -len(".service")]
        try:
            txt = _read_text(svc)
        except OSError:
            continue
        cmd = None
        for line in txt.splitlines():
            s = line.strip()
            if s.startswith("ExecStart="):
                cmd = s[len("ExecStart="):]
                break
        if not cmd:
            continue
        sched = "timer?"
        tfp = os.path.join(d, unit + ".timer")
        if os.path.isfile(tfp):
            try:
                for line in _read_text(tfp).splitlines():
                    s = line.strip()
                    if s.startswith("OnCalendar="):
                        sched = s[len("OnCalendar="):]
                        break
            except OSError:
                pass
        jobs.append({"name": "systemd:%s" % unit, "source": "systemd",
                     "schedule": sched, "command": cmd, "origin": svc})
    return jobs


def load_systemd_live():
    """Linux live: systemctl list-timers -> systemctl cat per unit (best effort)."""
    jobs = []
    try:
        p = subprocess.run(["systemctl", "list-timers", "--all", "--no-pager"],
                           capture_output=True, text=True, timeout=20)
        if p.returncode != 0:
            return jobs
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return jobs
    units = set()
    for line in p.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 5 and "." in parts[-2] and parts[-2].endswith(".timer"):
            units.add(parts[-2])
    for unit in sorted(units)[:200]:
        try:
            q = subprocess.run(["systemctl", "cat", unit], capture_output=True,
                               text=True, timeout=15)
            if q.returncode != 0:
                continue
        except (subprocess.TimeoutExpired):
            continue
        cmd = None
        for line in q.stdout.splitlines():
            s = line.strip()
            if s.startswith("ExecStart="):
                cmd = s[len("ExecStart="):]
                break
        if cmd:
            jobs.append({"name": "systemd:%s" % unit[:-6], "source": "systemd",
                         "schedule": "timer", "command": cmd, "origin": unit})
    return jobs

# ---------------------------------------------------------------- command analysis

VAR_RE = re.compile(r"\$\{(\w+)\}|\$(\w+)")


def interpolate(tok, env):
    def repl(m):
        key = m.group(1) or m.group(2)
        return env.get(key, m.group(0))
    return VAR_RE.sub(repl, tok)


def path_dirs(env, source):
    p = env.get("PATH") or (CRON_DEFAULT_PATH if source == "cron" else os.environ.get("PATH", CRON_DEFAULT_PATH))
    return [x for x in p.split(":") if x]


def which_in(name, dirs):
    for d in dirs:
        fp = os.path.join(d, name)
        if os.path.isfile(fp) and os.access(fp, os.R_OK):
            return fp
    return None


def read_shebang(path):
    """-> (interp_path_or_None, env_name_or_None, raw_line_or_None). None raw = no shebang."""
    try:
        with open(path, "rb") as f:
            head = f.read(120)
    except OSError:
        return None, None, None
    if not head.startswith(b"#!"):
        return None, None, None
    line = head.split(b"\n", 1)[0].decode("utf-8", "replace").strip()
    toks = line[2:].strip().split()
    if not toks:
        return None, None, line
    if toks[0].endswith("env"):
        rest = [t for t in toks[1:] if not t.startswith("-")]
        return None, (rest[0] if rest else None), line
    return toks[0], None, line


def identity(path):
    """Stable identity of a file: sha256 for small readable files, stat signature otherwise."""
    try:
        st = os.stat(path)
        if st.st_size <= BIG_FILE:
            with open(path, "rb") as f:
                return "sha:" + hashlib.sha256(f.read()).hexdigest()
        return "stat:%d:%d:%d" % (st.st_size, st.st_mtime_ns, st.st_ino)
    except OSError:
        try:
            st = os.lstat(path)
            return "lstat:%d:%d" % (st.st_size, st.st_mtime_ns)
        except OSError:
            return "missing"


def strip_redirections(cmd):
    """Remove redirection forms so pipeline segmentation doesn't mistake 2>&1 for a command."""
    out = re.sub(r"\d*&?>{1,2}\s*\S+", " ", cmd)   # >>file, > file, 2>file, &>file, &>>file
    out = re.sub(r"\d*>{1,2}&\d+", " ", out)        # 2>&1, >&2
    out = re.sub(r"\d*<\s*\S+", " ", out)           # <file, 0<file
    return out


def _cmd_is_inline_code(toks):
    """v1.0.1: True when the command is interpreter + inline-code flag + payload
    (sh -c, osascript -e, node -e …). Such commands get no script-path scanning
    and no chained-segment analysis: shell grammar applied to non-shell code
    yields meaningless 'segments' and false P1s."""
    return any(t in INLINE_TAKE_CODE for t in toks)


def analyze_job(job, cron_env):
    """-> dict(target=..., script=..., interp=..., findings=[...])."""
    cmd = (job["command"] or "").strip()
    source = job["source"]
    env = dict(cron_env) if source == "cron" else {}
    findings = []

    # strip env-assignment prefixes: FOO=bar /bin/x -> /bin/x
    toks = []
    try:
        toks = shlex.split(cmd)
    except ValueError:
        findings.append(finding("JL-11", "P2", job, "命令无法分词（引号不配对等），需人工过目",
                                cmd[:100], "整理引号后重跑；本行未做落点审计"))
        return {"target": None, "script": None, "interp": None, "findings": findings}
    while toks and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", toks[0]):
        k, _, v = toks[0].partition("=")
        env.setdefault(k, v.strip('"').strip("'"))
        toks = toks[1:]
    if not toks:
        return {"target": None, "script": None, "interp": None, "findings": findings}

    dirs = path_dirs(env, source)
    target = interpolate(toks[0], env)
    target = os.path.expanduser(target) if source != "launchd" else target

    target_path = None
    tilde_hit = False
    if source == "launchd" and "~" in cmd:
        findings.append(finding("JL-07", "P2", job, "launchd 命令含 ~，launchd 不展开波浪线",
                                cmd[:100], "plist 里写绝对路径（/Users/xxx/...）"))
        tilde_hit = True
    if "/" in target:
        if os.path.exists(target):
            target_path = target
        elif tilde_hit:
            pass  # existence already explained by JL-07; don't double-report
        else:
            findings.append(finding("JL-01", "P0", job, "程序不存在: %s" % target,
                                    job["origin"], "找回文件、改路径，或下线这条任务"))
    else:
        hit = which_in(target, dirs)
        if hit:
            target_path = hit
        else:
            findings.append(finding("JL-03", "P1", job,
                                    "裸命令 %r 在该调度器的 PATH 里找不到（PATH=%s）" % (target, ":".join(dirs)),
                                    job["origin"], "写绝对路径，或在任务环境里补 PATH"))

    # later segments of pipes / chains: resolve each first token too (redirections stripped)
    # v1.0.1: inline-code payloads (osascript -e / node -e / sh -c …) get no
    # chained-segment analysis either: splitting JXA/JS string literals on
    # |, && and ; is shell grammar applied to non-shell code — the "segments"
    # it yields (bare words like 127 out of an IP literal) are meaningless
    seg_tokens = [] if _cmd_is_inline_code(toks) else re.split(
        r"\||&&|\|\||;|&", strip_redirections(cmd))
    if len(seg_tokens) > 1:
        for seg in seg_tokens[1:]:
            seg = seg.strip()
            if not seg:
                continue
            try:
                stoks = shlex.split(seg)
            except ValueError:
                continue
            while stoks and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", stoks[0]):
                stoks = stoks[1:]
            if not stoks:
                continue
            sfirst = interpolate(stoks[0], env)
            if "/" in sfirst:
                if not os.path.exists(os.path.expanduser(sfirst)):
                    findings.append(finding("JL-10", "P1", job,
                                            "链式段程序不存在: %s" % sfirst,
                                            cmd[:100], "后半段的命令已失效，整条任务会在中途断掉"))
            else:
                if not which_in(sfirst, dirs):
                    findings.append(finding("JL-10", "P1", job,
                                            "链式段裸命令找不到: %r" % sfirst,
                                            cmd[:100], "后半段命令不在 PATH，任务会中途断掉"))


    # redirections are not scripts: filter tokens that start with '-' or are redirect targets
    # seed with the command token itself when it IS a script path (has a script
    # extension), so JL-04/05/06 (shebang/interp/exec-bit) also fire for bare-script
    # jobs; interpreter-style targets (/bin/sh, /usr/bin/env, python3) must NOT seed,
    # otherwise the arg-scan (JL-02/JL-08) below is short-circuited
    script_path = target_path if re.search(
        r"\.(sh|py|rb|pl|js|php)$", target) else None
    skip_next = False
    for t in toks[1:]:
        if skip_next:
            skip_next = False
            continue
        if t in INLINE_TAKE_CODE:
            skip_next = True  # next token is inline code, not a script path
            continue
        if re.match(r"^[012&]?>>?", t) or re.match(r"^[012]?<&?$", t) or t in ("<", "&"):
            skip_next = True
            continue
        if re.match(r"^[012&]?>>?.*", t) and not os.path.isfile(t):
            continue  # e.g. >>/var/log/x.log glued form
        if t.startswith("-"):
            continue
        if tilde_hit and "~" in t:
            continue  # already explained by JL-07; expanding it would lie
        cand = os.path.expanduser(interpolate(t, env))
        if "/" not in cand:
            continue  # bare args like --auto are not scripts
        if os.path.islink(cand) and not os.path.exists(cand):
            findings.append(finding("JL-09", "P1", job, "脚本参数是指向空处的软链: %s" % cand,
                                    job["origin"], "重新挂回目标或替换成真实文件"))
            script_path = cand
            break
        if os.path.isfile(cand):
            script_path = cand
            break
        else:
            findings.append(finding("JL-02", "P1", job, "脚本参数不存在: %s" % cand,
                                    job["origin"], "脚本被删/改名/挪走了——恢复它或改这行"))
            script_path = None
            break
    if source == "launchd" and script_path is None and len(toks) > 1 and tilde_hit is False:
        # launchd argv[1] is often the script even without slash-match above
        cand = toks[1]
        if not cand.startswith("~") and os.path.isfile(cand):
            script_path = cand

    # symlink health for the target (JL-01 catches missing files; a dangling
    # symlink at the target position deserves its own precise verdict)
    if target_path is None and "/" in target and os.path.islink(target) \
            and not os.path.exists(target):
        findings.append(finding("JL-09", "P1", job, "落点是指向空处的软链: %s" % target,
                                job["origin"], "重新挂回目标或替换成真实文件"))
        script_path = target

    # relative-path script (no slash anywhere in argv but a file-like arg exists)
    # JL-08 is a STYLE verdict: the finding is "path depends on the scheduler's
    # CWD" -- it must fire whether or not the file happens to exist in the scan
    # process CWD (a relative ref that resolves nowhere from here is the most
    # dangerous form, not a pass)
    if script_path is None and not tilde_hit:
        for t in toks[1:]:
            if t.startswith("-") or not t or "/" in t or "~" in t:
                continue
            cand = os.path.expanduser(interpolate(t, env))
            if re.search(r"\.(sh|py|rb|pl|js|php)$", cand):
                script_path = cand
                findings.append(finding("JL-08", "P2", job,
                                        "脚本用相对路径引用: %s（取决于调度器的工作目录）" % cand,
                                        job["origin"], "改成绝对路径，CWD 不同机器上就是另一个文件"))

    interp_path = None
    if script_path and os.path.isfile(script_path):
        # symlink health
        if os.path.islink(script_path) and not os.path.exists(os.path.realpath(script_path)):
            findings.append(finding("JL-09", "P1", job, "脚本是指向空处的软链: %s" % script_path,
                                    job["origin"], "重新挂回目标或替换成真实文件"))
        else:
            ipath, env_name, _raw = read_shebang(script_path)
            if env_name:
                hit = which_in(env_name, dirs)
                if not hit:
                    findings.append(finding("JL-05", "P1", job,
                                            "shebang 经 env 找解释器 %r：不在调度器 PATH 里" % env_name,
                                            "%s 首行 %s" % (script_path, _raw),
                                            "shebang 写成绝对解释器路径，或补 PATH"))
                else:
                    interp_path = hit
            elif ipath:
                if os.path.islink(ipath) and not os.path.exists(ipath):
                    findings.append(finding("JL-04", "P1", job,
                                            "shebang 解释器是失效软链: %s" % ipath,
                                            "%s 首行 %s" % (script_path, _raw),
                                            "修解释器安装或改 shebang"))
                elif not os.path.exists(ipath):
                    findings.append(finding("JL-04", "P1", job,
                                            "shebang 解释器不存在: %s" % ipath,
                                            "%s 首行 %s" % (script_path, _raw),
                                            "解释器被卸载/挪走——装回或改 shebang"))
                else:
                    interp_path = ipath
        if source == "cron" and not os.access(script_path, os.X_OK):
            findings.append(finding("JL-06", "P1", job, "脚本没有执行位: %s" % script_path,
                                    job["origin"], "chmod +x %s" % script_path))

    return {"target": target_path, "script": script_path, "interp": interp_path,
            "findings": findings}


def finding(code, sev, job, message, evidence, hint=""):
    return {"code": code, "sev": sev, "job": job["name"], "source": job["source"],
            "schedule": job["schedule"], "message": message, "evidence": evidence,
            "hint": hint}

# ---------------------------------------------------------------- identity snapshot

def job_identities(jobs, cron_env):
    out = {}
    for job in jobs:
        r = analyze_job(job, cron_env)
        key = job["name"]
        sig = {
            "target": r["target"],
            "script": r["script"],
            "interp": r["interp"],
            "target_id": identity(r["target"]) if r["target"] else None,
            "script_id": identity(r["script"]) if r["script"] else None,
            "exec_bit": bool(r["script"]) and os.access(r["script"], os.X_OK) if r["script"] else None,
        }
        payload = json.dumps(sig, sort_keys=True, ensure_ascii=False)
        out[key] = {"sig": sig, "hash": hashlib.sha256(payload.encode("utf-8")).hexdigest()}
    return out

# ---------------------------------------------------------------- scan assembly

def collect_all(args):
    notes = []
    cron_env, cron_jobs, n1 = load_cron(args.file)
    notes += n1
    ld_dirs = args.launchd_dir or None
    ld_jobs = load_launchd(ld_dirs)
    sd_jobs = load_systemd_dir(args.systemd_dir)
    if args.file is None and args.launchd_dir is None and args.systemd_dir is None:
        if not args.no_systemd_live:
            sd_jobs += load_systemd_live()
    env = dict(os.environ)
    env.update(cron_env)
    jobs = cron_jobs + ld_jobs + sd_jobs
    return env, jobs, notes


def do_scan(args, quiet_p2=False):
    env, jobs, notes = collect_all(args)
    all_findings = []
    results = {}
    for job in jobs:
        r = analyze_job(job, env)
        results[job["name"]] = r
        for f in r["findings"]:
            if quiet_p2 and f["sev"] == "P2":
                continue
            all_findings.append(f)
    all_findings.sort(key=lambda f: (SEV_ORDER[f["sev"]], f["job"], f["code"]))
    return {"jobs": jobs, "results": results, "findings": all_findings,
            "notes": notes, "env": env}


def render_scan(scan, title="scan"):
    L = []
    jobs = scan["jobs"]
    fs = scan["findings"]
    n_p0 = sum(1 for f in fs if f["sev"] == "P0")
    n_p1 = sum(1 for f in fs if f["sev"] == "P1")
    n_p2 = sum(1 for f in fs if f["sev"] == "P2")
    L.append("# joblens %s — %d 个定时任务落点体检" % (title, len(jobs)))
    for note in scan["notes"]:
        L.append("  [note] %s" % note)
    L.append("")
    by_job = {}
    for f in fs:
        by_job.setdefault(f["job"], []).append(f)
    for job in jobs:
        jf = by_job.get(job["name"], [])
        r = scan["results"][job["name"]]
        if not jf:
            L.append("  [OK]   %s  (%s)" % (job["name"], job["schedule"]))
            continue
        worst = jf[0]["sev"]
        L.append("  [%s] %s  (%s)" % (worst, job["name"], job["schedule"]))
        for f in jf:
            L.append("         %s %s" % (f["code"], f["message"]))
            L.append("           证据: %s" % f["evidence"])
            if f["hint"]:
                L.append("           修复: %s" % f["hint"])
    L.append("")
    L.append("小结: 任务 %d | P0 %d | P1 %d | P2 %d" % (len(jobs), n_p0, n_p1, n_p2))
    return "\n".join(L), (2 if n_p0 else (1 if (n_p1 or n_p2) else 0))

# ---------------------------------------------------------------- baseline

def cmd_baseline(args):
    env, jobs, notes = collect_all(args)
    ident = job_identities(jobs, env)
    base = {
        "tool": TOOL, "version": VERSION,
        "created_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "jobs": {k: v["sig"] for k, v in ident.items()},
        "hashes": {k: v["hash"] for k, v in ident.items()},
        "counts": {"jobs": len(jobs)},
    }
    body = json.dumps(base, sort_keys=True, ensure_ascii=False)
    base["sha256"] = hashlib.sha256(body.encode("utf-8")).hexdigest()
    with open(args.out, "w", encoding="utf-8") as f:
        f.write(json.dumps(base, ensure_ascii=False, indent=1) + "\n")
    print("基线已写入 %s（%d 个任务，含落点身份哈希）" % (args.out, len(jobs)))
    return 0


def baseline_tampered(base):
    copy = dict(base)
    copy.pop("sha256", None)
    body = json.dumps(copy, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(body.encode("utf-8")).hexdigest() != base.get("sha256")


def cmd_check(args):
    try:
        base = json.loads(_read_text(args.baseline))
    except (OSError, ValueError) as e:
        print("基线读不出来: %s" % e, file=sys.stderr)
        return 3
    env, jobs, notes = collect_all(args)
    ident = job_identities(jobs, env)
    events = []
    if baseline_tampered(base):
        events.append({"kind": "BL-TAMPER", "sev": "P1", "job": "-",
                       "msg": "基线文件身份校验失败——基线被人改过，结果不可信，请重新 baseline"})
    old = base.get("jobs", {})
    new = {k: v["sig"] for k, v in ident.items()}
    for key, osig in old.items():
        if key not in new:
            events.append({"kind": "BL-REMOVED", "sev": "P1", "job": key,
                           "msg": "任务从调度源里消失了（被删任务/被清 crontab）"})
            continue
        nsig = new[key]
        if osig.get("target") and not nsig.get("target"):
            events.append({"kind": "BL-GONE", "sev": "P0", "job": key,
                           "msg": "落点程序在基线之后被删除: %s" % osig["target"]})
        elif (not osig.get("target")) and nsig.get("target"):
            events.append({"kind": "BL-REBORN", "sev": "P2", "job": key,
                           "msg": "落点程序恢复了: %s" % nsig["target"]})
        elif osig.get("target") and nsig.get("target") and osig["target"] != nsig["target"]:
            events.append({"kind": "BL-DRIFTED", "sev": "P1", "job": key,
                           "msg": "落点换了路径: %s -> %s" % (osig["target"], nsig["target"])})
        elif osig.get("script_id") != nsig.get("script_id") or osig.get("target_id") != nsig.get("target_id"):
            events.append({"kind": "BL-DRIFTED", "sev": "P1", "job": key,
                           "msg": "落点文件内容被改写: %s" % (nsig.get("script") or nsig.get("target"))})
        elif osig.get("interp") != nsig.get("interp"):
            events.append({"kind": "BL-DRIFTED", "sev": "P1", "job": key,
                           "msg": "shebang 解释器换了: %s -> %s" % (osig.get("interp"), nsig.get("interp"))})
        elif osig.get("exec_bit") != nsig.get("exec_bit") and nsig.get("exec_bit") is not None:
            events.append({"kind": "BL-DRIFTED", "sev": "P1", "job": key,
                           "msg": "执行位翻转: %s (%s->%s)" % (nsig["script"], osig.get("exec_bit"), nsig.get("exec_bit"))})
    for key in new:
        if key not in old:
            events.append({"kind": "BL-NEW", "sev": "P2", "job": key,
                           "msg": "基线之后新增的任务（先看看是谁加的）"})
    order = {"BL-TAMPER": 0, "BL-GONE": 1, "BL-REMOVED": 2, "BL-DRIFTED": 3,
             "BL-NEW": 4, "BL-REBORN": 5}
    events.sort(key=lambda e: (order.get(e["kind"], 9), e["job"]))
    print("# joblens check — 对比基线 %s" % os.path.basename(args.baseline))
    if not events:
        print("  全部一致：任务集与落点身份均无变化")
        return 0
    for e in events:
        print("  [%s][%s] %s" % (e["kind"], e["sev"], e["job"]))
        print("         %s" % e["msg"])
    bad = any(e["kind"] in ("BL-TAMPER", "BL-REMOVED", "BL-DRIFTED") for e in events)
    gone = any(e["kind"] == "BL-GONE" for e in events)
    print("\n小结: 事件 %d" % len(events))
    return 2 if gone else (1 if bad else 0)

# ---------------------------------------------------------------- watch

def cmd_watch(args):
    env, jobs, notes = collect_all(args)
    prev = job_identities(jobs, env)
    print("# joblens watch — %d 任务, %d 轮 x %ds" % (len(jobs), args.rounds, args.interval))
    for rd in range(1, args.rounds + 1):
        time.sleep(args.interval)
        env2, jobs2, _ = collect_all(args)
        cur = job_identities(jobs2, env2)
        deltas = []
        for k in set(prev) | set(cur):
            a, b = prev.get(k), cur.get(k)
            if a is None:
                deltas.append("  [轮%d][BL-NEW] %s" % (rd, k))
            elif b is None:
                deltas.append("  [轮%d][BL-REMOVED] %s" % (rd, k))
            elif a["hash"] != b["hash"]:
                diffs = [f for f in ("target", "script", "interp", "exec_bit")
                         if a["sig"].get(f) != b["sig"].get(f)]
                deltas.append("  [轮%d][BL-DRIFTED] %s (%s)" % (rd, k, ",".join(diffs)))
        if deltas:
            print("\n".join(deltas))
        else:
            print("  [轮%d] 无变化" % rd)
        prev = cur
    return 0

# ---------------------------------------------------------------- json / doctor / selftest

def scan_json(scan):
    out = {
        "tool": TOOL, "version": VERSION,
        "jobs_total": len(scan["jobs"]),
        "notes": scan["notes"],
        "findings": scan["findings"],
        "jobs": [{"name": j["name"], "source": j["source"], "schedule": j["schedule"],
                  "command": j["command"], "origin": j["origin"],
                  "target": scan["results"][j["name"]]["target"],
                  "script": scan["results"][j["name"]]["script"],
                  "interp": scan["results"][j["name"]]["interp"]}
                 for j in scan["jobs"]],
    }
    return json.dumps(out, ensure_ascii=False, indent=1)


def main(argv=None):
    ap = argparse.ArgumentParser(prog="joblens",
                                 description="定时任务落点透镜：每条调度命令指向的东西还在吗、还能跑吗")
    ap.add_argument("--version", action="version", version="joblens %s" % VERSION)
    ap.add_argument("--json", action="store_true", help="machine output (scan)")
    ap.add_argument("--file", help="offline: audit this crontab file instead of live sources")
    ap.add_argument("--launchd-dir", action="append", help="offline: launchd plist dir (repeatable)")
    ap.add_argument("--systemd-dir", help="offline: systemd unit fixture dir")
    ap.add_argument("--no-systemd-live", action="store_true", help="skip systemctl live probe")
    sub = ap.add_subparsers(dest="cmd")
    sub.add_parser("scan", help="全量体检")
    sub.add_parser("doctor", help="只报 P0/P1")
    p_base = sub.add_parser("baseline", help="落点身份基线")
    p_base.add_argument("--out", required=True)
    p_chk = sub.add_parser("check", help="对比基线")
    p_chk.add_argument("--baseline", required=True)
    p_watch = sub.add_parser("watch", help="实况轮询")
    p_watch.add_argument("--rounds", type=int, default=4)
    p_watch.add_argument("--interval", type=int, default=30)
    sub.add_parser("selftest", help="不变量自测")
    args = ap.parse_args(argv)

    if args.cmd == "selftest":
        import selftest  # noqa
        return selftest.run()
    if args.cmd == "baseline":
        return cmd_baseline(args)
    if args.cmd == "check":
        return cmd_check(args)
    if args.cmd == "watch":
        return cmd_watch(args)
    if args.cmd in ("scan", "doctor"):
        scan = do_scan(args, quiet_p2=(args.cmd == "doctor"))
        if args.json and args.cmd == "scan":
            print(scan_json(scan))
            fs = scan["findings"]
            return 2 if any(f["sev"] == "P0" for f in fs) else (1 if fs else 0)
        text, rc = render_scan(scan, title=args.cmd)
        print(text)
        return rc
    ap.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
