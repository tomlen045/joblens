#!/usr/bin/env python3
"""joblens selftest — 全部 fixture 走临时目录，不碰真机调度器（离线模式）。
跑法: python3 selftest.py   （46 条不变量）"""
import json
import os
import plistlib
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
JOBLENS = os.path.join(HERE, "joblens.py")
PY = sys.executable

PASS, FAIL = [], []
FX = {}
CT = None


def setup_fixtures():
    global CT
    d = tempfile.mkdtemp(prefix="joblens-fix-")
    bin_d = os.path.join(d, "bin")
    os.makedirs(bin_d)

    good = os.path.join(d, "good.sh")
    with open(good, "w") as f:
        f.write("#!/bin/sh\necho ok\n")
    os.chmod(good, 0o755)

    deadshebang = os.path.join(d, "deadshebang.sh")
    with open(deadshebang, "w") as f:
        f.write("#!/opt/removed-interpreter/bin/python\necho x\n")
    os.chmod(deadshebang, 0o755)

    envshe = os.path.join(d, "envshe.sh")
    with open(envshe, "w") as f:
        f.write("#!/usr/bin/env python3.999\nprint('x')\n")
    os.chmod(envshe, 0o755)

    noexec = os.path.join(d, "noexec.sh")
    with open(noexec, "w") as f:
        f.write("#!/bin/sh\necho x\n")
    os.chmod(noexec, 0o644)

    symlink_gone = os.path.join(d, "symlink_gone.sh")
    os.symlink(os.path.join(d, "deleted_target.sh"), symlink_gone)

    ld_dir = os.path.join(d, "LaunchAgents")
    os.makedirs(ld_dir)
    with open(os.path.join(ld_dir, "com.tilde.test.plist"), "wb") as f:
        plistlib.dump({"Label": "com.tilde.test",
                       "ProgramArguments": ["/bin/sh", "~/scripts/tilde_task.sh"],
                       "StartInterval": 300}, f)
    with open(os.path.join(ld_dir, "com.keepalive.only.plist"), "wb") as f:
        plistlib.dump({"Label": "com.keepalive.only",
                       "ProgramArguments": ["/bin/sh", "-c", "echo x"],
                       "KeepAlive": True}, f)

    sd_dir = os.path.join(d, "systemd")
    os.makedirs(sd_dir)
    with open(os.path.join(sd_dir, "backup.service"), "w") as f:
        f.write("[Service]\nExecStart=/bin/sh %s\n" % good)
    with open(os.path.join(sd_dir, "backup.timer"), "w") as f:
        f.write("[Timer]\nOnCalendar=*-*-* 03:00:00\n")
    with open(os.path.join(sd_dir, "gone.service"), "w") as f:
        f.write("[Service]\nExecStart=%s\n" % os.path.join(d, "deleted_prog"))

    CT = os.path.join(d, "ct.txt")
    FX.update({"root": d, "bin": bin_d, "good": good, "deadshebang": deadshebang,
               "envshe": envshe, "noexec": noexec, "symlink_gone": symlink_gone,
               "ld_dir": ld_dir, "sd_dir": sd_dir})


def ct_text(extra=""):
    return "PATH=%s:/usr/bin:/bin\n\n* * * * * /bin/sh %s\n%s" % (FX["bin"], FX["good"], extra)


def write_ct(text):
    with open(CT, "w") as f:
        f.write(text)


def run(args, timeout=120):
    p = subprocess.run([PY, JOBLENS] + args, capture_output=True, text=True, timeout=timeout)
    return p.returncode, p.stdout, p.stderr


def scan(extra_ct="", offline_extra=None):
    write_ct(ct_text(extra_ct))
    args = ["--file", CT, "--launchd-dir", FX["ld_dir"],
            "--systemd-dir", FX["sd_dir"], "--no-systemd-live", "scan"]
    if offline_extra:
        args = ["--file", CT, "--launchd-dir", FX["ld_dir"],
                "--systemd-dir", FX["sd_dir"], "--no-systemd-live"] + offline_extra
    return run(args)


CLEAN = {}


def setup_clean():
    """A second, finding-free fixture set: no tilde, no gone unit."""
    d = tempfile.mkdtemp(prefix="joblens-clean-")
    good2 = os.path.join(d, "good2.sh")
    with open(good2, "w") as f:
        f.write("#!/bin/sh\necho ok\n")
    os.chmod(good2, 0o755)
    ld = os.path.join(d, "LaunchAgents")
    os.makedirs(ld)
    with open(os.path.join(ld, "com.clean.t.plist"), "wb") as f:
        plistlib.dump({"Label": "com.clean.t",
                       "ProgramArguments": ["/bin/sh", good2],
                       "StartInterval": 600}, f)
    sd = os.path.join(d, "systemd")
    os.makedirs(sd)
    with open(os.path.join(sd, "cleanjob.service"), "w") as f:
        f.write("[Service]\nExecStart=/bin/sh %s\n" % good2)
    with open(os.path.join(sd, "cleanjob.timer"), "w") as f:
        f.write("[Timer]\nOnCalendar=*-*-* 04:00:00\n")
    CLEAN.update({"root": d, "good": good2, "ld": ld, "sd": sd,
                  "ct": os.path.join(d, "ct.txt")})


def scan_clean(cmd=None, extra=(), as_json=False, subcmd="scan"):
    """Run against the clean fixture set only (no launchd dir / systemd dir unless given)."""
    ct = CLEAN["ct"]
    body = "PATH=%s:/usr/bin:/bin\n\n" % os.path.dirname(CLEAN["good"])
    body += (cmd or ("* * * * * /bin/sh %s\n" % CLEAN["good"]))
    for e in extra:
        body += e
    with open(ct, "w") as f:
        f.write(body)
    args = []
    if as_json:
        args.append("--json")
    args += ["--file", ct, "--launchd-dir", CLEAN["ld"],
             "--systemd-dir", CLEAN["sd"], "--no-systemd-live", subcmd]
    return run(args)


def doctor(extra_ct=""):
    write_ct(ct_text(extra_ct))
    return run(["--file", CT, "--launchd-dir", FX["ld_dir"],
                "--systemd-dir", FX["sd_dir"], "--no-systemd-live", "doctor"])


def t(name):
    def deco(fn):
        def run():
            try:
                fn()
                PASS.append(name)
                print("  ok   %s" % name)
            except AssertionError as e:
                FAIL.append((name, str(e)))
                print("  FAIL %s: %s" % (name, e))
            except Exception as e:  # noqa
                FAIL.append((name, "%s: %s" % (type(e).__name__, e)))
                print("  FAIL %s: %s: %s" % (name, type(e).__name__, e))
        return run
    return deco


def main():
    setup_fixtures()
    setup_clean()
    tests = []

    @t("JL-01 首token不存在判P0")
    def _():
        rc, out, err = scan("* * * * * %s/deleted_prog\n" % FX["root"])
        assert "[P0]" in out and "JL-01" in out and "程序不存在" in out, out
    tests.append(_)

    @t("JL-01 P0 使退出码=2")
    def _():
        rc, out, err = scan("* * * * * %s/deleted_prog\n" % FX["root"])
        assert rc == 2, rc
    tests.append(_)

    @t("JL-02 脚本参数不存在")
    def _():
        rc, out, err = scan("* * * * * /bin/sh %s\n" % os.path.join(FX["root"], "missing.py"))
        assert "JL-02" in out and "脚本参数不存在" in out, out
    tests.append(_)

    @t("JL-03 裸命令不在PATH")
    def _():
        rc, out, err = scan("* * * * * totally_missing_cmd --do\n")
        assert "JL-03" in out and "找不到" in out, out
    tests.append(_)

    @t("JL-04 shebang解释器不存在")
    def _():
        rc, out, err = scan("* * * * * %s\n" % FX["deadshebang"])
        assert "JL-04" in out and "解释器不存在" in out, out
    tests.append(_)

    @t("JL-05 env shebang 解释器不在PATH")
    def _():
        rc, out, err = scan("* * * * * %s\n" % FX["envshe"])
        assert "JL-05" in out, out
    tests.append(_)

    @t("JL-06 无执行位")
    def _():
        rc, out, err = scan("* * * * * %s\n" % FX["noexec"])
        assert "JL-06" in out and "chmod +x" in out, out
    tests.append(_)

    @t("JL-07 launchd 波浪线")
    def _():
        rc, out, err = scan()
        assert "JL-07" in out and "launchd 不展开" in out, out
    tests.append(_)

    @t("JL-08 相对路径脚本")
    def _():
        write_ct(ct_text("* * * * * /bin/sh %s\n" % os.path.basename(FX["good"])))
        args = ["--file", CT, "--launchd-dir", FX["ld_dir"], "--systemd-dir", FX["sd_dir"],
                "--no-systemd-live", "scan"]
        rc, out, err = run(args)
        assert "JL-08" in out, out
    tests.append(_)

    @t("JL-09 失效软链")
    def _():
        rc, out, err = scan("* * * * * %s\n" % FX["symlink_gone"])
        assert "JL-09" in out and "软链" in out, out
    tests.append(_)

    @t("JL-10 管道后半段丢失")
    def _():
        rc, out, err = scan("* * * * * /bin/sh %s | %s/deleted_seg\n" % (FX["good"], FX["root"]))
        assert "JL-10" in out and "链式段" in out, out
    tests.append(_)

    @t("JL-11 引号不配对不崩")
    def _():
        rc, out, err = scan('* * * * * /bin/sh "unclosed\n')
        assert "JL-11" in out, out
        assert rc in (1, 2), rc
    tests.append(_)

    @t("OK 健康任务零finding且退出0")
    def _():
        rc, out, err = scan_clean()
        assert rc == 0, (rc, out)
        assert "[OK]   cron:" in out
        assert "P0 0 | P1 0 | P2 0" in out
    tests.append(_)

    @t("doctor 过滤P2只留P0/P1")
    def _():
        rc, out, err = doctor("* * * * * /bin/echo tilde-not-here\n")
        # fixture set always carries gone.service (JL-01 P0), so doctor must show
        # P0/P1 (rc=2) while filtering BOTH P2 sources: fixture launchd tilde + this one
        assert "JL-07" not in out, out
        assert "JL-01" in out, out  # P0 must survive the P2 filter
        assert rc == 2, rc
    tests.append(_)

    @t("doctor 显示P0/P1")
    def _():
        rc, out, err = doctor("* * * * * %s/deleted_prog\n" % FX["root"])
        assert "JL-01" in out, out
        assert rc == 2, rc
    tests.append(_)

    @t("源: 注释跳过+6字段解析")
    def _():
        rc, out, err = scan("# hello comment\n0 3 * * * /bin/sh %s # tail\n" % FX["good"])
        assert "hello comment" not in out
        assert "cron:/bin/sh" in out
    tests.append(_)

    @t("源: @daily 特殊调度")
    def _():
        rc, out, err = scan("@daily /bin/sh %s\n" % FX["good"])
        assert "@daily" in out
    tests.append(_)

    @t("源: env行不误判为任务")
    def _():
        rc, out, err = scan()  # PATH= line already present and not a job
        assert "任务" in out
        # exactly 1 cron job counted (plus launchd/systemd from fixtures)
        assert "PATH=" not in out.split("小结")[0].split("[OK]")[0]
    tests.append(_)

    @t("源: launchd StartInterval 识别")
    def _():
        rc, out, err = scan()
        assert "launchd:com.tilde.test" in out and "every 300s" in out
    tests.append(_)

    @t("源: launchd keepalive-only 排除")
    def _():
        rc, out, err = scan()
        assert "com.keepalive.only" not in out
        assert "com.tilde.test" in out

    @t("源: launchd RunAtLoad 幽灵必扫出(v1.0.1 真机案例回归)")
    def _():
        # RunAtLoad=true 无 Interval/Calendar：登录即跑，是真实调度不是 keepalive-only；
        # 单元素 argv 指向已消失的程序 = netdisk_service 真机形态，必须判 JL-01 P0
        ld = FX["ld_dir"]
        ghost_prog = os.path.join(FX["root"], "vanished_prog")
        with open(os.path.join(ld, "com.runatload.ghost.plist"), "wb") as f:
            plistlib.dump({"Label": "com.runatload.ghost",
                           "ProgramArguments": [ghost_prog],
                           "RunAtLoad": True}, f)
        rc, out, err = scan()
        assert "com.runatload.ghost" in out, "RunAtLoad job must be scanned (v1.0.1)"
        assert "程序不存在" in out, "missing target must be flagged JL-01"
        assert "[P0]" in out, "ghost runatload job is P0"
        os.remove(os.path.join(ld, "com.runatload.ghost.plist"))
    tests.append(_)

    @t("源: systemd timer配对")
    def _():
        rc, out, err = scan()
        assert "systemd:backup" in out and "03:00:00" in out
    tests.append(_)

    @t("源: systemd 无落点判GONE")
    def _():
        rc, out, err = scan()
        assert "systemd:gone" in out and "程序不存在" in out
    tests.append(_)

    @t("env: crontab PATH 行生效")
    def _():
        write_ct("PATH=%s:/usr/bin:/bin\n\n* * * * * sh_interpreter %s\n" % (FX["bin"], FX["good"]))
        # create interpreter in fixture bin
        interp = os.path.join(FX["bin"], "sh_interpreter")
        with open(interp, "w") as f:
            f.write("#!/bin/sh\necho x\n")
        os.chmod(interp, 0o755)
        rc, out, err = run(["--file", CT, "--launchd-dir", FX["ld_dir"],
                            "--systemd-dir", FX["sd_dir"], "--no-systemd-live", "scan"])
        # point of the test: crontab PATH line makes the bare command resolve -> no JL-03.
        # rc is 2, never 0/1: fixture systemd dir always carries gone.service (JL-01 P0),
        # and the launchd fixture dir always carries the tilde plist (JL-07 P2)
        assert "JL-03" not in out, out
        assert rc == 2, rc
    tests.append(_)

    @t("env: 默认PATH不含fixture bin")
    def _():
        write_ct("* * * * * sh_interpreter %s\n" % FX["good"])
        rc, out, err = run(["--file", CT, "--launchd-dir", FX["ld_dir"],
                            "--systemd-dir", FX["sd_dir"], "--no-systemd-live", "scan"])
        assert "JL-03" in out, out
    tests.append(_)

    @t("env: ${VAR} 与 $VAR 插值")
    def _():
        rc, out, err = scan_clean(None, extra=["\nSCRIPT=%s\n" % ""])
        # simpler: write ct directly with variable lines
        ct = CLEAN["ct"]
        with open(ct, "w") as f:
            f.write("PATH=%s:/usr/bin:/bin\nSCRIPT=%s\n\n* * * * * /bin/sh ${SCRIPT}\n"
                    % (os.path.dirname(CLEAN["good"]), CLEAN["good"]))
        rc, out, err = run(["--file", ct, "--launchd-dir", CLEAN["ld"],
                            "--systemd-dir", CLEAN["sd"], "--no-systemd-live", "scan"])
        assert rc == 0, out
        with open(ct, "w") as f:
            f.write("PATH=%s:/usr/bin:/bin\nSCRIPT=%s\n\n* * * * * /bin/sh $SCRIPT\n"
                    % (os.path.dirname(CLEAN["good"]), CLEAN["good"]))
        rc, out, err = run(["--file", ct, "--launchd-dir", CLEAN["ld"],
                            "--systemd-dir", CLEAN["sd"], "--no-systemd-live", "scan"])
        assert rc == 0, out
    tests.append(_)

    @t("env: 前置FOO=bar剥离")
    def _():
        rc, out, err = scan_clean("* * * * * LOGLEVEL=debug /bin/sh %s\n" % CLEAN["good"])
        assert rc == 0, out
    tests.append(_)

    @t("trap: 重定向目标不误判脚本")
    def _():
        rc, out, err = scan_clean("* * * * * /bin/sh %s >> /var/log/no_dir/x.log 2>&1\n" % CLEAN["good"])
        assert "JL-02" not in out, out
        assert "JL-10" not in out, out
        assert rc == 0, out
    tests.append(_)

    @t("trap: -c 内联payload不算脚本")
    def _():
        rc, out, err = scan_clean("* * * * * /bin/sh -c 'echo hi'\n")
        assert rc == 0, out
    tests.append(_)

    @t("trap: 带空格路径shlex切分")
    def _():
        space_d = os.path.join(CLEAN["root"], "App With Space.app", "Contents", "MacOS")
        os.makedirs(space_d, exist_ok=True)
        sp = os.path.join(space_d, "Agent Bin")
        with open(sp, "w") as f:
            f.write("#!/bin/sh\necho x\n")
        os.chmod(sp, 0o755)
        rc, out, err = scan_clean('* * * * * "%s"\n' % sp)
        assert rc == 0, out
    tests.append(_)

    @t("trap: 无shebang可执行不误报")
    def _():
        noshe = os.path.join(CLEAN["root"], "noshe.sh")
        with open(noshe, "w") as f:
            f.write("echo x\n")
        os.chmod(noshe, 0o755)
        rc, out, err = scan_clean("* * * * * %s\n" % noshe)
        assert rc == 0, out
    tests.append(_)

    @t("trap: /bin/sh软链至存在的bash不误报")
    def _():
        rc, out, err = scan_clean()
        assert "JL-04" not in out, out  # good.sh uses #!/bin/sh
    tests.append(_)

    @t("trap: 二进制程序(=/bin/echo)不触发解释器检查")
    def _():
        rc, out, err = scan_clean("* * * * * /bin/echo hello\n")
        assert rc == 0, out
    tests.append(_)

    @t("base: 写盘+哈希+计数")
    def _():
        base = os.path.join(FX["root"], "base.json")
        scan()
        rc, out, err = run(["--file", CT, "--launchd-dir", FX["ld_dir"],
                            "--systemd-dir", FX["sd_dir"], "--no-systemd-live",
                            "baseline", "--out", base])
        assert rc == 0
        d = json.load(open(base))
        assert d["counts"]["jobs"] >= 4 and d["sha256"]
    tests.append(_)

    @t("base: check无变化退出0")
    def _():
        base = os.path.join(FX["root"], "base.json")
        scan()
        run(["--file", CT, "--launchd-dir", FX["ld_dir"], "--systemd-dir", FX["sd_dir"],
             "--no-systemd-live", "baseline", "--out", base])
        rc, out, err = run(["--file", CT, "--launchd-dir", FX["ld_dir"],
                            "--systemd-dir", FX["sd_dir"], "--no-systemd-live",
                            "check", "--baseline", base])
        assert rc == 0 and "全部一致" in out, (rc, out)
    tests.append(_)

    @t("base: 删任务抓BL-REMOVED")
    def _():
        base = os.path.join(FX["root"], "b_rm.json")
        scan()
        run(["--file", CT, "--launchd-dir", FX["ld_dir"], "--systemd-dir", FX["sd_dir"],
             "--no-systemd-live", "baseline", "--out", base])
        write_ct("PATH=%s:/usr/bin:/bin\n\n" % FX["bin"])  # cron job gone
        rc, out, err = run(["--file", CT, "--launchd-dir", FX["ld_dir"],
                            "--systemd-dir", FX["sd_dir"], "--no-systemd-live",
                            "check", "--baseline", base])
        assert "BL-REMOVED" in out, out
        assert rc in (1, 2), rc
    tests.append(_)

    @t("base: 新增任务抓BL-NEW")
    def _():
        base = os.path.join(FX["root"], "b_new.json")
        scan()
        run(["--file", CT, "--launchd-dir", FX["ld_dir"], "--systemd-dir", FX["sd_dir"],
             "--no-systemd-live", "baseline", "--out", base])
        scan("*/5 * * * * /bin/echo new-job\n")
        rc, out, err = run(["--file", CT, "--launchd-dir", FX["ld_dir"],
                            "--systemd-dir", FX["sd_dir"], "--no-systemd-live",
                            "check", "--baseline", base])
        assert "BL-NEW" in out, out
    tests.append(_)

    @t("base: 脚本改写抓BL-DRIFTED")
    def _():
        base = os.path.join(FX["root"], "b_drift.json")
        scan()
        run(["--file", CT, "--launchd-dir", FX["ld_dir"], "--systemd-dir", FX["sd_dir"],
             "--no-systemd-live", "baseline", "--out", base])
        with open(FX["good"], "a") as f:
            f.write("echo drifted\n")
        rc, out, err = run(["--file", CT, "--launchd-dir", FX["ld_dir"],
                            "--systemd-dir", FX["sd_dir"], "--no-systemd-live",
                            "check", "--baseline", base])
        assert "BL-DRIFTED" in out, out
        with open(FX["good"], "w") as f:
            f.write("#!/bin/sh\necho ok\n")
    tests.append(_)

    @t("base: 删落点抓BL-GONE P0退出2")
    def _():
        base = os.path.join(FX["root"], "b_gone.json")
        victim = os.path.join(FX["root"], "victim.sh")
        with open(victim, "w") as f:
            f.write("#!/bin/sh\necho x\n")
        os.chmod(victim, 0o755)
        write_ct(ct_text("* * * * * %s\n" % victim))
        run(["--file", CT, "--launchd-dir", FX["ld_dir"], "--systemd-dir", FX["sd_dir"],
             "--no-systemd-live", "baseline", "--out", base])
        os.remove(victim)
        rc, out, err = run(["--file", CT, "--launchd-dir", FX["ld_dir"],
                            "--systemd-dir", FX["sd_dir"], "--no-systemd-live",
                            "check", "--baseline", base])
        assert "BL-GONE" in out and rc == 2, (rc, out)
    tests.append(_)

    @t("base: 篡改基线抓BL-TAMPER")
    def _():
        base = os.path.join(FX["root"], "b_tamper.json")
        scan()
        run(["--file", CT, "--launchd-dir", FX["ld_dir"], "--systemd-dir", FX["sd_dir"],
             "--no-systemd-live", "baseline", "--out", base])
        d = json.load(open(base))
        d["jobs"]["cron:forged"] = {"target": "/bin/evil"}
        json.dump(d, open(base, "w"))
        rc, out, err = run(["--file", CT, "--launchd-dir", FX["ld_dir"],
                            "--systemd-dir", FX["sd_dir"], "--no-systemd-live",
                            "check", "--baseline", base])
        assert "BL-TAMPER" in out, out
    tests.append(_)

    @t("base: 执行位翻转抓DRIFTED")
    def _():
        base = os.path.join(FX["root"], "b_exec.json")
        scan()
        run(["--file", CT, "--launchd-dir", FX["ld_dir"], "--systemd-dir", FX["sd_dir"],
             "--no-systemd-live", "baseline", "--out", base])
        os.chmod(FX["good"], 0o644)
        rc, out, err = run(["--file", CT, "--launchd-dir", FX["ld_dir"],
                            "--systemd-dir", FX["sd_dir"], "--no-systemd-live",
                            "check", "--baseline", base])
        assert "BL-DRIFTED" in out and "执行位" in out, out
        os.chmod(FX["good"], 0o755)
    tests.append(_)

    @t("base: shebang换解释器抓DRIFTED")
    def _():
        base = os.path.join(FX["root"], "b_shebang.json")
        tmp_sh = os.path.join(FX["root"], "swap.sh")
        with open(tmp_sh, "w") as f:
            f.write("#!/bin/sh\necho x\n")
        os.chmod(tmp_sh, 0o755)
        write_ct(ct_text("* * * * * %s\n" % tmp_sh))
        run(["--file", CT, "--launchd-dir", FX["ld_dir"], "--systemd-dir", FX["sd_dir"],
             "--no-systemd-live", "baseline", "--out", base])
        with open(tmp_sh, "w") as f:
            f.write("#!/usr/bin/env python3.999\nprint(1)\n")
        rc, out, err = run(["--file", CT, "--launchd-dir", FX["ld_dir"],
                            "--systemd-dir", FX["sd_dir"], "--no-systemd-live",
                            "check", "--baseline", base])
        assert "解释器换了" in out or "BL-DRIFTED" in out, out
    tests.append(_)

    @t("json: --json结构完整+退出码")
    def _():
        scan("* * * * * %s/deleted_prog\n" % FX["root"])
        rc, out, err = run(["--json", "--file", CT, "--launchd-dir", FX["ld_dir"],
                            "--systemd-dir", FX["sd_dir"], "--no-systemd-live", "scan"])
        d = json.loads(out)
        assert d["tool"] == "joblens" and d["jobs_total"] >= 4
        assert any(f["code"] == "JL-01" and f["sev"] == "P0" for f in d["findings"])
        assert rc == 2
    tests.append(_)

    @t("json: P2-only退出1")
    def _():
        # clean fixture with a single relative-path script (the only P2 producer)
        good_base = os.path.dirname(CLEAN["good"])
        ct = CLEAN["ct"]
        with open(ct, "w") as f:
            f.write("PATH=%s:/usr/bin:/bin\n\n* * * * * /bin/sh good2.sh\n" % good_base)
        rc, out, err = run(["--json", "--file", ct, "--launchd-dir", CLEAN["ld"],
                            "--systemd-dir", CLEAN["sd"], "--no-systemd-live", "scan"])
        d = json.loads(out)
        assert all(f["sev"] != "P0" for f in d["findings"]), d["findings"]
        assert any(f["sev"] == "P2" for f in d["findings"]), d["findings"]
        assert rc == 1, rc
    tests.append(_)

    @t("misc: scan只读不改审计对象")
    def _():
        scan()
        before = os.stat(FX["good"]).st_mtime_ns, open(FX["good"], "rb").read()
        scan()
        after = os.stat(FX["good"]).st_mtime_ns, open(FX["good"], "rb").read()
        assert before == after
    tests.append(_)

    @t("misc: 基线缺失退出3")
    def _():
        scan()
        rc, out, err = run(["--file", CT, "check", "--baseline", "/nonexistent/b.json"])
        assert rc == 3, rc
    tests.append(_)

    @t("misc: watch两轮不崩")
    def _():
        scan()
        rc, out, err = run(["--file", CT, "--launchd-dir", FX["ld_dir"],
                            "--systemd-dir", FX["sd_dir"], "--no-systemd-live",
                            "watch", "--rounds", "2", "--interval", "1"], timeout=90)
        assert rc == 0 and "[轮1]" in out and "[轮2]" in out, out
    tests.append(_)

    @t("misc: 版本号")
    def _():
        rc, out, err = run(["--version"])
        import joblens as _jl
        assert ("joblens %s" % _jl.VERSION) in out + err
    tests.append(_)

    @t("trap: osascript -e 内联payload不误报JL-02(v1.0.1 真机回归)")
    def _():
        # JXA payload 里必然含 ObjC 框架路径风格的 "/"，曾被当成「脚本参数不存在」
        rc, out, err = scan_clean(
            "* * * * * /usr/bin/osascript -e 'ObjC.import(\"stdlib\"); $.system(\"exec /usr/bin/true\")'\n")
        assert rc == 0, (rc, out, err)
        assert "JL-02" not in out, out
        assert "osascript" in out, out  # 任务本身要被扫到
    tests.append(_)

    print("# joblens selftest — %d 条不变量" % len(tests))
    for fn in tests:
        fn()
    print()
    print("PASS %d / FAIL %d" % (len(PASS), len(FAIL)))
    if FAIL:
        for n, msg in FAIL:
            print("  FAILED:", n, "-", msg[:200])
        shutil.rmtree(FX["root"], ignore_errors=True)
        return 1
    shutil.rmtree(FX["root"], ignore_errors=True)
    print("ALL GREEN")
    return 0


if __name__ == "__main__":
    sys.exit(main())
