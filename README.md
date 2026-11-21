# joblens · 定时任务落点透镜

**每条定时任务指向的那个文件，今天还在吗？还能跑吗？**

cron 到点永远照跑。脚本被删、被改名、解释器被卸载、执行位被翻转、
launchd 任务指向 App Translocation 临时目录里早已被清走的二进制——
调度器一声不吭，你只会发现「备份怎么没出来」。

joblens 对每条调度命令做**落点体检**：程序在不在、shebang 解释器在不在、
执行位对不对、参数里的脚本在不在、软链悬没悬空。

```
  [P0] launchd:netdisk_service  (RunAtLoad)
         JL-01 程序不存在: /private/var/folders/.../AppTranslocation/.../netdisk_service
           证据: /Users/len/Library/LaunchAgents/netdisk_service.plist
```

（上面是本机真机实捕：百度网盘每次登录都在拉一个早已被清走的二进制）

## 它盯什么

三个调度源，一个不落：

- **cron**（用户 crontab）
- **launchd**（macOS `~/Library/LaunchAgents` / `/Library/LaunchAgents` / `/Library/LaunchDaemons`）
- **systemd**（`.timer` + `.service` 配对，live 与离线 fixture 双模式）

## 11 种判决

| 代码 | 级别 | 含义 |
|---|---|---|
| JL-01 | P0 | 程序不存在（任务到点必炸） |
| JL-02 | P1 | 脚本参数不存在（程序活着，参数里的脚本没了） |
| JL-03 | P1 | 裸命令不在调度器 PATH 里 |
| JL-04 | P1 | shebang 解释器不存在 / 失效软链（`#!/opt/xxx/bin/python` 被卸载） |
| JL-05 | P1 | shebang 经 env 找解释器，但不在调度器 PATH |
| JL-06 | P1 | 脚本没有执行位（cron 不帮你 chmod） |
| JL-07 | P2 | launchd 命令含 `~`（launchd 不展开波浪线） |
| JL-08 | P2 | 脚本用相对路径引用（换台机器 CWD 不同就是另一个文件） |
| JL-09 | P1 | 落点/脚本是指向空处的软链 |
| JL-10 | P1 | 管道/链式命令后半段已失效 |
| JL-11 | — | 引号不配对（本行跳过深审，明示不装懂） |

## 基线六事件（不只看今天，还看「变了没」）

`baseline` 记下每个落点的身份（存在性/大小/哈希/执行位），`check` 对比：

- **BL-GONE**（P0）：基线里有、现在没了
- **BL-REBORN**：死而复生（值得警觉，不是好消息）
- **BL-DRIFTED**：内容/权限变了（哈希不同，可能是被换过）
- **BL-NEW** / **BL-REMOVED**：任务增减
- **BL-TAMPER**：基线文件本身被改（有人动了你的记录）

## 六命令

```
joblens scan                 # 全量体检（P0/P1/P2 全出）
joblens doctor               # 只报 P0/P1（日常巡检用这个）
joblens baseline --out b.json   # 落点身份基线
joblens check --baseline b.json # 对比基线，报六事件
joblens watch --rounds 4 --interval 30   # 实况轮询
joblens selftest             # 48 条不变量自测
```

离线审计（不碰真机调度器）：

```
joblens --file my.crontab --launchd-dir ./fixtures/LaunchAgents \
        --systemd-dir ./fixtures/systemd --no-systemd-live scan
```

`--json` 出机器可读输出，退出码：0 干净 / 1 有 finding / 2 有 P0 / 3 基线缺失。

## 零依赖 · 只读 · 单文件

- Python 3.8+ 标准库，一个第三方包都不装
- **只读设计**：不写你的脚本，不动你的 plist，不碰 crontab
- 单文件 700 余行，`scp` 到任何机器就能跑

## 自测

`python3 selftest.py` —— 48 条不变量，全部走临时目录 fixture，
不碰真机调度器（真机泄漏回归已修：fixture 与真机目录严格隔离）。

## 家族

cronguard 盯配置语法，cronproof 钉 crontab 文本漂移，cronlens 读执行历史——
**joblens 验落点**：调度行指向的文件本体还在不在。四个拼起来，定时任务从
「写的时候对」到「跑的时候还在」才算闭环。

## License

MIT
