# joblens CHANGELOG

## 1.0.1 (2026-11-21)

狗粮版本：真机首扫逮到真幽灵的同时，暴露了扫描器自己的三个盲区——全在本版修掉。

### 新增
- **RunAtLoad 也是调度**：launchd plist 无 StartInterval/StartCalendarInterval 但
  `RunAtLoad=true` 的，纳入扫描（登录即跑一次是真实调度）。真机案例：
  `netdisk_service.plist` 指向 App Translocation 临时目录，目录被清后每次登录
  launchd 都去拉一个不存在的二进制——纯 KeepAlive 过滤把这类幽灵整个漏掉。
  新增回归不变量：RunAtLoad 幽灵必扫出且判 P0。

### 修复
- **内联代码不再误报**：`osascript -e 'ObjC.import(…)'` 的 JXA payload 含
  ObjC 框架路径风格的 `/`，曾被当成「脚本参数不存在」（JL-02）；payload 里的
  IP 字面量 `127.0.0.1` 被链式段分析拆出裸命令 `127` 再报「找不到」（JL-10）。
  现在内联代码命令（`-c/-e/-E/-r/-p/--eval…`）跳过脚本路径扫描与链式段分析。
  新增回归不变量：osascript -e 零误报。
- **selftest 真机泄漏回归**：`scan_clean()` / 两个直写用例没传 fixture 目录，
  load_launchd 落回三个真机目录——「离线自测」实际混入真机任务，此前全绿
  只是真机恰好零 finding。现在 fixture 与真机严格隔离，泄漏任务即失败。
- 版本号不变量改为从模块读，不再硬编码（bump 不再打破自测）。

### 自测
- 48 条不变量全绿（46 + 2 条 v1.0.1 回归）。

## 1.0.0 (2026-11-20)

首发：scan/doctor/baseline/check/watch/selftest 六命令；11 种判决 + 基线六事件；
cron + launchd + systemd 三源；只读零依赖单文件。
