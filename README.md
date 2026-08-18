# Frida 17.17.0 去特征版（不改客户端 / stock client 兼容）

对**原版 frida 17.17.0** 的 frida-server + frida-gadget 进行源码级去特征，
**客户端保持原版**（pip 安装官方 frida 即可连接），无需重编客户端。

> ⚠️ 仅用于**授权的安全测试 / 红队演练**。

## 与"参考项目"（frida-defeatured-release）的区别

参考项目把 D-Bus 总线名 `re.frida.*` 改成 `re.gsvc.*`，导致**客户端必须成套重编**
（官方客户端连不上）。本版本**只改服务端/gadget 自身的进程特征**，端到端协议串的
**运行时值保持不变**，因此原版客户端直接可用：

- **保值混淆**：`frida:rpc` 用 `GLib.Base64.decode` 在运行时还原 —— 二进制无字面量，值不变。
- **直接替换**：线程名、agent .so 名、memfd 名、helper socket 名、默认端口、prgname 等。
- **保留**（客户端协议红线，值必须一致）：`re.frida.*`、`lolcathost`、`frida:stdout/stderr`、
  `frida_dylib_range=`、`Frida/` UA 头等。

## 去除了哪些特征

| 特征 | 原值 | 改为 |
|------|------|------|
| 默认端口 | `27042` | `49374`（客户端用 `-H host:port` 指定） |
| 进程名 prgname | `frida` | `gsvc` |
| 线程名 | `gum-js-loop` / `gmain` / `gdbus` | `js-loop` / `evtloop` / `ipcbus` |
| 线程名 | `frida-gadget` / `frida-gadget-tcp-*` / `frida-gadget-unix` | `gsvc-gadget*` |
| 线程名 | `frida-main-loop` / `frida-eternal-agent` 等 | `gsvc-*` |
| agent 注入资源名 | `frida-agent-arm64.so` 等（App maps 可见） | `gsvc-agent-arm64.so` |
| helper memfd/socket | `frida-helper-32/64`、`/frida-<uuid>` | `gsvc-helper-*`、`/gsvc-*` |
| helper Java 包 + 类名 | `re.frida.Helper` / `re.frida.HelperBackend` | `re.gsvc.Helper` / `re.gsvc.HelperBackend`（含重新编译 dex） |
| helper 内部 D-Bus 名 | `re.frida.Helper` / `/re/frida/Helper` | `re.gsvc.Helper` / `/re/gsvc/Helper`（server↔helper 内部协议，客户端不引用） |
| gadget 显示名 | `Gadget` | `Gsvc` |
| RPC 协议串字面量 | `frida:rpc` | 运行时 base64 还原（值不变） |

## 构建（GitHub Actions）

1. 把本目录推送到 GitHub 仓库，**Actions → build-defeatured-frida-17 → Run workflow**。
2. 两个并行 job 产出两份 artifact：
   - `frida-server-defeatured-17.17.0-android-arm64` —— frida-server
   - `frida-gadget-defeatured-17.17.0-android-arm64` —— frida-server + frida-gadget.so（arm64）+ frida-gadget.so（armeabi-v7a 兼容版）+ frida-inject

> 已实测构建通过（NDK r29）。gadget 构建时**禁用了 minizip 依赖**（APK 资源读取特性，
> 冷门；避免 minizip-ng 在 android 交叉编译下的 zlib/zlib-ng/fseeko 问题）。

## 使用（配合原版客户端）

```bash
# 设备端（需 root）
adb push frida-server /data/local/tmp/fs
adb shell && su
chmod 755 /data/local/tmp/fs
/data/local/tmp/fs -l 0.0.0.0:8888 &

# PC 端（原版 frida 客户端，无需重编）
pip install frida==17.17.0 frida-tools
adb forward tcp:8888 tcp:8888
frida -H 127.0.0.1:8888 -n com.example.app -l hook.js   # attach
frida -H 127.0.0.1:8888 -f com.example.app -l hook.js    # spawn
```

## 已知残留（刻意保留，客户端协议或无法混淆）

- `re.frida.Gadget` / `re.frida.Server` / `re.frida.HostSession*` 等**客户端可见** D-Bus 名 —— 客户端据此通信
  （helper 内部 D-Bus 名 `re.frida.Helper` 已改 `re.gsvc.Helper`，客户端不感知）
- `lolcathost` TLS origin —— 客户端握手用
- agent JS 派发器里的 `frida:rpc` 字面量（frida-gum 运行时，strongR 同款不处理）
- `frida:stdout/stderr`（switch case 无法运行时解码）
- `Frida/` UA/Server 头、`Frida` JS 全局名

## 文件说明

```
de-frida.py                去特征补丁脚本（幂等，frida-core/frida-gum）
tools/regenerate-helper-dex.sh   重新编译 helper dex（spawn 模式需要）
.github/workflows/build.yml      GitHub Actions 构建流程
```
