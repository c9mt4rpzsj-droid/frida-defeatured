#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
de-frida.py — Frida 17.17.0 去特征补丁脚本（不改客户端 / stock client 兼容）

与参考项目（frida-defeatured-release，改了 re.frida.* 且客户端必须成套重编）不同，
本版【不修改客户端】：原版 pip frida 客户端可直接连接。

策略分两类：
  A. 保值混淆：frida:rpc 等端到端协议串，用 GLib.Base64 在【运行时】解码还原。
     二进制里没有字面量，但运行时值与 stock 客户端一致 -> 协议兼容。
  B. 直接替换：线程名、agent .so 名、memfd 名、helper socket 名、默认端口、
     prgname、gadget 显示名等纯服务端/设备端特征（客户端不感知）。

刻意保留（客户端协议红线，运行时值必须与 stock 一致，不做值替换）：
  - re.frida.*      D-Bus 总线名（含 re.frida.Gadget，客户端据此发现 gadget）
  - frida:rpc       运行时值（字面量已在 frida-core 侧混淆）
  - frida:stdout/stderr  (agent 消息类型；switch case 无法做运行时解码)
  - lolcathost       TLS origin/SNI（客户端握手用）
  - frida_dylib_range= / frida_gadget_config=  (客户端注入 gadget 时传入的配置键)
  - Frida/ UA/Server 头、Frida JS 全局名、/frida CModule 虚拟路径

用法：
  python de-frida.py            # 应用全部补丁（frida-core / frida-gum）
  python de-frida.py --verify   # 只检查残留，不做修改
"""

import os
import sys
import argparse

ROOT = os.path.dirname(os.path.abspath(__file__))

# 参与替换的源码树（注意：不含 frida-python —— 客户端不改）
TREES = [
    os.path.join(ROOT, "subprojects", "frida-core"),
    os.path.join(ROOT, "subprojects", "frida-gum"),
]

# 需要递归扫描的源码扩展名（二进制/资源文件不处理）
EXTENSIONS = {".c", ".h", ".vala", ".js", ".ts", ".m", ".mm", ".plist",
              ".xcent", ".py", ".meson", ".build", ".rs", ".md", ".txt",
              ".cpp", ".cc", ".hpp", ".java"}

# 无扩展名但也需要处理的文件名
BARE_FILENAMES = {"Makefile", "meson.build", "meson.options"}

# 需要跳过的目录（相对路径片段）
SKIP_DIRS = {".git", "glib-src", "tests", "test"}

# ---------------------------------------------------------------------------
# A. 保值混淆：base64 运行时解码（值不变，二进制无字面量）
#    frida:rpc  ->  GLib.Base64.decode("ZnJpZGE6cnBj")  == "frida:rpc"
#    "frida:rpc"(带引号,JSON内) -> decode("ImZyaWRhOnJwYyI=") == "\"frida:rpc\""
# ---------------------------------------------------------------------------
BASE64_REPLACEMENTS = [
    ('"frida:rpc"', '(string) GLib.Base64.decode("ZnJpZGE6cnBj")'),
    ('"\\"frida:rpc\\""', '(string) GLib.Base64.decode("ImZyaWRhOnJwYyI=")'),
]

# ---------------------------------------------------------------------------
# B. 直接替换：纯服务端/设备端特征（客户端不感知）
#    全部为精确字面量，避免误伤构建目标名 / 头文件 / 资源访问器名。
# ---------------------------------------------------------------------------
REPLACEMENTS = [
    # --- 默认端口（客户端用 -H host:port 显式指定端口，服务端默认值可改）---
    ("DEFAULT_CONTROL_PORT = 27042", "DEFAULT_CONTROL_PORT = 49374"),

    # --- 进程名 prgname（顺带消除 glib 的 pool-frida 线程名）---
    ('g_set_prgname ("frida")', 'g_set_prgname ("gsvc")'),

    # --- 线程名（/proc/<pid>/task/*/comm 可见）---
    ('"gum-js-loop"', '"js-loop"'),
    ('g_thread_new ("frida-gadget"', 'g_thread_new ("gsvc-gadget"'),
    ('"frida-gadget-tcp-%u"', '"gsvc-gadget-tcp-%u"'),
    ('"frida-gadget-unix"', '"gsvc-gadget-unix"'),
    ('g_thread_new ("frida-main-loop"', 'g_thread_new ("gsvc-main-loop"'),
    ('"frida-eternal-agent"', '"gsvc-eternal-agent"'),
    ('"frida-agent-emulated"', '"gsvc-agent-emulated"'),
    ('"frida-agent-container"', '"gsvc-agent-container"'),

    # --- agent 注入资源名（目标 App /proc/self/maps 可见）---
    ("frida-agent-<arch>.so", "gsvc-agent-<arch>.so"),
    ("frida-agent-arm.so", "gsvc-agent-arm.so"),
    ("frida-agent-arm64.so", "gsvc-agent-arm64.so"),

    # --- Android helper memfd（server 进程 /proc/self/maps 可见）---
    # 只改 make_temporary_helper 的 memfd 名字面量，不改 embed-helper.py
    # 的 get_frida_helper_XX_blob 访问器名（改了会编译错）。
    ('make_temporary_helper ("frida-helper-32"', 'make_temporary_helper ("gsvc-helper-32"'),
    ('make_temporary_helper ("frida-helper-64"', 'make_temporary_helper ("gsvc-helper-64"'),
    ('"/data/local/tmp/frida-helper-"', '"/data/local/tmp/gsvc-helper-"'),
    ("localabstract:/frida-helper-", "localabstract:/gsvc-helper-"),

    # --- helper/注入器抽象 unix socket: "/frida-" + uuid ---
    ('"/frida-"', '"/gsvc-"'),

    # --- Android helper Java 包名（spawn 模式 helper 进程，服务端内部）---
    # re.frida.Gadget / re.frida.HostSession17 等 D-Bus 协议名不动。
    ("package re.frida;", "package re.gsvc;"),
    ('"frida-helper <instance-id>"', '"gsvc-helper <instance-id>"'),
    ('"--nice-name=re.frida.helper "', '"--nice-name=re.gsvc.helper "'),
    ('"re.frida.Helper "', '"re.gsvc.Helper "'),

    # --- gadget 进程显示名（enumerate_processes 里可见）---
    ('string name = "Gadget"', 'string name = "Gsvc"'),

    # --- gadget 相关错误串 / 路径（服务端侧，客户端不可见）---
    ("Emulated realm is not supported by frida-gadget",
     "Emulated realm is not supported by gsvc-gadget"),
    ("frida-gadget.so to use", "gsvc-gadget.so to use"),
    ("frida-gadget.dylib to use", "gsvc-gadget.dylib to use"),
    ("/data/local/tmp/frida-gadget-", "/data/local/tmp/gsvc-gadget-"),
]


def iter_source_files(trees, skip_dirs=SKIP_DIRS, exts=EXTENSIONS):
    for tree in trees:
        for dirpath, dirnames, filenames in os.walk(tree):
            dirnames[:] = [d for d in dirnames
                           if d not in skip_dirs and ".git" not in d]
            for fn in filenames:
                if os.path.splitext(fn)[1].lower() not in exts \
                        and fn not in BARE_FILENAMES:
                    continue
                yield os.path.join(dirpath, fn)


def apply_replacements(trees, repls, label, exts=EXTENSIONS):
    changed_files = 0
    total_hits = 0
    for path in iter_source_files(trees, exts=exts):
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                text = f.read()
        except OSError:
            continue

        new_text = text
        hits = 0
        for old, new in repls:
            c = new_text.count(old)
            if c:
                hits += c
                new_text = new_text.replace(old, new)

        if hits:
            with open(path, "w", encoding="utf-8", newline="") as f:
                f.write(new_text)
            changed_files += 1
            total_hits += hits
            rel = os.path.relpath(path, ROOT)
            print(f"[{label}] {rel}: {hits} 处")

    print(f"\n[{label}] 共修改 {changed_files} 个文件，{total_hits} 处替换\n")
    return changed_files, total_hits


def verify(trees):
    """报告残留特征（运行时可被检测的源码，跳过 tests/glib-src）。"""
    print("=" * 70)
    print("残留特征检查（仅列运行时可影响检测的源码，跳过 tests/glib-src）")
    print("=" * 70)
    # 已去除、应 0 命中：gum-js-loop / 27042 / g_set_prgname("frida")
    # 刻意保留（客户端协议，属预期残留）：re.frida. / lolcathost / frida:stdout
    # frida:rpc 在 frida-core 应已混淆（0），但 frida-gum JS 派发器属预期残留。
    patterns = [
        "gum-js-loop", "27042",
        'g_set_prgname ("frida")',
        "frida-agent-arm64.so", "frida-helper-64", "frida-gadget-tcp-",
    ]
    kept_by_design = [
        "re.frida.", "lolcathost", "frida:stdout", "frida:stderr",
        "frida_dylib_range=", "frida_gadget_config=",
    ]
    total = 0
    for path in iter_source_files(trees):
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                text = f.read()
        except OSError:
            continue
        for pat in patterns:
            if pat in text:
                for i, line in enumerate(text.splitlines(), 1):
                    if pat in line:
                        rel = os.path.relpath(path, ROOT)
                        print(f"  [残留] {rel}:{i}: {line.strip()[:100]}")
                        total += 1
    print(f"\n残留匹配行总数: {total}")
    print("刻意保留（客户端协议，不视为残留）："
          + ", ".join(kept_by_design))
    return total


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--verify", action="store_true",
                    help="只检查残留特征，不做修改")
    args = ap.parse_args()

    trees = [t for t in TREES if os.path.isdir(t)]

    if args.verify:
        verify(trees)
        return

    if not trees:
        print("未找到 frida-core / frida-gum 源码树，请先 clone 子模块。")
        sys.exit(1)

    print("== A. 保值混淆（base64 运行时解码，值不变，客户端兼容）==")
    # 只对 vala 做 base64 混淆（GLib.Base64 仅 vala/GLib 环境可用）。
    # JS/TS 运行时派发器里的 frida:rpc 保持字面量（与 strongR 一致，属已知残留）。
    apply_replacements(trees, BASE64_REPLACEMENTS, "base64", exts={".vala"})

    print("== B. 直接替换（服务端/设备端特征）==")
    apply_replacements(trees, REPLACEMENTS, "replace")

    print("补丁应用完成。可运行  python de-frida.py --verify  复查残留。")
    print("提示：glib 线程名 gmain/gdbus 由 workflow 对 glib 源码 sed 处理；")
    print("      helper Java 目录 re/frida -> re/gsvc 由 workflow mv 处理。")


if __name__ == "__main__":
    main()
