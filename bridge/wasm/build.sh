#!/usr/bin/env bash
# =============================================================================
# 把客户端盲签名模块编译成浏览器可加载的 WASM。
#
# 产物：bridge/wasm/dist/cc_client.js + cc_client.wasm（ES module）
#
# 用法：
#   OPENHITLS_ROOT=/path/to/openhitls bash bridge/wasm/build.sh
#
# ── 踩过的坑都在这里，改之前先读 ────────────────────────────────────────────
#
# 1) 特性宏不是签入源码树的，而是 configure 阶段生成的。
#    只用 -I 加目录会让 crypt_ecc.h / crypt_bn.h 的整个文件体被 #ifdef 掉，
#    报一堆 unknown type name。这里同时准备两条路：
#      a. 找得到 hitls_build_config.h 就用 -include 前置包含（和 bridge/CMakeLists.txt 同款）
#      b. 找不到就用 -DHITLS_BUILD_GEN_INFO=ON 生成的 macros.txt 转成 -D 逐个传
#    （macros.txt 由 GEN_INFO 保证产出，所以 b 一定可用。）
#
# 2) HITLS_COMPILE_OPTIONS 是可覆盖的 CACHE 变量。默认值带
#    -Werror/-Wcast-qual/-Wshadow 和 GCC 专用的 --param=ssp-buffer-size=4，
#    clang(Emscripten) 下直接失败，所以整体替换。
#
# 3) -U__unix__ 是必须的，不是随手加的。
#    openHiTLS bsl/sal/src/sal_threadlock.c：
#        #if defined(__linux__) || defined(__APPLE__) || defined(__unix__)
#            return SAL_PthreadRunOnce(onceControl, initFunc);
#        #else
#            // Fallback for no threading support
#    而 SAL_PthreadRunOnce 的声明只在 HITLS_BSL_SAL_LINUX / DARWIN 下可见
#    （同一个文件其它分支用的就是这两个宏）。Emscripten 会定义 __unix__，
#    于是走进 pthread 分支、拿到一个未声明函数；Emscripten 默认带
#    -Werror=implicit-function-declaration，直接编译失败。
#    WASM 本来就该走 #else 的无线程回退分支，所以 -U__unix__ 是语义正确的修法。
#    （sal_threadlock.c 在 bsl/sal/CMakeLists.txt 的核心源列表里，无条件编译，躲不掉。）
#
# 4) 用 HITLS_BUILD_PROFILE=none 做真正的裁剪，只开客户端需要的特性：
#    BSL 的 SAL(内存)+ERR、SM3、BN、ECC(含 SM2 曲线)。
#    这样就不会去编 TLS/PKI/entropy/dlopen/SCTP 这些 wasm 上没必要或有坑的部分。
#    （cmake/hitls_load_preset.cmake 会把用户的 -D 在 preset 之后强制恢复，
#      所以显式传的特性开关不会被 profile 覆盖。）
#    注意：不要显式打开 HITLS_BSL / HITLS_CRYPTO 这种父开关 —— 父开关会把
#    全部子特性一起打开，等于又回到 full profile。
#
# 5) 只建静态库（HITLS_BUILD_SHARED=OFF）。共享库那套 -Wl,-z,.../--build-id/-pie
#    在 wasm-ld 下没有意义，建静态库就绕开了 HITLS_*_LINKER_FLAGS 的识别分支。
#
# 6) 链接时只把 cc_client.c + 需要的 .a 交给 emcc。静态库按需取成员，
#    所以最终 wasm 很小。
# =============================================================================
set -euo pipefail

: "${OPENHITLS_ROOT:?请设置 OPENHITLS_ROOT 指向 openHiTLS 源码树}"

BRIDGE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${OUT_DIR:-$BRIDGE_DIR/wasm/dist}"
BUILD_DIR="${BUILD_DIR:-$BRIDGE_DIR/wasm/build-openhitls}"
SRC="$BRIDGE_DIR/src/cc_client.c"

if [ ! -f "$SRC" ]; then
  echo "找不到 $SRC" >&2
  exit 1
fi

echo "== 环境 =="
echo "OPENHITLS_ROOT = $OPENHITLS_ROOT"
echo "BUILD_DIR      = $BUILD_DIR"
echo "OUT_DIR        = $OUT_DIR"
emcc --version | head -n 2
cmake --version | head -n 1

mkdir -p "$OUT_DIR"

# ------------------------------------------------- 1) 裁剪版静态库（none profile）
emcmake cmake -S "$OPENHITLS_ROOT" -B "$BUILD_DIR" \
  -DCMAKE_BUILD_TYPE=Release \
  -DHITLS_BUILD_PROFILE=none \
  -DHITLS_BUILD_STATIC=ON \
  -DHITLS_BUILD_SHARED=OFF \
  -DHITLS_BUILD_GEN_INFO=ON \
  -DHITLS_COMPILE_OPTIONS="-O2;-U__unix__" \
  -DHITLS_SHARED_LINKER_FLAGS="" \
  -DHITLS_EXE_LINKER_FLAGS="" \
  -DHITLS_BSL_SAL_MEM=ON \
  -DHITLS_BSL_ERR=ON \
  -DHITLS_CRYPTO_SM3=ON \
  -DHITLS_CRYPTO_BN=ON \
  -DHITLS_CRYPTO_ECC=ON \
  -DHITLS_CRYPTO_CURVE_SM2=ON

cmake --build "$BUILD_DIR" --parallel 2

# 诊断：确认我们真正需要的宏都在。少一个，后面 -include/-D 就拿不到声明。
if [ -f "$BUILD_DIR/macros.txt" ]; then
  echo "== 启用的特性宏（我们需要的）=="
  grep -E 'HITLS_(BSL_SAL_MEM|BSL_ERR|CRYPTO_SM3|CRYPTO_BN|CRYPTO_ECC|CRYPTO_CURVE_SM2)$' \
    "$BUILD_DIR/macros.txt" || echo "  !! 一个都没匹配到，检查 macros.txt 格式"
  echo "== macros.txt 前 5 行（确认格式）=="
  head -n 5 "$BUILD_DIR/macros.txt"
fi

# ------------------------------------------------- 2) 特性宏：优先生成头，退回 macros.txt
HITLS_CONFIG_HEADER="$(find "$BUILD_DIR" -name 'hitls_build_config.h' | head -n 1)"
FEATURE_FLAGS=()
if [ -n "$HITLS_CONFIG_HEADER" ]; then
  echo "生成头: $HITLS_CONFIG_HEADER（用 -include 前置包含）"
  FEATURE_FLAGS+=("-include" "$HITLS_CONFIG_HEADER")
elif [ -f "$BUILD_DIR/macros.txt" ]; then
  echo "没有 hitls_build_config.h，改用 macros.txt 转 -D"
  # 末尾的 || true 是必须的：set -e + pipefail 下，grep 没匹配到会让整个赋值返回 1，
  # 脚本会在下面那句友好提示之前直接静默退出（表现为「没有任何输出的 exit 1」，很难查）。
  MACROS="$(tr -d '\r' < "$BUILD_DIR/macros.txt" | grep -E '^[A-Z_][A-Z0-9_]*$' | sort -u || true)"
  if [ -z "$MACROS" ]; then
    echo "macros.txt 里没有解析出宏，把它的前 20 行发我：" >&2
    head -n 20 "$BUILD_DIR/macros.txt" >&2
    exit 1
  fi
  echo "  宏数量: $(printf '%s\n' "$MACROS" | wc -l)"
  while IFS= read -r macro; do
    [ -n "$macro" ] && FEATURE_FLAGS+=("-D$macro")
  done <<< "$MACROS"
else
  echo "既没有 hitls_build_config.h 也没有 macros.txt" >&2
  ls -la "$BUILD_DIR" >&2
  exit 1
fi

# ------------------------------------------------- 3) include 路径
# 基准列表无条件带上。第一项是 cc_client.h 所在处 —— 最初漏了它，
# 链接阶段直接 "'cc_client.h' file not found"。
# 第 2~6 项给 openHiTLS 内部头，最后一项让 crypt_*.h 能 #include "hitls_build.h"。
INC_FLAGS=(
  "-I$BRIDGE_DIR/include"
  "-I$OPENHITLS_ROOT/include/crypto"
  "-I$OPENHITLS_ROOT/include/bsl"
  "-I$OPENHITLS_ROOT/crypto/sm3/include"
  "-I$OPENHITLS_ROOT/crypto/bn/include"
  "-I$OPENHITLS_ROOT/crypto/ecc/include"
  "-I$OPENHITLS_ROOT/config/macro_config"
)
# 再叠加生成的 include_dirs.txt。它解析不出来也不影响上面的基准列表；
# 实测里面是相对路径（所以第一次跑显示「提供 0 个 -I」），不能用它替代基准列表。
if [ -f "$BUILD_DIR/include_dirs.txt" ]; then
  EXTRA_INC=0
  while IFS= read -r dir; do
    if [ -n "$dir" ] && [ -d "$dir" ]; then
      INC_FLAGS+=("-I$dir")
      EXTRA_INC=$((EXTRA_INC + 1))
    fi
  done < <(tr ';' '\n' < "$BUILD_DIR/include_dirs.txt" | tr -d '\r"' \
             | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
  echo "include_dirs.txt 额外提供 $EXTRA_INC 个 -I"
fi

CRYPTO_A="$(find "$BUILD_DIR" -name 'libhitls_crypto*.a' | head -n 1)"
BSL_A="$(find "$BUILD_DIR" -name 'libhitls_bsl*.a' | head -n 1)"
echo "crypto 静态库: ${CRYPTO_A:-<未找到>}"
echo "bsl    静态库: ${BSL_A:-<未找到>}"
if [ -z "$CRYPTO_A" ] || [ -z "$BSL_A" ]; then
  echo "缺少静态库，无法链接。build 目录下的 .a：" >&2
  find "$BUILD_DIR" -name '*.a' >&2 || true
  exit 1
fi

# ------------------------------------------------- 4) 链接成 WASM
echo "== 链接 =="
emcc -O2 \
  "${INC_FLAGS[@]}" \
  "${FEATURE_FLAGS[@]}" \
  -Wno-unused-command-line-argument \
  "$SRC" "$CRYPTO_A" "$BSL_A" \
  -sMODULARIZE=1 \
  -sEXPORT_ES6=1 \
  -sENVIRONMENT=web \
  -sALLOW_MEMORY_GROWTH=1 \
  -sEXPORTED_RUNTIME_METHODS='["ccall","cwrap","HEAPU8","UTF8ToString"]' \
  -sEXPORTED_FUNCTIONS='["_cc_client_version","_cc_client_last_error","_cc_client_blind","_cc_client_unblind","_cc_client_credential","_cc_client_verify","_cc_client_sm3","_cc_client_scalar_is_valid","_cc_client_encode_message","_malloc","_free"]' \
  -o "$OUT_DIR/cc_client.js"

echo "== 产物 =="
ls -la "$OUT_DIR"
echo "完成。前端从 web/src/security/wasm-credential-provider.ts 加载 /wasm/cc_client.js"
