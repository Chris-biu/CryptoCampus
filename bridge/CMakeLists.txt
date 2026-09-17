cmake_minimum_required(VERSION 3.16)
project(cc_bridge C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

if(NOT DEFINED OPENHITLS_ROOT)
  set(OPENHITLS_ROOT "/opt/openhitls" CACHE PATH "openHiTLS source root")
endif()

set(HITLS_CRYPTO_INCLUDE "${OPENHITLS_ROOT}/include/crypto")
set(HITLS_BSL_INCLUDE "${OPENHITLS_ROOT}/include/bsl")
set(HITLS_PKI_INCLUDE "${OPENHITLS_ROOT}/include/pki")
set(HITLS_ECC_INCLUDE "${OPENHITLS_ROOT}/crypto/ecc/include")
set(HITLS_BN_INCLUDE "${OPENHITLS_ROOT}/crypto/bn/include")
set(HITLS_SM3_INCLUDE "${OPENHITLS_ROOT}/crypto/sm3/include")
set(HITLS_LIB_DIR "${OPENHITLS_ROOT}/build")

# ---------------------------------------------------------------------------
# 注意：openHiTLS 的“特性宏”不在源码树里。
#   config/macro_config/hitls_build.h 只是一个壳：
#       #if defined(HITLS_CRYPTO_PROVIDER) && defined(HITLS_CONFIG_FILE)
#       #include HITLS_CONFIG_FILE
#       #endif
#   真正的内容由构建期从 cmake/config.h.in 生成 hitls_build_config.h。
# 所以桥接层只加 -I 路径是不够的：crypt_ecc.h / crypt_bn.h 里的
#   #ifdef HITLS_CRYPTO_ECC / HITLS_CRYPTO_BN
# 会把全部内部 ECC/BN 声明编译掉，表现为一大堆
#   error: unknown type name 'ECC_Para' / 'BN_BigNum'
# 这里找到生成出来的 hitls_build_config.h，用 -include 强制前置包含，
# 保证与 libhitls_crypto.so 用的是同一套特性宏。
# 其中 HITLS_SIXTY_FOUR_BITS 决定 BN_UINT 的宽度，而 BN_BigNum 是公开结构体
#   struct BigNum { bool sign; uint32_t size; uint32_t room; uint32_t flag; BN_UINT *data; };
# 布局必须与库一致，否则会内存越界 —— 这也是必须用生成头而不是手写 -D 的原因。
# ---------------------------------------------------------------------------
file(GLOB_RECURSE _hitls_cfg_candidates "${OPENHITLS_ROOT}/hitls_build_config.h")
list(LENGTH _hitls_cfg_candidates _hitls_cfg_count)
message(STATUS "cc_bridge: hitls_build_config.h candidates (${_hitls_cfg_count}): ${_hitls_cfg_candidates}")

set(HITLS_CONFIG_HEADER "")
foreach(_cand ${_hitls_cfg_candidates})
  file(READ "${_cand}" _cand_txt)
  if(_cand_txt MATCHES "(^|\n)[ \t]*#[ \t]*define[ \t]+HITLS_CRYPTO_ECC([ \t\r\n]|$)")
    set(HITLS_CONFIG_HEADER "${_cand}")
    break()
  endif()
endforeach()
if(NOT HITLS_CONFIG_HEADER AND _hitls_cfg_candidates)
  list(GET _hitls_cfg_candidates 0 HITLS_CONFIG_HEADER)
endif()

if(HITLS_CONFIG_HEADER)
  get_filename_component(HITLS_CONFIG_DIR "${HITLS_CONFIG_HEADER}" DIRECTORY)
  message(STATUS "cc_bridge: -include ${HITLS_CONFIG_HEADER}")
else()
  set(HITLS_CONFIG_DIR "")
  message(WARNING
    "cc_bridge: 没找到 hitls_build_config.h（${OPENHITLS_ROOT} 下）。"
    "退回手写特性宏，若仍报 unknown type name 'ECC_Para'/'BN_BigNum'，"
    "请把 ${OPENHITLS_ROOT}/build 的目录清单发给负责人。")
endif()

add_library(cc_bridge SHARED src/cc_bridge.c src/cc_client.c)
target_include_directories(cc_bridge PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/include
  ${HITLS_CRYPTO_INCLUDE}
  ${HITLS_BSL_INCLUDE}
  ${HITLS_PKI_INCLUDE}
  ${HITLS_ECC_INCLUDE}
  ${HITLS_BN_INCLUDE}
  ${HITLS_SM3_INCLUDE}
  # 内部头 #include "hitls_build.h" 需要能找到这个壳文件
  ${OPENHITLS_ROOT}/config/macro_config
  # 生成头所在目录，方便它 include 同目录其它生成头
  ${HITLS_CONFIG_DIR}
)
if(HITLS_CONFIG_HEADER)
  target_compile_options(cc_bridge PRIVATE -include "${HITLS_CONFIG_HEADER}")
else()
  target_compile_definitions(cc_bridge PRIVATE
    HITLS_CRYPTO_ECC HITLS_CRYPTO_BN HITLS_SIXTY_FOUR_BITS)
endif()
target_link_directories(cc_bridge PRIVATE ${HITLS_LIB_DIR})
target_link_libraries(cc_bridge PRIVATE hitls_pki hitls_crypto hitls_bsl)

if(BUILD_TESTING)
  enable_testing()
  add_executable(test_cc_bridge tests/test_cc_bridge.c)
  target_include_directories(test_cc_bridge PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${HITLS_CRYPTO_INCLUDE}
    ${HITLS_BSL_INCLUDE}
    ${HITLS_PKI_INCLUDE}
  )
  target_link_directories(test_cc_bridge PRIVATE ${HITLS_LIB_DIR})
  # 测试文件直接调用 openHiTLS API（CSR 解析/自签校验用 hitls_pki，BSL_SAL_FREE 用 hitls_bsl），
  # 而 cc_bridge 的 PRIVATE 依赖不会传递给消费者，故此处必须显式链接。
  target_link_libraries(test_cc_bridge PRIVATE cc_bridge hitls_pki hitls_crypto hitls_bsl)
  add_test(NAME cc_bridge_kata COMMAND test_cc_bridge)
endif()
