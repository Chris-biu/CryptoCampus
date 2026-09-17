#!/usr/bin/env python3
import ctypes
import sys
import os

LIB_PATH = os.path.join(os.path.dirname(__file__), "..", "libhitls_bridge.so")

@ctypes.CFUNCTYPE(None, ctypes.c_char_p, ctypes.c_char_p)
def python_log_callback(step, data_hex):
    print(f"📝 [{step.decode()}] {data_hex.decode()}")

def main():
    print("🔍 测试日志回调机制")
    try:
        c_lib = ctypes.CDLL(LIB_PATH)
        print("✅ 加载动态库成功")
    except OSError as e:
        print(f"⚠️  加载失败（还未编译，正常现象）: {e}")
        print("   等编译后再运行此测试")
        return
    
    c_lib.bridge_register_log_callback.argtypes = [ctypes.CFUNCTYPE(None, ctypes.c_char_p, ctypes.c_char_p)]
    c_lib.bridge_register_log_callback.restype = None
    c_lib.sm3_digest_with_log.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p]
    c_lib.sm3_digest_with_log.restype = ctypes.c_int
    
    callback_ptr = ctypes.CFUNCTYPE(None, ctypes.c_char_p, ctypes.c_char_p)(python_log_callback)
    c_lib.bridge_register_log_callback(callback_ptr)
    print("✅ 回调注册成功")
    
    test_input = b"abc123"
    output = ctypes.create_string_buffer(32)
    ret = c_lib.sm3_digest_with_log(test_input, len(test_input), output)
    
    if ret == 0:
        print(f"✅ 测试完成，输出: {output.raw[:32].hex()}")
    else:
        print(f"❌ 测试失败")

if __name__ == "__main__":
    main()