import subprocess
import re

TARGET_FILE = "demo"

def run_cmd(cmd):
    return subprocess.check_output(cmd).decode()

# 1. 获取 main 函数地址
nm_out = run_cmd(["nm", TARGET_FILE])
main_addr = None
for line in nm_out.splitlines():
    if " main" in line:
        main_addr = int(line.split()[0], 16)
        break
if not main_addr:
    print("[-] 找不到 main 函数地址")
    exit(1)
print(f"[+] main 函数地址: 0x{main_addr:x}")

# 2. 反汇编 main
objdump_out = run_cmd(["objdump", "-d", "--start-address", hex(main_addr), TARGET_FILE])

# 3. 找到 call check_password
call_match = re.search(r"call.*<check_password>", objdump_out)
if not call_match:
    print("[-] 找不到调用 check_password 的指令")
    exit(1)

# 4. 找到 test eax,eax 后的 JE/JNE
after_call = objdump_out[call_match.end():]
test_match = re.search(r"test\s+%eax,%eax", after_call)
if not test_match:
    print("[-] 找不到 test eax,eax")
    exit(1)

after_test = after_call[test_match.end():]
jump_match = re.search(r"([0-9a-f]+):\s+(7[45])\s([0-9a-f]{2})", after_test)  # 74=JE, 75=JNE
if not jump_match:
    print("[-] 找不到 JE/JNE 条件跳转")
    exit(1)

jump_vaddr = int(jump_match.group(1), 16)
opcode = jump_match.group(2)  # 74 或 75
offset_hex = jump_match.group(3)  # 跳转偏移字节
offset_val = int(offset_hex, 16)
if offset_val >= 0x80:
    offset_val -= 0x100  # 有符号数

target_vaddr = jump_vaddr + 2 + offset_val  # 目标地址

print(f"[+] 找到条件跳转: 0x{jump_vaddr:x} ({opcode}) → 0x{target_vaddr:x}")

# 5. 判断目标是不是错误分支（简单判断：目标地址在 puts/printf 调用附近）
is_fail_branch = False
branch_disasm = run_cmd(["objdump", "-d", "--start-address", hex(target_vaddr), TARGET_FILE])
if "puts@plt" in branch_disasm or "printf@plt" in branch_disasm:
    is_fail_branch = True

if not is_fail_branch:
    print("[!] 跳转目标不像是错误分支，谨慎修改")
else:
    print("[+] 确认是错误分支")

# 6. 计算文件偏移
readelf_out = run_cmd(["readelf", "-S", TARGET_FILE])
sec_match = re.search(r"\.text\s+\S+\s+([0-9a-f]+)\s+([0-9a-f]+)", readelf_out)
text_vaddr = int(sec_match.group(1), 16)
text_offset = int(sec_match.group(2), 16)
file_offset = (jump_vaddr - text_vaddr) + text_offset

# 7. 修改：NOP NOP
with open(TARGET_FILE, "r+b") as f:
    f.seek(file_offset)
    orig = f.read(2)
    print(f"[i] 原始字节: {orig.hex()}")
    if orig[0] in (0x74, 0x75):
        f.seek(file_offset)
        f.write(b"\x90\x90")  # NOP NOP
        print("[+] 成功去掉条件跳转（绕过密码验证）")
    else:
        print("[-] 文件中该位置不是 JE/JNE，取消修改")
