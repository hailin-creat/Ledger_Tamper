import subprocess
import re

TARGET_FILE = "demo"

def run_cmd(cmd):
    return subprocess.check_output(cmd).decode()

# 1. Get the address of the main function
nm_out = run_cmd(["nm", TARGET_FILE])
main_addr = None
for line in nm_out.splitlines():
    if " main" in line:
        main_addr = int(line.split()[0], 16)
        break
if not main_addr:
    print("[-] Could not find the address of the main function")
    exit(1)
print(f"[+] Main function address: 0x{main_addr:x}")

# 2. Disassemble main
objdump_out = run_cmd(["objdump", "-d", "--start-address", hex(main_addr), TARGET_FILE])

# 3. Find the call to check_password
call_match = re.search(r"call.*<check_password>", objdump_out)
if not call_match:
    print("[-] Could not find the call to check_password")
    exit(1)

# 4. Find the JE/JNE after 'test eax, eax'
after_call = objdump_out[call_match.end():]
test_match = re.search(r"test\s+%eax,%eax", after_call)
if not test_match:
    print("[-] Could not find 'test eax, eax'")
    exit(1)

after_test = after_call[test_match.end():]
jump_match = re.search(r"([0-9a-f]+):\s+(7[45])\s([0-9a-f]{2})", after_test)  # 74 = JE, 75 = JNE
if not jump_match:
    print("[-] Could not find JE/JNE conditional jump")
    exit(1)

jump_vaddr = int(jump_match.group(1), 16)
opcode = jump_match.group(2)      # 74 or 75
offset_hex = jump_match.group(3)  # jump offset byte
offset_val = int(offset_hex, 16)
if offset_val >= 0x80:
    offset_val -= 0x100  # signed offset

target_vaddr = jump_vaddr + 2 + offset_val  # jump target address

print(f"[+] Found conditional jump: 0x{jump_vaddr:x} ({opcode}) → 0x{target_vaddr:x}")

# 5. Check if the jump target is the failure branch 
# (simple check: target address is near a puts/printf call)
is_fail_branch = False
branch_disasm = run_cmd(["objdump", "-d", "--start-address", hex(target_vaddr), TARGET_FILE])
if "puts@plt" in branch_disasm or "printf@plt" in branch_disasm:
    is_fail_branch = True

if not is_fail_branch:
    print("[!] Jump target does not look like a failure branch, modify with caution")
else:
    print("[+] Confirmed failure branch")

# 6. Calculate the file offset
readelf_out = run_cmd(["readelf", "-S", TARGET_FILE])
sec_match = re.search(r"\.text\s+\S+\s+([0-9a-f]+)\s+([0-9a-f]+)", readelf_out)
text_vaddr = int(sec_match.group(1), 16)
text_offset = int(sec_match.group(2), 16)
file_offset = (jump_vaddr - text_vaddr) + text_offset

# 7. Patch: replace with NOP NOP
with open(TARGET_FILE, "r+b") as f:
    f.seek(file_offset)
    orig = f.read(2)
    print(f"[i] Original bytes: {orig.hex()}")
    if orig[0] in (0x74, 0x75):
        f.seek(file_offset)
        f.write(b"\x90\x90")  # NOP NOP
        print("[+] Successfully removed the conditional jump (password check bypassed)")
    else:
        print("[-] The bytes at this location are not JE/JNE, aborting modification")
