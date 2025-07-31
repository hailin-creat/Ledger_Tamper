import os
import re
import subprocess
import argparse
import lief
import random
from math import ceil


# ---------------- PRESENT Lightweight Block Cipher ----------------
class PRESENT:
    """
    Implementation of the PRESENT lightweight block cipher.

    Attributes:
        key (int): Initial 80-bit key (only 64-bit used for compatibility with C++).
        start_value (int): Starting counter value.
    """
    def __init__(self, key, start_value):
        self.key = key
        self.start_value = start_value
        self.s_box = [
            0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD,
            0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2
        ]

    def add_round_key(self, state, key):
        """XOR the state with the high 64 bits of the key."""
        key_high64 = (key >> 16) & 0xFFFFFFFFFFFFFFFF
        return state ^ key_high64

    def sub_bytes(self, state):
        """Apply the S-box substitution to the state."""
        res = 0
        for i in range(16):
            block = (state >> (i * 4)) & 0xF
            res |= self.s_box[block] << (i * 4)
        return res

    def p_layer(self, state):
        """Apply the permutation layer to the state."""
        res = 0
        for i in range(64):
            bit = (state >> i) & 1
            new_pos = (i * 16) % 63 if i != 63 else 63
            res |= bit << new_pos
        return res

    def update_key(self, key, rc):
        """Rotate key, apply S-box, and XOR round counter bits."""
        key = ((key << 61) | (key >> 19)) & 0xFFFFFFFFFFFFFFFFFFFF
        nibble = (key >> 76) & 0xF
        s_val = self.s_box[nibble]
        key = (key & ~(0xF << 76)) | (s_val << 76)
        for i in range(5):
            bit = (rc >> (4 - i)) & 1
            key ^= (bit << (19 - i))
        return key

    def encrypt(self, state, key):
        """Encrypt a 64-bit block using the PRESENT cipher."""
        for rc in range(1, 32):
            state = self.add_round_key(state, key)
            state = self.sub_bytes(state)
            state = self.p_layer(state)
            key = self.update_key(key, rc)
        return self.add_round_key(state, key)

    def generate(self, offset):
        """Generate cipher output for a given offset."""
        plain = (self.start_value + offset) & 0xFFFFFFFFFFFFFFFF
        return self.encrypt(plain, self.key)


# ---------------- Utility Functions ----------------
def compress_to_n_bits(value, n):
    """
    Compress a 64-bit integer into n bits using XOR folding.

    Args:
        value (int): 64-bit value.
        n (int): Target bit width.

    Returns:
        int: Compressed integer.
    """
    bits = format(value, '064b')
    result = 0
    for i, bit in enumerate(bits):
        if bit == '1':
            result ^= (1 << (i % n))
    return result


def run_objdump(path):
    """
    Run objdump to disassemble an ELF executable.

    Args:
        path (str): Path to the ELF file.

    Returns:
        str: objdump output.
    """
    cmd = ["objdump", "-d", path]
    res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if res.returncode != 0:
        raise RuntimeError(res.stderr)
    return res.stdout


# ---------------- Main Process ----------------
def main():
    parser = argparse.ArgumentParser(
        description="Unified Ledger Generator (Compatible with C++ Random Key Logic)"
    )
    parser.add_argument("exe", help="Path to ELF executable file")
    parser.add_argument("--bit", type=int, default=4, help="Compressed bit width (default: 1)")
    args = parser.parse_args()

    exe_path = args.exe
    bit_width = args.bit

    # 1. Parse ELF and find entry point and .text section end
    binary = lief.parse(exe_path)
    entry = binary.entrypoint
    text_section = binary.get_section(".text")
    text_end = text_section.virtual_address + text_section.size

    # 2. Disassemble and extract machine code instructions
    disasm = run_objdump(exe_path)
    regex = re.compile(r'^\s*([0-9a-fA-F]+):\s+([0-9a-fA-F ]+)\s+.*', re.MULTILINE)

    instructions = []
    for line in disasm.splitlines():
        m = regex.match(line)
        if not m:
            continue
        addr = int(m.group(1), 16)
        if entry <= addr <= text_end:
            code = m.group(2).replace(" ", "")
            instructions.append((addr, code))

    if not instructions:
        print("No instructions found.")
        return

    base_addr = instructions[0][0]
    offsets = [addr - base_addr for addr, _ in instructions]

    # 3. Generate random key and counter (C++ compatible: key is only 64-bit)
    key64 = random.getrandbits(64)
    key = key64  # Higher 16 bits are zero
    counter = random.getrandbits(64)
    cipher = PRESENT(key, counter)

    # Save parameters
    with open("parameter.txt", "w") as f:
        f.write(f"Counter: {counter}\n")
        f.write(f"Key: {key64}\n")  # Output only 64-bit integer (C++ compatible)

    # 4. Generate ledger
    ledger_entries = []
    for (offset, (_, code)) in zip(offsets, instructions):
        cipher_val = cipher.generate(offset)
        mc_val = int(code[:16].zfill(16), 16)
        xor_val = cipher_val ^ mc_val
        tag = compress_to_n_bits(xor_val, bit_width)
        if bit_width == 1:
            tag_str = str(tag)
        else:
            hex_width = ceil(bit_width / 4)
            tag_str = format(tag, f'0{hex_width}x')
        ledger_entries.append(f"{tag_str} ({offset})")

    with open("Ledger.txt", "w") as f:
        f.write("%".join(ledger_entries))

    print("✅ Ledger generation completed: leger.txt")


if __name__ == "__main__":
    main()
