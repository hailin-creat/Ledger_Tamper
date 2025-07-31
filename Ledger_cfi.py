import os
import gdb
import sys


class PRESENT:
    """
    Implementation of the PRESENT lightweight block cipher.
    Used for generating dynamic verification values in debugging.
    """

    def __init__(self, key=None, start_value=0):
        """Initialize PRESENT encryption algorithm."""
        self.key = key
        self.start_value = start_value

        # S-box definition
        self.s_box = [
            0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD,
            0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2
        ]

    def load_parameter(self):
        """Load Counter and Key from parameter.txt."""
        parameter_file = "parameter.txt"
        if not os.path.exists(parameter_file):
            print(f"❌ Error: file {parameter_file} not found")
            return

        try:
            with open(parameter_file, 'r') as file:
                for line in file:
                    if line.startswith("Counter:"):
                        self.start_value = int(line.split(":")[1].strip())
                    elif line.startswith("Key:"):
                        self.key = int(line.split(":")[1].strip())
        except Exception as e:
            print(f"❌ Failed to load parameter.txt: {e}")

    def add_round_key(self, state, key):
        """Round key addition."""
        key_high64 = (key >> 16) & 0xFFFFFFFFFFFFFFFF
        return state ^ key_high64

    def sub_byte(self, state):
        """Substitute bytes using S-box."""
        new_state = 0
        for i in range(16):
            block = (state >> (i * 4)) & 0xF
            s_val = self.s_box[block]
            new_state |= (s_val << (i * 4))
        return new_state

    def p_sub(self, state):
        """P-layer permutation."""
        new_state = 0
        for i in range(63):
            bit = (state >> i) & 1
            new_pos = (i * 16) % 63
            new_state |= (bit << new_pos)
        new_state |= (state & (1 << 63))  # Preserve bit 63
        return new_state

    def key_update(self, key, rc_val):
        """Key scheduling and round constant update."""
        key = ((key << 61) | (key >> 19)) & 0xFFFFFFFFFFFFFFFFFFFF
        high_nibble = (key >> 76) & 0xF
        s_val = self.s_box[high_nibble]
        key = (key & ~(0xF << 76)) | (s_val << 76)

        rc_5bit = rc_val & 0x1F
        key ^= ((rc_5bit >> 4) & 1) << 19
        key ^= ((rc_5bit >> 3) & 1) << 18
        key ^= ((rc_5bit >> 2) & 1) << 17
        key ^= ((rc_5bit >> 1) & 1) << 16
        key ^= ((rc_5bit >> 0) & 1) << 15
        return key

    def encrypt(self, state, key):
        """Encrypt a 64-bit block."""
        for rc in range(1, 32):
            state = self.add_round_key(state, key)
            state = self.sub_byte(state)
            state = self.p_sub(state)
            key = self.key_update(key, rc)
        return self.add_round_key(state, key)

    def bitset_to_hex(self, state):
        """Convert state to a hexadecimal string."""
        hex_str = ""
        for i in range(16):
            nibble = (
                ((state >> (i * 4 + 3)) & 1) << 3 |
                ((state >> (i * 4 + 2)) & 1) << 2 |
                ((state >> (i * 4 + 1)) & 1) << 1 |
                (state >> (i * 4)) & 1
            )
            hex_str += f"{nibble:01X}"
        return hex_str

    def present(self, offset_text):
        """Run PRESENT encryption for a given offset."""
        if self.key is None:
            print("❌ Error: Key not initialized")
            return None

        plain = (self.start_value + offset_text) & 0xFFFFFFFFFFFFFFFF
        cipher = self.encrypt(plain, self.key)
        return self.bitset_to_hex(cipher)


class Debugger(gdb.Command, PRESENT):
    """
    Custom GDB debugger command: stepi_hex
    Uses PRESENT encryption to validate execution flow and detect tampering.
    """

    def __init__(self):
        PRESENT.__init__(self)
        super(Debugger, self).__init__("ledgercfi", gdb.COMMAND_USER)

        # ========= Compression bit-width setting =========
        # Change this value manually to adjust tag compression
        self.bit_width = 4  # e.g., 1 for parity check, 4/8/16 for wider tags

        self.text_start = None
        self.ret_stack = []
        self.compressed_file = 'Ledger.txt'
        self.compressed_values = {}
        self.initialize()

    def initialize(self):
        """Initialize compressed ledger values and load key/counter."""
        self.compressed_values = self.load_compressed_values()
        if not self.compressed_values:
            print("❌ Failed to load compressed ledger values")
        else:
            print("✅ Compressed ledger values loaded")
        self.load_parameter()

    def compress_to_n_bits(self, value, n):
        """
        Compress a 64-bit integer into n bits using XOR folding.
        Args:
            value (str): Hex string (e.g., '1a2b3c...')
            n (int): Target bit width
        """
        bits = format(int(value, 16), '064b')
        result = 0
        for i, bit in enumerate(bits):
            if bit == '1':
                result ^= (1 << (i % n))
        return result

    def load_compressed_values(self):
        """Load compressed ledger values from file."""
        if not os.path.exists(self.compressed_file):
            print(f"❌ Error: {self.compressed_file} not found")
            return {}
        try:
            with open(self.compressed_file, 'r') as file:
                compressed_values = {}
                for raw_value in file.read().split('%'):
                    parts = raw_value.strip().split()
                    if len(parts) == 2 and parts[1].startswith('('):
                        if self.bit_width == 1:
                            value = int(parts[0])  # 1-bit parity
                        else:
                            value = int(parts[0], 16)  # multi-bit hex
                        offset = int(parts[1][1:-1])
                        compressed_values[offset] = value
                return compressed_values
        except Exception as e:
            print(f"❌ Error loading compressed ledger: {e}")
            return {}

    def handle_call_instruction(self, pc, insn):
        """Handle 'call' instruction by pushing return address."""
        length = insn.get("length", 0)
        if length == 0:
            try:
                next_insn = gdb.selected_frame().architecture().disassemble(pc + 1, count=1)[0]
                length = next_insn["addr"] - pc
            except Exception:
                print(f"⚠ Unable to determine call length @ {pc:#x}")
                length = 0

        return_addr = pc + length
        mac_return_addr = self.present(return_addr)
        self.ret_stack.append(mac_return_addr)
        print(f"📥 CALL @ {pc:#x} -> Return addr {return_addr:#x} pushed (depth: {len(self.ret_stack)})")

    def is_dl_runtime_resolve_ret(self, pc):
        """Check if ret belongs to _dl_runtime_resolve."""
        try:
            sym_info = gdb.execute(f"info symbol {pc:#x}", to_string=True).strip()
            return "_dl_runtime_resolve" in sym_info
        except gdb.error:
            return False

    def handle_ret_instruction(self, pc, current_pc):
        """Handle 'ret' instruction by validating return address."""
        if self.is_dl_runtime_resolve_ret(pc):
            print(f"🔗 Skipping ret @ {pc:#x} (dynamic linker)")
            return

        if not self.ret_stack:
            print("💥 Error: return stack empty on ret!")
            gdb.execute("quit 1")
            return

        expected = self.ret_stack.pop()
        actual = self.present(current_pc)
        if expected != actual:
            print(f"💥 RET Mismatch! Expected {expected} ≠ Actual {actual}")
            gdb.execute("quit 1")
        else:
            print(f"✅ RET verified (depth: {len(self.ret_stack)})")

    def get_text_start_address(self):
        """Get the .text section start address."""
        if self.text_start is None:
            try:
                output = gdb.execute("info files", to_string=True)
                for line in output.splitlines():
                    if ".text" in line:
                        self.text_start = int(line.split()[0], 16)
                        print(f".text section start: {self.text_start:#x}")
                        break
            except (gdb.error, ValueError):
                print("❌ Unable to retrieve .text section start")
        return self.text_start

    def get_instruction_hex(self, address):
        """Get machine code bytes at a given address as hex."""
        try:
            arch = gdb.selected_frame().architecture()
            instruction = arch.disassemble(address, count=1)[0]
            length = min(instruction['length'], 15)
            mem = gdb.selected_inferior().read_memory(address, length).tobytes()
            return ''.join(f"{byte:02x}" for byte in mem).zfill(16)
        except gdb.error as e:
            print(f"❌ Memory read error: {e}")
            return "ReadError"

    def hex_xor(self, hex1, hex2):
        """XOR two hex strings."""
        if not hex1 or not hex2:
            return ''
        return format(int(hex1, 16) ^ int(hex2, 16), '016x')

    def print_instruction_info(self, pc, text_start):
        """Verify instruction tag against ledger."""
        offset_text = pc - text_start
        output_part = self.present(offset_text)
        if output_part is None:
            return

        if offset_text not in self.compressed_values:
            return

        instruction_hex = self.get_instruction_hex(pc)
        xor_result = self.hex_xor(instruction_hex, output_part)
        compressed_value = self.compress_to_n_bits(xor_result, self.bit_width)

        expected_value = self.compressed_values[offset_text]
        if compressed_value != expected_value:
            print(f"💥 FAIL: Offset {offset_text}, Got {compressed_value}, Expected {expected_value}")
            gdb.execute("quit")
        else:
            print(f"✅ OK: Addr {pc:#x}, Offset {offset_text}, Tag {compressed_value}")

    def invoke(self, arg, from_tty):
        """Main debugger loop."""
        text_start = self.get_text_start_address()
        if text_start is None:
            return

        try:
            gdb.execute("delete")
            gdb.execute("break _start")
            gdb.execute("run")
        except gdb.error as e:
            print(f"❌ Init failed: {e}")
            return

        while True:
            try:
                frame = gdb.selected_frame()
                pc = frame.pc()
                arch = frame.architecture()
                insn = arch.disassemble(pc, count=1)[0]
                asm = insn["asm"].split()[0]

                if asm.startswith("call"):
                    self.handle_call_instruction(pc, insn)

                self.print_instruction_info(pc, text_start)
                gdb.execute("si", to_string=True)

                current_pc = gdb.selected_frame().pc()
                if asm.startswith("ret"):
                    self.handle_ret_instruction(pc, current_pc)

            except (gdb.MemoryError, IndexError):
                print("✅ Program finished")
                break
            except Exception as e:
                print(f"❌ Debugger error: {e}")
                gdb.execute("quit 1")


Debugger()
