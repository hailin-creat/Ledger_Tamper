# Ledger_Tamper

# Project Structure
attack.py ：Attack script: patches the binary to bypass password verification

demo.c：Target C program with password verification logic

Ledger_cfi.py：GDB plugin: enforces runtime CFI checks using the ledger

Ledger_generate.py：Generates a ledger for validating the binary at runtime

# Requirements

Operating System: Ubuntu 20.04 (tested)

GDB: GNU Debugger, to run the target program and inject defense logic

Python 3: to run the automation and attack scripts

32-bit GCC toolchain: to build the target program for 32-bit architecture

# Environment Setup
On a fresh Ubuntu 20.04 system, run the following commands in order to set up the environment:

Clone the repository: git clone https://github.com/hailin-creat/Ledger_Tamper.git

cd Ledger_Tamper

sudo apt update

sudo apt upgrade

--- Install build tools---：

sudo apt install autoconf automake libtool

# How It Works

1.Target Program

The demo.c program checks for a hardcoded password (123456). If the password is incorrect, it refuses to perform the sensitive operation.

2.Attack

The attack.py script:

Locates the JE/JNE conditional jump after the password check.

Patches it with two NOP instructions (0x90 0x90).

This bypasses the password verification, allowing any input to succeed.

3.Defense

The ledger-based defense works by:

Ledger generation (Ledger_generate.py): creates a list of valid instruction signatures (ledger) for the binary.

Runtime verification (Ledger_cfi.py): a GDB script that monitors instruction flow and verifies return addresses and instruction signatures against the ledger.

If tampering is detected, the program terminates.

# Usage

1.Build the target binary

gcc -o demo demo.c -no-pie -fno-stack-protector -O0

2.Run normally

./demo

Enter the correct password (123456) to execute the sensitive operation.
Any other password will be rejected.

3.Perform the attack

python3 attack.py

Now, any password will bypass verification:

./demo

4.Enable the defense mechanism

(1)Recompile the target binary:

gcc -o demo demo.c -no-pie -fno-stack-protector -O0

(2)Generate the ledger:

python3 Ledger_generate.py ./demo

(3)Try the attack again:

python3 attack.py

(4)Run with ledger verification:

gdb -q -ex "source Ledger_cfi.py" -ex "ledgercfi" --args demo

The ledger-based defense will detect the tampering and terminate the program.

# Notes
The defense uses the lightweight PRESENT block cipher to generate cryptographic instruction tags.

This project is for educational and research purposes only. Do not use it for unauthorized tampering.

# License

This project is licensed under the MIT License - see the LICENSE file for details.
