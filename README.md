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
