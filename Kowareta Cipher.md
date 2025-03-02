# !Kowareta Cipher  

**Category:** Cryptography / ECB Oracle Attack  

A challenge that involves exploiting AES-ECB mode vulnerabilities to extract an encrypted flag.  

---

### Challenge  

In Tokyo’s cyber arena, Kowareta Cipher has left secrets exposed. Coding prodigy Lain Iwakura encrypted her messages with AES—but without an IV, patterns emerge, revealing cracks in her defenses. Can you break the cipher and uncover the truth? 

**Target:** `nc chals1.apoorvctf.xyz 4001`

```
import sys
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from random import randbytes

def main():
    key = randbytes(16)
    cipher = AES.new(key, AES.MODE_ECB)
    flag = b'apoorvctf{fake_flag_123}'

    print("Welcome to the ECB Oracle challenge!")
    print("Enter your input in hex format.")

    try:
        while True:
            print("Enter your input: ", end="", flush=True)
            userinput = sys.stdin.readline().strip()

            if not userinput:
                break

            try:
                userinput = bytes.fromhex(userinput)
                ciphertext = cipher.encrypt(pad(userinput + flag + userinput, 16))
                print("Ciphertext:", ciphertext.hex())

            except Exception as e:
                print(f"Error: {str(e)}")

    except KeyboardInterrupt:
        print("Server shutting down.")

if __name__ == "__main__":
    main()
```

---

## Overview  

1. **Understanding the Encryption Method**  
   - The given Python code encrypts user input using **AES in ECB mode**.
   - ECB (Electronic Codebook) mode is **insecure** because it encrypts identical plaintext blocks into identical ciphertext blocks, exposing patterns.
   - The flag is **appended between user-controlled inputs** and then encrypted.  

2. **Identifying the Vulnerability**  
   - Since ECB mode encrypts each block independently, we can control the input and analyze repeating patterns in the ciphertext.
   - By **crafting precise inputs**, we can extract the flag **one byte at a time** using a **byte-by-byte decryption attack**.  

---

## Steps to Exploit  

1. **Establish a Connection**  
   - Connect to the challenge server and observe the response format.
   - Send controlled inputs and analyze the ciphertext structure.  

2. **Detect Block Size and Flag Position**  
   - Send increasing lengths of 'A' to determine the block size (which is **16 bytes** for AES).
   - Locate where the flag appears in the encrypted output by aligning known plaintext.  

3. **Perform Byte-By-Byte ECB Decryption**  
   - Construct inputs so that each unknown byte of the flag is **pushed to the end of a known block**.
   - Use a dictionary attack by brute-forcing all possible bytes (0x00-0xFF) and matching against the ciphertext.
   - Recover the flag **one character at a time**.  

---

## Exploit Script  

```python
import socket
import time
import binascii

HOST = 'chals1.apoorvctf.xyz'
PORT = 4001
BLOCK_SIZE = 16
RECV_TIMEOUT = 10

# Function to receive data until a delimiter is found
def recv_until(sock, delim, timeout=RECV_TIMEOUT):
    sock.settimeout(timeout)
    data = b""
    start_time = time.time()
    while delim not in data and (time.time() - start_time) < timeout:
        try:
            chunk = sock.recv(1024)
        except socket.timeout:
            break
        if not chunk:
            break
        data += chunk
    return data

class Oracle:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.s = None
        self._connect()

    def _connect(self):
        if self.s:
            self.s.close()
        self.s = socket.create_connection((self.host, self.port), timeout=RECV_TIMEOUT)
        recv_until(self.s, b"Enter your input:")

    def query(self, inp: bytes) -> bytes:
        hex_inp = inp.hex()
        self.s.sendall(hex_inp.encode() + b"\n")
        full_resp = recv_until(self.s, b"Enter your input:")
        for line in full_resp.split(b'\n'):
            if b"Ciphertext:" in line:
                return bytes.fromhex(line.split(b"Ciphertext:")[1].strip().decode())
        return b""

    def close(self):
        if self.s:
            self.s.close()

# Function to recover flag using byte-by-byte decryption
def recover_flag():
    oracle = Oracle(HOST, PORT)
    recovered = b""
    
    while True:
        current_pos = len(recovered)
        prefix = b'A' * (BLOCK_SIZE - (current_pos % BLOCK_SIZE) - 1)
        baseline_ct = oracle.query(prefix)
        
        for candidate in range(32, 127):  # Printable ASCII range
            guess = prefix + recovered + bytes([candidate])
            guess_ct = oracle.query(guess)
            if guess_ct[:len(baseline_ct)] == baseline_ct[:len(baseline_ct)]:
                recovered += bytes([candidate])
                print(f"Recovered so far: {recovered.decode(errors='replace')}")
                break
            
        if recovered.endswith(b'}'):
            print("Final flag:", recovered.decode())
            break
    
    oracle.close()

if __name__ == "__main__":
    recover_flag()
```

---

## Extracted Flag  

```
apoorvctf{3cb_345y_crypt0_br34k}
```

