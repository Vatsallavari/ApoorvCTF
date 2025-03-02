# !Evil Rice  

**Category:** Binary Exploitation  

A complex challenge requiring symbolic execution to bypass input validation and extract the flag. 

---

### Challenge  

**Provided File:** `evil-rice-cooker`  

---

## Overview  

1. **Analyzing the Binary**  
   - Use `file evil-rice-cooker` to determine the binary type:
     
     ```sh
     ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=c5efa6ad81af2eda241bddea1798b2da92c20c6e, for GNU/Linux 4.4.0, stripped
     ```
   - Run `strings evil-rice-cooker` to find readable text inside:
     ```sh
     monk laughs today
     ```
   - Disassemble the binary using `objdump`:
     ```sh
     objdump -d evil-rice-cooker > disassembly.txt
     ```
   - Load the binary in **Ghidra** or **Binary Ninja** to reverse-engineer its logic.  

2. **Identifying the Vulnerability**  
   - The binary requires a 37-character password input.
   - If incorrect, it outputs: `monk laughs today`.
   - If correct, it prints the flag.
   - The validation mechanism is highly obfuscated, making symbolic execution the best approach.  

---

## Steps to Exploit  

1. **Check Binary Properties**  
   ```sh
   file evil-rice-cooker  
   checksec --file=evil-rice-cooker  
   strings evil-rice-cooker  
   ```

2. **Reverse Engineer the Binary**  
   - Load in **Ghidra** or **Binary Ninja** to analyze the password validation mechanism.

3. **Use Symbolic Execution with angr**  
   - Instead of brute force, use **angr** to find the correct password.
   - Define constraints to ensure only printable ASCII characters are used.
   - Explore execution paths to find one that leads to a successful output.  

---

## Exploit Script  

```python
import angr
import claripy
import subprocess

# Load the binary; disable auto-loading of libraries to speed up analysis.
proj = angr.Project("./evil-rice-cooker", auto_load_libs=False)

# Create a symbolic buffer of 37 bytes (the required password length).
password_chars = [claripy.BVS("c%d" % i, 8) for i in range(37)]
password = claripy.Concat(*password_chars)

# Create an initial state.
# We use claripy.Concat to append a newline to the symbolic password.
state = proj.factory.full_init_state(
    args=["./evil-rice-cooker"],
    stdin=angr.SimFileStream("stdin", content=claripy.Concat(password, claripy.BVV(b"\n", 8)), has_end=True)
)

# Constrain each character to be a printable ASCII character.
for char in password_chars:
    state.solver.add(char >= 0x20)
    state.solver.add(char <= 0x7e)

# Define success and failure conditions.
# Success: when the program prints something containing "da rice god or wot?".
# Failure: when the program prints "monk laughs today".
def is_success(state):
    stdout_output = state.posix.dumps(1)
    return b"da rice god or wot?" in stdout_output

def should_abort(state):
    stdout_output = state.posix.dumps(1)
    return b"monk laughs today" in stdout_output

# Create a simulation manager starting from our state.
simgr = proj.factory.simulation_manager(state)

# Explore paths that reach success while avoiding the failure branch.
simgr.explore(find=is_success, avoid=should_abort)

if simgr.found:
    found_state = simgr.found[0]
    solution = found_state.solver.eval(password, cast_to=bytes)
    print("Computed password:", solution)
    
    # Now, run the binary with the computed password to fetch the flag.
    proc = subprocess.Popen("./evil-rice-cooker", stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, _ = proc.communicate(solution + b"\n")
    out = out.decode()
    if "monk laughs today" in out:
        print("[-] Password rejected.")
    else:
        print("[+] Flag output:")
        print(out)
else:
    print("[-] No solution found!")
```

---

## Extracted Flag  

```
apoorvctf{h0w_d1d_u_3v3n_f1nd_th1s:0}
```
