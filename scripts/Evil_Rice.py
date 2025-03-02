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
