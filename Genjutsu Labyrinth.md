# !Genjutsu Labyrinth  

**Category:** Algorithmic Challenge / Pathfinding  

A challenge that involves navigating a grid while minimizing an XOR value to zero using BFS pathfinding.  

---

### Challenge  

Genjutsu Labyrinth is filled with hidden secrets and illusions. We’ve uncovered some clues about the escape, but reality isn’t always what it seems. Can you see through the deception and find the way out?

```python
from sympy import primerange
import random
from collections import deque

def generate(size):
    grid = [[random.randint(0, 9) for col in range(size)] for row in range(size)]
    grid[0][0] = 0
    return grid

def encrypt(n, a, b, mod=101):
    return (a * n + b) % mod

def build_encrypted_grid(grid, a, b, mod=101):
    size = 10
    encry_grid = []
    for y in range(size):
        row = []
        for x in range(size):
            enc_val = encrypt(grid[y][x], a, b, mod)
            row.append(str(enc_val).zfill(2))
        encry_grid.append(row)
    return encry_grid

def optimize(grid):
    #hidden
    pass

grid = generate(10)
a = random.choice(list(primerange(2, 12)))
b = random.choice(range(101))
encry_grid = build_encrypted_grid(grid, a, b, mod=101)
```

---

## Overview  

1. **Understanding the Grid Generation**  
   - The grid is generated as a 10x10 matrix with random integer values between 0 and 9.
   - An encryption function is used to obfuscate the grid values:
     ```python
     def encrypt(n, a, b, mod=101):
         return (a * n + b) % mod
     ```
   - The encrypted grid is built using random values of `a` (a prime number between 2 and 12) and `b` (a random integer between 0 and 100).

2. **Understanding the Movement Constraints**  
   - The challenge presents a 9x9 grid.
   - The allowed movements are **Right (D)** and **Down (S)**.
   - The goal is to find the optimal path that results in an **XOR value of 0** at the end.

---

## Steps to Solve  

1. **Grid Analysis**  
   - The grid values are encrypted, but we only need to focus on their XOR properties.
   - The challenge allows us to move only **Right (D)** or **Down (S)**.
   
2. **Pathfinding using BFS (Breadth-First Search)**  
   - We use BFS to explore all possible paths.
   - The objective is to find the path where the cumulative XOR value is closest to **0**.
   - If multiple paths exist, the optimal one is chosen.

---

## Exploit Script  

```python
from collections import deque

# BFS to find the optimal path with XOR value closest to 0
queue = deque([(0, 0, 0, [])])  # (row, col, current XOR, path)
visited = set()

optimal_path = None
closest_xor = float('inf')

while queue:
    r, c, current_xor, path = queue.popleft()
    
    # If we reach the bottom-right corner
    if r == N - 1 and c == N - 1:
        if abs(current_xor) < abs(closest_xor):  # Minimize absolute XOR value, aiming for 0
            closest_xor = current_xor
            optimal_path = path + [(r, c)]
        continue

    # Possible moves: Right (D), Down (S)
    for dr, dc in [(0, 1), (1, 0)]:
        nr, nc = r + dr, c + dc
        if 0 <= nr < N and 0 <= nc < N and (nr, nc) not in visited:
            queue.append((nr, nc, current_xor ^ grid[nr][nc], path + [(r, c)]))
            visited.add((nr, nc))

# Convert path to movement instructions
movement_instructions = []
for (r1, c1), (r2, c2) in zip(optimal_path, optimal_path[1:]):
    if c2 > c1:
        movement_instructions.append("D")
    else:
        movement_instructions.append("S")

# Return the optimal movement sequence and final XOR
movement_instructions, closest_xor
```

---

## Extracted Flag  

```
apoorvctf{G3NJUTSU_M4ST3R}
```
