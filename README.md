# Integer Overflow Crackme — Reverse Engineering Writeup

First reverse engineering challenge completed using static analysis, dynamic debugging, and mathematical modeling.

This project demonstrates how an **integer overflow vulnerability in `atoi()`** can produce **infinite valid passwords**.

---

## Challenge

| Property | Value |
|--------|--------|
| Challenge | izijerry – int overflow |
| Platform | Linux x86-64 |
| Language | C/C++ |
| Difficulty | 1.4 / 6 |
| Vulnerability | Integer overflow |
| Tools Used | Ghidra, GDB, Python |

Target binary compares user input converted with `atoi()` against a **negative constant**.

Because `atoi()` returns a **signed 32-bit integer**, large inputs overflow and wrap around.

---

# Repository Contents

```
binary/        original crackme binary
scripts/       password generation script
screenshots/   reversing screenshots
writeup/       full research writeup
notes/         reversing notes and analysis
```

---

# Vulnerability

Relevant code recovered via **Ghidra decompiler**:

```c
int main()
{
    char *input = GetPass();
    int value = atoi(input);

    if (value == -0x2023e3c2)
        printf("Password Correct!!!");
    else
        printf("Incorrect Password!!!");
}
```

Key problem:

```
atoi() has no overflow protection
```

Any number whose **lower 32 bits equal the comparison value** will pass.

---

# Deriving the Password

Comparison constant:

```
-0x2023e3c2
```

Convert to decimal:

```
-539,222,978
```

32-bit unsigned equivalent:

```
2^32 = 4,294,967,296

4,294,967,296 - 539,222,978
= 3,755,744,318
```

### Primary Password

```
3755744318
```

---

# Dynamic Analysis

Using **GDB**, execution was paused at the comparison instruction.

```
cmpl $0xdfdc1c3e,-0xc(%rbp)
```

Register state:

```
rax = 12345678910
eax = -539222978
```

Explanation:

```
rax → full 64-bit value
eax → lower 32 bits only
```

Since the comparison only checks `eax`, overflowed values are accepted.

---

# Infinite Password Discovery

Integer arithmetic in 32-bit systems operates **modulo 2^32**.

Therefore any number satisfying:

```
X mod 2^32 = 3,755,744,318
```

will pass the check.

### General Formula

```
password = 3,755,744,318 + (n × 4,294,967,296)
```

Where:

```
n = 0,1,2,3...
```

---

# Password Generator Script

`scripts/password_generator.py`

```python
import ctypes

MODULUS = 2 ** 32
TARGET_SIGNED = -0x2023e3c2
BASE_PASSWORD = MODULUS + TARGET_SIGNED

def simulate_atoi_signed32(n):
    truncated = n % MODULUS
    return ctypes.c_int32(truncated).value

for i in range(10):
    pwd = BASE_PASSWORD + (i * MODULUS)
    print(pwd)
```

---

# Verified Passwords

| n | Password |
|---|---|
| 0 | 3755744318 |
| 1 | 8050711614 |
| 2 | 12345678910 |
| 3 | 16640646206 |
| 4 | 20935613502 |

All produce the same **32-bit value**:

```
Hex: 0xDFDC1C3E
Signed: -539222978
```

---

# Key Concepts Learned

### Reverse Engineering

- Static analysis with **Ghidra**
- Dynamic debugging with **GDB**
- Reading assembly instructions
- Inspecting CPU registers

### Low-Level Concepts

- Integer overflow
- Two's complement representation
- 32-bit vs 64-bit registers
- Modular arithmetic

### Automation

- Modeling C integer behavior in Python
- Generating exploit inputs programmatically

---

# Screenshots

Example reversing workflow:

```
screenshots/ghidra-analysis.png
screenshots/gdb-disassembly.png
screenshots/register-overflow.png
```

---

# Full Writeup

A detailed step-by-step research writeup is available here:

```
writeup/full-writeup.pdf
```

---

# Summary

| Item | Value |
|----|----|
| Vulnerability | Integer overflow |
| Target Value | -539222978 |
| First Password | 3755744318 |
| Valid Passwords | Infinite |
| Exploit Method | 32-bit integer wraparound |

---

# Author

First reverse engineering challenge completed March 2026.

Focus areas:

- reverse engineering
- binary exploitation
- vulnerability research
