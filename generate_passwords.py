#!/usr/bin/env python3
"""
Integer Overflow Password Generator
Target: izijerry's "int overflow" crackme on crackmes.one
Vulnerability: atoi() on user input stored as signed 32-bit int
Check: atoi(input) == -0x2023e3c2 == -539,222,978
"""

import ctypes

# ── Constants ────────────────────────────────────────────────────────────────
MODULUS       = 2 ** 32                  # 4,294,967,296  (32-bit wrap-around)
TARGET_SIGNED = -0x2023e3c2             # -539,222,978   (what the binary checks)
BASE_PASSWORD = MODULUS + TARGET_SIGNED  # 3,755,744,318  (smallest valid password)

# ── Core simulation ──────────────────────────────────────────────────────────
def simulate_atoi_signed32(n: int) -> int:
    """
    Simulate exactly what atoi() does on a large number in C.
    
    atoi() computes the full integer value, then stores it
    in a signed 32-bit int. Python's ctypes.c_int32 replicates
    that truncation and sign interpretation perfectly.
    """
    truncated = n % MODULUS                  # keep lower 32 bits only
    signed    = ctypes.c_int32(truncated).value  # interpret as signed 32-bit
    return signed


def is_valid_password(n: int) -> bool:
    """Returns True if this number passes the crackme's password check."""
    return simulate_atoi_signed32(n) == TARGET_SIGNED


# ── Generate the series ──────────────────────────────────────────────────────
def generate_passwords(count: int = 10) -> list:
    """
    Generate 'count' valid passwords using the formula:
        password = BASE_PASSWORD + (n * MODULUS)
    """
    return [BASE_PASSWORD + (n * MODULUS) for n in range(count)]


# ── Main output ──────────────────────────────────────────────────────────────
def main():
    print("=" * 70)
    print("  INTEGER OVERFLOW PASSWORD GENERATOR")
    print("  Target: izijerry's 'int overflow' crackme")
    print("=" * 70)

    print(f"\n[*] Target check value  : {TARGET_SIGNED}")
    print(f"[*] In hex              : -0x{abs(TARGET_SIGNED):08X}")
    print(f"[*] 32-bit modulus      : {MODULUS:,}")
    print(f"[*] Base password (n=0) : {BASE_PASSWORD:,}")

    print(f"\n[*] Formula: password = {BASE_PASSWORD:,} + (n × {MODULUS:,})")
    print()

    print("-" * 70)
    print(f"  {'n':>4}  {'Password':>25}  {'atoi() result':>15}  {'Valid?':>6}")
    print("-" * 70)

    passwords = generate_passwords(10)

    for n, pwd in enumerate(passwords):
        result = simulate_atoi_signed32(pwd)
        valid  = result == TARGET_SIGNED
        flag   = "✓  PASS" if valid else "✗  FAIL"
        print(f"  {n:>4}  {pwd:>25,}  {result:>15,}  {flag}")

    print("-" * 70)

    # ── Verify our two discovered passwords ──────────────────────────────────
    print("\n[*] Verifying passwords discovered during the session:")
    discoveries = [3_755_744_318, 12_345_678_910]
    for d in discoveries:
        result = simulate_atoi_signed32(d)
        valid  = result == TARGET_SIGNED
        flag   = "✓  PASS" if valid else "✗  FAIL"
        print(f"    Input: {d:>15,}  →  atoi() = {result:>12,}  →  {flag}")

    # ── Show the math visually ────────────────────────────────────────────────
    print("\n[*] Why 12,345,678,910 works — step by step:")
    n = 12_345_678_910
    remainder = n % MODULUS
    signed    = ctypes.c_int32(remainder).value
    print(f"    Input             : {n:,}")
    print(f"    n mod 2^32        : {n:,} mod {MODULUS:,} = {remainder:,}")
    print(f"    Signed 32-bit     : {remainder:,}  →  {signed:,}")
    print(f"    Matches target?   : {signed} == {TARGET_SIGNED} → {signed == TARGET_SIGNED}")

    # ── Demonstrate the limit ─────────────────────────────────────────────────
    print("\n[*] Testing a number that is TOO large for atoi() to handle:")
    too_large = 21111511111111111111111111111111
    # Python can compute it but atoi() in C cannot — show why
    digits = len(str(too_large))
    print(f"    Input             : {too_large}")
    print(f"    Number of digits  : {digits}")
    print(f"    64-bit int max    : 9,223,372,036,854,775,807 (19 digits)")
    print(f"    Verdict           : {digits} digits > 19 → atoi() produces")
    print(f"                        undefined/garbage in C → likely FAIL")

    print("\n[*] Safe password range:")
    print(f"    n=0 : {passwords[0]:,}   (confirmed ✓)")
    print(f"    n=1 : {passwords[1]:,}   (safe — 19 digits max)")
    print(f"    n=2 : {passwords[2]:,}  (confirmed ✓)")
    print(f"    n=3 : {passwords[3]:,}  (test this one yourself!)")
    print(f"    n=4+: unreliable — atoi() behavior undefined for very large strings")

    print("\n" + "=" * 70)
    print("  All passwords share the same 32-bit representation:")
    print(f"  Binary: {BASE_PASSWORD % MODULUS:032b}")
    print(f"  Hex   : 0x{BASE_PASSWORD % MODULUS:08X}")
    print(f"  Signed: {TARGET_SIGNED}")
    print("=" * 70)


if __name__ == "__main__":
    main()
