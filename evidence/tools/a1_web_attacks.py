#!/usr/bin/env python3
"""
A1 (web): the four ideas of part2/xor_attack.py, run against the REAL Cryptography page (Low level)
through https://127.0.0.1 (Encode/Decode form). The attacker only sees what the form returns.
"""
import base64, sys
sys.path.insert(0, __file__.rsplit('/', 1)[0])
from dvwa_client import DVWA

def xor(a, b): return bytes(x ^ y for x, y in zip(a, b))
def xor_rep(data, key): return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))
def ct_of(b64): raw = base64.b64decode(b64); return raw, raw[13:-16]   # version|nonce(12)|ct|tag(16)

d = DVWA("https://127.0.0.1", "certs/lab-ca.crt")
assert d.login("admin", "password")[0]; d.set_security("low")
ok_all = True
def res(name, defended, detail=""):
    global ok_all; ok_all &= defended
    print(("DEFENDED    " if defended else "VULNERABLE  ") + name + (f"\n            {detail}" if detail else ""))

secret = "Your new password is: Olifant"
c_secret, _, _ = d.crypto(secret)
raw, body = ct_of(c_secret)
print(f"Encode('{secret}') -> {c_secret}\n  length {len(raw)} bytes = 1 version + 12 nonce + {len(body)} ciphertext + 16 tag\n")

# [1] key from the source code
guess = xor_rep(body, b"wachtwoord")
res("[1] XOR with the old source key 'wachtwoord' does not give the plaintext",
    b"Olifant" not in guess and b"password" not in guess, f"XOR result (hex) = {guess.hex()}")
pt, warn, _ = d.crypto("Lg4WGlQZChhSFBYSEB8bBQtPGxdNQSwEHREOAQY=", "decode")
res("[1] the old XOR 'intercepted' message is rejected by Decode", pt is None and warn and "rejected" in warn, f"server said: {warn}")

# [2] chosen-plaintext oracle
A = b"A" * 30
k1 = xor(ct_of(d.crypto(A.decode())[0])[1], A)
k2 = xor(ct_of(d.crypto(A.decode())[0])[1], A)
res("[2] keystream from two Encode('A'*30) requests differs (fresh nonce)", k1 != k2,
    f"ks1 = {k1.hex()}\n            ks2 = {k2.hex()}")
period = next((n for n in range(1, len(k1)) if all(k1[i] == k1[i % n] for i in range(len(k1)))), None)
res("[2] keystream has no repeating key (no period < 30)", period is None, f"period found: {period}")
res("[2] recovered keystream does not decrypt the intercepted message",
    b"Olifant" not in xor(body, k1), f"result = {xor(body, k1)!r}")

# [3] two-time pad
p1, p2 = b"Meet me at the library at 9", b"Password for the lab is: 1234"
c1 = ct_of(d.crypto(p1.decode())[0])[1]; c2 = ct_of(d.crypto(p2.decode())[0])[1]
n = min(len(p1), len(p2))
res("[3] c1 XOR c2 != p1 XOR p2", xor(c1, c2)[:n] != xor(p1, p2)[:n],
    f"c1^c2 = {xor(c1, c2)[:n].hex()}\n            p1^p2 = {xor(p1, p2)[:n].hex()}")

# [4] malleability: Olifant -> Hackers bit flip, then submit to Decode
t = bytearray(raw); pos = 13 + secret.index("Olifant")
for i, (o, h) in enumerate(zip(b"Olifant", b"Hackers")): t[pos + i] ^= o ^ h
tampered = base64.b64encode(bytes(t)).decode()
pt, warn, _ = d.crypto(tampered, "decode")
res("[4] bit-flipped ciphertext (Olifant->Hackers) rejected by Decode", pt is None and warn is not None,
    f"submitted {tampered}\n            server said: {warn}; plaintext returned: {pt!r}")
pt, warn, _ = d.crypto(c_secret, "decode")
res("[4] control: the untouched ciphertext still decodes", pt == secret, f"Decode -> {pt!r}")

print("\nALL ATTACKS DEFENDED" if ok_all else "\nSOME ATTACKS SUCCEEDED"); sys.exit(0 if ok_all else 1)
