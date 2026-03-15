"""
Key Generation module for ShadowVault — implemented from scratch.

Chain:
  CSPRNG  ──►  generate_prime (Miller-Rabin)  ──►  RSA key generation

Classes / functions:
  CSPRNG          — Hash-based cryptographically secure pseudo-random generator
                    (seeded from os.urandom, state updated with SHA-256)
  miller_rabin    — Probabilistic primality test (k rounds → error < 4^-k)
  generate_prime  — Generate a random prime of exactly `bits` bits
  RSAKeyPair      — Holds (n, e, d, p, q) and encrypt/decrypt operations
  generate_rsa    — Full RSA-2048 key generation using the above primitives

External libraries used: NONE (only Python stdlib: os, hashlib, struct)
"""
from __future__ import annotations
import os
import hashlib
import struct
from dataclasses import dataclass

from core.bigint import BigInt


# ════════════════════════════════════════════════════════════════
# 1. CSPRNG — Hash-based (SHA-256 counter mode)
# ════════════════════════════════════════════════════════════════

class CSPRNG:
    """
    Cryptographically Secure Pseudo-Random Number Generator.

    Construction:
      - Seed = 64 bytes from os.urandom  (true entropy source)
      - State updated using SHA-256(seed || counter || extra_entropy)
      - Each call to random_bytes() consumes one or more SHA-256 blocks

    This is similar to the CTR_DRBG / Hash_DRBG schemes in NIST SP 800-90A.
    """

    BLOCK = 32   # SHA-256 output size in bytes

    def __init__(self):
        # Pull 64 bytes of true randomness from the OS
        self._seed    = os.urandom(64)
        self._counter = 0
        self._buffer  = b""

    def _generate_block(self) -> bytes:
        """Produce one 32-byte block and advance the counter."""
        data = (
            self._seed
            + struct.pack(">Q", self._counter)
            + os.urandom(8)          # extra entropy per block
        )
        self._counter += 1
        # Re-mix seed to prevent state recovery
        self._seed = hashlib.sha256(self._seed + struct.pack(">Q", self._counter)).digest()
        return hashlib.sha256(data).digest()

    def random_bytes(self, n: int) -> bytes:
        """Return n cryptographically random bytes."""
        while len(self._buffer) < n:
            self._buffer += self._generate_block()
        result, self._buffer = self._buffer[:n], self._buffer[n:]
        return result

    def random_int(self, bits: int) -> int:
        """Return a random non-negative integer with at most `bits` bits."""
        n_bytes = (bits + 7) // 8
        raw     = self.random_bytes(n_bytes)
        value   = int.from_bytes(raw, "big")
        # Mask excess bits
        return value & ((1 << bits) - 1)

    def random_bigint(self, bits: int) -> BigInt:
        """Return a random BigInt of at most `bits` bits."""
        return BigInt(self.random_int(bits))

    def random_bigint_exact(self, bits: int) -> BigInt:
        """Return a random BigInt with exactly `bits` bits (top bit = 1)."""
        v = self.random_int(bits)
        v |= (1 << (bits - 1))   # set top bit
        return BigInt(v)

    def random_range_int(self, low: int, high: int) -> int:
        """Return a uniform random integer in [low, high]."""
        diff  = high - low
        bits  = diff.bit_length()
        while True:
            v = self.random_int(bits)
            if v <= diff:
                return v + low


# ════════════════════════════════════════════════════════════════
# 2. Miller-Rabin Primality Test
# ════════════════════════════════════════════════════════════════

# Small primes for quick trial-division pre-filter
_SMALL_PRIMES = [
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47,
    53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107,
    109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167,
    173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229,
    233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283,
]


def miller_rabin(n: BigInt, rng: CSPRNG, k: int = 20) -> bool:
    """
    Miller-Rabin probabilistic primality test.

    A composite number passes at most k rounds with probability < 4^(-k).
    With k=20, error probability < 10^(-12).

    Algorithm:
      1. Write n-1 = 2^r * d  (d odd)
      2. For k random witnesses a in [2, n-2]:
           x = a^d mod n
           if x == 1 or x == n-1: continue  (probably prime for this witness)
           for _ in range(r-1):
               x = x^2 mod n
               if x == n-1: goto next witness
           return COMPOSITE
      3. return PROBABLY PRIME

    We use Python's built-in pow(a, d, n) for the heavy modular exponentiation
    (it calls the same square-and-multiply algorithm as BigInt.pow_mod, but is
    implemented in C for performance — acceptable since the algorithm is identical).
    """
    n_int = n.to_int()

    if n_int < 2:   return False
    if n_int == 2:  return True
    if n_int == 3:  return True
    if n_int % 2 == 0: return False

    # Quick trial division
    for p in _SMALL_PRIMES:
        if n_int == p:    return True
        if n_int % p == 0: return False

    # Factor out powers of 2 from n-1:  n-1 = 2^r * d
    d = n_int - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1

    # k witness rounds
    for _ in range(k):
        a = rng.random_range_int(2, n_int - 2)

        # x = a^d mod n  (square-and-multiply — same algorithm as BigInt.pow_mod)
        x = pow(a, d, n_int)

        if x == 1 or x == n_int - 1:
            continue

        composite = True
        for _ in range(r - 1):
            x = pow(x, 2, n_int)
            if x == n_int - 1:
                composite = False
                break

        if composite:
            return False

    return True   # probably prime


# ════════════════════════════════════════════════════════════════
# 3. Prime Generation
# ════════════════════════════════════════════════════════════════

def generate_prime(bits: int, rng: CSPRNG, miller_rabin_rounds: int = 20) -> BigInt:
    """
    Generate a random prime of exactly `bits` bits.

    Strategy:
      1. Generate a random odd number with top and bottom bits set
         (top bit ensures exactly `bits` bits; bottom bit ensures odd)
      2. Apply trial-division pre-filter (fast reject of obvious composites)
      3. Apply Miller-Rabin test
      4. Repeat until prime found

    Expected iterations: O(bits) by the prime number theorem
    (density of primes near 2^bits ≈ 1 / ln(2^bits) = 1 / (bits * ln2))
    """
    if bits < 8:
        raise ValueError("Prime bit length must be at least 8")

    while True:
        # Step 1: random candidate with top and bottom bits set
        candidate_int = rng.random_int(bits)
        candidate_int |= (1 << (bits - 1))   # top bit  = 1  → exactly `bits` bits
        candidate_int |= 1                    # bottom bit = 1 → odd

        # Step 2: quick trial division
        definitely_composite = False
        for p in _SMALL_PRIMES:
            if candidate_int == p:
                return BigInt(candidate_int)   # it's a small prime itself
            if candidate_int % p == 0:
                definitely_composite = True
                break
        if definitely_composite:
            continue

        # Step 3: Miller-Rabin
        candidate = BigInt(candidate_int)
        if miller_rabin(candidate, rng, miller_rabin_rounds):
            return candidate


# ════════════════════════════════════════════════════════════════
# 4. RSA Key Pair
# ════════════════════════════════════════════════════════════════

@dataclass
class RSAKeyPair:
    """
    RSA key pair (n, e, d, p, q).

    n = p * q            (public modulus)
    e = 65537            (public exponent, standard Fermat F4)
    d = e^-1 mod λ(n)    (private exponent, λ = lcm(p-1, q-1) = Carmichael)
    p, q                 (private primes)
    """
    n: BigInt
    e: BigInt
    d: BigInt
    p: BigInt
    q: BigInt

    # ── Encryption (public) ──────────────────────────────────────

    def encrypt(self, m: BigInt) -> BigInt:
        """
        Textbook RSA encryption: c = m^e mod n.
        m must satisfy 0 <= m < n.
        """
        if m >= self.n:
            raise ValueError("Message too large for this key size")
        return m.pow_mod(self.e, self.n)

    def decrypt(self, c: BigInt) -> BigInt:
        """
        Textbook RSA decryption using CRT (Chinese Remainder Theorem).

        CRT speeds decryption ~4× by splitting into two half-size exponentiations:
          m_p = c^(d mod p-1) mod p        (1024-bit exp instead of 2048-bit)
          m_q = c^(d mod q-1) mod q
          h   = q_inv * (m_p - m_q) mod p  (Garner's recombination)
          m   = m_q + q * h
        """
        dp    = self.d % (self.p - BigInt(1))
        dq    = self.d % (self.q - BigInt(1))
        q_inv = self.q.mod_inverse(self.p)

        m_p = c.pow_mod(dp, self.p)
        m_q = c.pow_mod(dq, self.q)

        # Garner's recombination — use Python int to handle potential negative diff
        mp_i    = m_p.to_int()
        mq_i    = m_q.to_int()
        p_i     = self.p.to_int()
        qinv_i  = q_inv.to_int()

        h = (qinv_i * ((mp_i - mq_i) % p_i)) % p_i   # Python % always non-negative
        m = mq_i + self.q.to_int() * h
        return BigInt(m)

    # ── Byte-level helpers ───────────────────────────────────────

    def encrypt_bytes(self, data: bytes) -> bytes:
        """Encrypt bytes as a BigInt, return ciphertext as fixed-length byte string."""
        m        = BigInt.from_bytes(data)
        c        = self.encrypt(m)
        key_bytes = (self.n.bit_length() + 7) // 8
        return c.to_bytes(key_bytes)

    def decrypt_bytes(self, data: bytes, msg_len: int | None = None) -> bytes:
        """
        Decrypt ciphertext bytes, return message bytes.
        msg_len: expected plaintext length in bytes (re-pads leading zeros if needed).
        """
        c = BigInt.from_bytes(data)
        m = self.decrypt(c)
        raw = m.to_bytes()
        if msg_len is not None and len(raw) < msg_len:
            raw = b"\x00" * (msg_len - len(raw)) + raw
        return raw

    # ── Serialisation ────────────────────────────────────────────

    def private_to_bytes(self) -> bytes:
        """
        Serialise private key to bytes.
        Format: [n_len:2][n][e_len:2][e][d_len:2][d][p_len:2][p][q_len:2][q]
        """
        parts = [self.n, self.e, self.d, self.p, self.q]
        out   = b""
        for bi in parts:
            b = bi.to_bytes()
            out += struct.pack(">H", len(b)) + b
        return out

    @classmethod
    def private_from_bytes(cls, data: bytes) -> "RSAKeyPair":
        """Deserialise private key from bytes produced by private_to_bytes()."""
        parts = []
        pos   = 0
        for _ in range(5):
            length = struct.unpack(">H", data[pos:pos + 2])[0]
            pos   += 2
            parts.append(BigInt.from_bytes(data[pos:pos + length]))
            pos   += length
        n, e, d, p, q = parts
        return cls(n=n, e=e, d=d, p=p, q=q)

    def public_to_bytes(self) -> bytes:
        """Serialise public key (n, e) to bytes."""
        nb = self.n.to_bytes()
        eb = self.e.to_bytes()
        return struct.pack(">H", len(nb)) + nb + struct.pack(">H", len(eb)) + eb

    @classmethod
    def public_from_bytes(cls, data: bytes) -> "RSAKeyPair":
        """Deserialise public-only key (d, p, q will be zero)."""
        length = struct.unpack(">H", data[:2])[0]
        n = BigInt.from_bytes(data[2:2 + length])
        rest = data[2 + length:]
        length2 = struct.unpack(">H", rest[:2])[0]
        e = BigInt.from_bytes(rest[2:2 + length2])
        return cls(n=n, e=e, d=BigInt(0), p=BigInt(0), q=BigInt(0))


# ════════════════════════════════════════════════════════════════
# 5. RSA Key Generation
# ════════════════════════════════════════════════════════════════

def generate_rsa(bits: int = 2048, rng: CSPRNG | None = None) -> RSAKeyPair:
    """
    Generate an RSA key pair of `bits` total bits.

    Algorithm:
      1. Choose prime p of bits//2 bits
      2. Choose prime q of bits//2 bits,  q ≠ p
      3. n = p * q
      4. e = 65537  (Fermat F4 — widely used, efficient for encryption)
      5. Compute Carmichael's totient: λ(n) = lcm(p-1, q-1)
         λ(n) = (p-1)(q-1) / gcd(p-1, q-1)
      6. d = e^-1 mod λ(n)   (private exponent)
      7. Verify e*d ≡ 1 (mod λ(n))

    Requirements for security:
      - p and q must be distinct large primes
      - gcd(e, λ(n)) must equal 1  (e and λ(n) coprime)
    """
    if rng is None:
        rng = CSPRNG()

    half = bits // 2
    E    = BigInt(65537)          # standard public exponent

    while True:
        # ── Step 1–2: Generate two distinct primes ───────────────
        p = generate_prime(half, rng)
        while True:
            q = generate_prime(half, rng)
            if q != p:
                break

        # ── Step 3: Compute modulus ───────────────────────────────
        n = p * q

        # ── Step 5: Carmichael totient λ(n) = lcm(p-1, q-1) ─────
        pm1  = p - BigInt(1)
        qm1  = q - BigInt(1)
        g    = pm1.gcd(qm1)
        lam  = (pm1 // g) * qm1      # = lcm(p-1, q-1)

        # ── Step 6: Check gcd(e, λ) = 1 ─────────────────────────
        if E.gcd(lam) != BigInt(1):
            continue                  # rare; try new primes

        # ── Step 6: Compute private exponent d = e^-1 mod λ ──────
        try:
            d = E.mod_inverse(lam)
        except ValueError:
            continue                  # should not happen if gcd=1

        # ── Step 7: Sanity check ─────────────────────────────────
        check = (E * d) % lam
        if check != BigInt(1):
            continue

        return RSAKeyPair(n=n, e=E, d=d, p=p, q=q)


# ── Module-level shared RNG instance ─────────────────────────────
_rng = CSPRNG()

def get_rng() -> CSPRNG:
    """Return the module-level CSPRNG instance."""
    return _rng
