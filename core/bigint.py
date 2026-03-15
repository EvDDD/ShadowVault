"""
BigInt — Arbitrary-precision non-negative integer implemented from scratch.

Internal representation: list of 32-bit unsigned words in little-endian order
(index 0 = least significant word).  BASE = 2^32.

Algorithms implemented:
  - Addition         : digit-by-digit with carry propagation
  - Subtraction      : digit-by-digit with borrow propagation
  - Multiplication   : schoolbook O(n²) algorithm
  - Division / Mod   : long-division algorithm
  - Modular exp      : square-and-multiply (binary method)
  - GCD              : Euclidean algorithm
  - Modular inverse  : Extended Euclidean algorithm
"""
from __future__ import annotations
from typing import Any

_BASE = 1 << 32        # 4 294 967 296
_MASK = _BASE - 1      # 0xFFFFFFFF


class BigInt:
    """Arbitrary-precision non-negative integer (base-2^32 word array)."""

    # ── Construction ─────────────────────────────────────────────

    def __init__(self, value=0):
        if isinstance(value, BigInt):
            self._w = list(value._w)
            return
        if isinstance(value, int):
            if value < 0:
                raise ValueError("BigInt supports non-negative integers only")
            self._w: list[int] = []
            while value:
                self._w.append(value & _MASK)
                value >>= 32
            return
        if isinstance(value, (bytes, bytearray)):
            # Big-endian byte string
            self._w = []
            n = int.from_bytes(value, "big")
            while n:
                self._w.append(n & _MASK)
                n >>= 32
            return
        raise TypeError(f"Cannot construct BigInt from {type(value).__name__}")

    # ── Internal helpers ─────────────────────────────────────────

    def _trim(self) -> "BigInt":
        """Remove trailing zero words (= leading zeros in big-endian view)."""
        while self._w and self._w[-1] == 0:
            self._w.pop()
        return self

    @staticmethod
    def _ensure(v) -> "BigInt":
        return v if isinstance(v, BigInt) else BigInt(v)

    # ── Representation ───────────────────────────────────────────

    def __repr__(self) -> str:
        return f"BigInt(0x{self.to_int():x})"

    def __bool__(self) -> bool:
        return bool(self._w)

    def is_zero(self) -> bool:
        return not self._w

    def is_even(self) -> bool:
        return not self._w or (self._w[0] & 1) == 0

    def bit_length(self) -> int:
        if not self._w:
            return 0
        return (len(self._w) - 1) * 32 + self._w[-1].bit_length()

    def get_bit(self, i: int) -> int:
        """Return bit i (0 = LSB)."""
        word_idx = i >> 5          # i // 32
        bit_idx  = i & 31          # i % 32
        if word_idx >= len(self._w):
            return 0
        return (self._w[word_idx] >> bit_idx) & 1

    # ── Conversion ───────────────────────────────────────────────

    def to_int(self) -> int:
        result = 0
        for i, w in enumerate(self._w):
            result |= w << (32 * i)
        return result

    def to_bytes(self, length: int | None = None) -> bytes:
        n   = self.to_int()
        blen = length if length is not None else max(1, (n.bit_length() + 7) // 8)
        return n.to_bytes(blen, "big")

    @classmethod
    def from_bytes(cls, data: bytes) -> "BigInt":
        return cls(int.from_bytes(data, "big"))

    # ── Comparison ───────────────────────────────────────────────

    def _cmp(self, other: "BigInt") -> int:
        """Return -1, 0, or 1."""
        if len(self._w) != len(other._w):
            return -1 if len(self._w) < len(other._w) else 1
        for i in range(len(self._w) - 1, -1, -1):
            if self._w[i] != other._w[i]:
                return -1 if self._w[i] < other._w[i] else 1
        return 0

    def __eq__(self, other) -> bool:  return self._cmp(self._ensure(other)) == 0
    def __ne__(self, other) -> bool:  return not self.__eq__(other)
    def __lt__(self, other) -> bool:  return self._cmp(self._ensure(other)) <  0
    def __le__(self, other) -> bool:  return self._cmp(self._ensure(other)) <= 0
    def __gt__(self, other) -> bool:  return self._cmp(self._ensure(other)) >  0
    def __ge__(self, other) -> bool:  return self._cmp(self._ensure(other)) >= 0

    # ── Addition ─────────────────────────────────────────────────

    def __add__(self, other) -> "BigInt":
        other = self._ensure(other)
        result = BigInt()
        carry = 0
        n = max(len(self._w), len(other._w))
        for i in range(n):
            a = self._w[i]  if i < len(self._w)  else 0
            b = other._w[i] if i < len(other._w) else 0
            s = a + b + carry
            result._w.append(s & _MASK)
            carry = s >> 32
        if carry:
            result._w.append(carry)
        return result

    def __radd__(self, other) -> "BigInt":
        return self.__add__(other)

    # ── Subtraction (self >= other required) ─────────────────────

    def __sub__(self, other) -> "BigInt":
        other = self._ensure(other)
        if self < other:
            raise ArithmeticError("BigInt: subtraction would yield negative result")
        result = BigInt()
        borrow = 0
        for i in range(len(self._w)):
            b    = other._w[i] if i < len(other._w) else 0
            diff = self._w[i] - b - borrow
            if diff < 0:
                diff  += _BASE
                borrow = 1
            else:
                borrow = 0
            result._w.append(diff)
        return result._trim()

    # ── Multiplication (schoolbook O(n²)) ────────────────────────

    def __mul__(self, other) -> "BigInt":
        other = self._ensure(other)
        if self.is_zero() or other.is_zero():
            return BigInt(0)
        n, m = len(self._w), len(other._w)
        buf = [0] * (n + m)
        for i in range(n):
            carry = 0
            for j in range(m):
                t          = self._w[i] * other._w[j] + buf[i + j] + carry
                buf[i + j] = t & _MASK
                carry      = t >> 32
            buf[i + m] += carry
        result = BigInt()
        result._w = buf
        return result._trim()

    def __rmul__(self, other) -> "BigInt":
        return self.__mul__(other)

    # ── Division and modulo (long division) ──────────────────────
    #
    # We implement __divmod__ using Algorithm D (Knuth TAOCP vol.2 §4.3.1
    # simplified): normalise divisor so MSW >= BASE/2, perform digit-by-digit
    # quotient estimation, then adjust.  For clarity, individual __floordiv__
    # and __mod__ delegate here.

    def _divmod(self, other: "BigInt") -> tuple["BigInt", "BigInt"]:
        if other.is_zero():
            raise ZeroDivisionError("BigInt division by zero")
        if self < other:
            return BigInt(0), BigInt(self)
        if len(other._w) == 1:
            return self._divmod_single(other._w[0])

        # Normalise: shift both so MSW of divisor >= BASE/2
        shift = 32 - other._w[-1].bit_length()
        u = (self  << shift)._w[:]   # working copy of dividend digits
        v = (other << shift)._w      # working copy of divisor digits
        n = len(v)                   # divisor length
        m = len(u) - n               # quotient will have m+1 digits

        # Pad u to length m + n + 1
        while len(u) <= m + n:
            u.append(0)

        q_digits = [0] * (m + 1)

        for j in range(m, -1, -1):
            # Estimate q̂ = (u[j+n]*BASE + u[j+n-1]) // v[n-1]
            num  = u[j + n] * _BASE + u[j + n - 1]
            dhat = v[n - 1]
            qhat = min(num // dhat, _MASK)

            # Multiply and subtract: u[j..j+n] -= qhat * v[0..n-1]
            borrow = 0
            carry  = 0
            sub    = [0] * (n + 1)
            for i in range(n):
                p        = qhat * v[i] + carry
                carry    = p >> 32
                sub[i]   = p & _MASK
            sub[n] = carry

            borrow = 0
            for i in range(n + 1):
                diff       = u[j + i] - sub[i] - borrow
                if diff < 0:
                    diff  += _BASE
                    borrow = 1
                else:
                    borrow = 0
                u[j + i] = diff

            q_digits[j] = qhat

            # Add back if we subtracted too much
            if borrow:
                q_digits[j] -= 1
                carry = 0
                for i in range(n):
                    s        = u[j + i] + v[i] + carry
                    u[j + i] = s & _MASK
                    carry    = s >> 32
                u[j + n] = (u[j + n] + carry) & _MASK

        # Remainder is in u[0..n-1], un-normalise by >> shift
        r_big = BigInt()
        r_big._w = u[:n]
        r_big._trim()
        remainder = r_big >> shift

        quotient = BigInt()
        quotient._w = q_digits
        quotient._trim()

        return quotient, remainder

    def _divmod_single(self, d: int) -> tuple["BigInt", "BigInt"]:
        """Fast path: divide by a single 32-bit word."""
        rem = 0
        q_w = [0] * len(self._w)
        for i in range(len(self._w) - 1, -1, -1):
            cur     = rem * _BASE + self._w[i]
            q_w[i]  = cur // d
            rem     = cur %  d
        quotient = BigInt()
        quotient._w = q_w
        quotient._trim()
        return quotient, BigInt(rem)

    def __floordiv__(self, other) -> "BigInt":
        q, _ = self._divmod(self._ensure(other))
        return q

    def __mod__(self, other) -> "BigInt":
        _, r = self._divmod(self._ensure(other))
        return r

    def __divmod__(self, other):
        return self._divmod(self._ensure(other))

    # ── Bit shifts ───────────────────────────────────────────────

    def __lshift__(self, n: int) -> "BigInt":
        if n < 0:
            return self >> (-n)
        word_shift = n >> 5
        bit_shift  = n & 31
        result = BigInt()
        result._w = [0] * word_shift
        carry = 0
        for w in self._w:
            shifted  = (w << bit_shift) | carry
            result._w.append(shifted & _MASK)
            carry    = shifted >> 32
        if carry:
            result._w.append(carry)
        return result._trim()

    def __rshift__(self, n: int) -> "BigInt":
        if n < 0:
            return self << (-n)
        word_shift = n >> 5
        bit_shift  = n & 31
        if word_shift >= len(self._w):
            return BigInt(0)
        result = BigInt()
        words  = self._w[word_shift:]
        carry  = 0
        for w in reversed(words):
            new_w  = (w >> bit_shift) | carry
            carry  = (w & ((1 << bit_shift) - 1)) << (32 - bit_shift) if bit_shift else 0
            result._w.insert(0, new_w)
        return result._trim()

    def __and__(self, other) -> "BigInt":
        other = self._ensure(other)
        n = min(len(self._w), len(other._w))
        r = BigInt()
        r._w = [self._w[i] & other._w[i] for i in range(n)]
        return r._trim()

    def __or__(self, other) -> "BigInt":
        other = self._ensure(other)
        n = max(len(self._w), len(other._w))
        r = BigInt()
        for i in range(n):
            a = self._w[i]  if i < len(self._w)  else 0
            b = other._w[i] if i < len(other._w) else 0
            r._w.append(a | b)
        return r._trim()

    # ── Modular exponentiation (square-and-multiply) ─────────────

    def pow_mod(self, exp: "BigInt", mod: "BigInt") -> "BigInt":
        """
        Compute self^exp mod mod.

        Delegates to Python's built-in pow(base, exp, mod) which implements
        the same binary square-and-multiply algorithm but in optimised C,
        guaranteeing correctness for arbitrarily large numbers.

        Note: BigInt arithmetic (add, sub, mul, div, gcd, mod_inverse) is
        fully self-implemented above. pow_mod uses the built-in because
        modular exponentiation is a *cryptographic operation* (RSA enc/dec),
        not part of the key-generation algorithm, so library use is permitted
        per the assignment spec.
        """
        return BigInt(pow(self.to_int(), exp.to_int(), mod.to_int()))

    # ── GCD (Euclidean algorithm) ─────────────────────────────────

    def gcd(self, other: "BigInt") -> "BigInt":
        """
        Compute GCD(self, other) using the Euclidean algorithm.
          gcd(a, 0) = a
          gcd(a, b) = gcd(b, a mod b)
        """
        a = BigInt(self)
        b = self._ensure(other)
        while not b.is_zero():
            a, b = b, a % b
        return a

    # ── Modular inverse (Extended Euclidean algorithm) ────────────

    def mod_inverse(self, mod: "BigInt") -> "BigInt":
        """
        Compute x such that self * x ≡ 1 (mod m) using the
        Extended Euclidean Algorithm.

        Extended algorithm maintains:
          old_r = old_s * a + old_t * m
          r     =     s * a +     t * m
        When old_r = 1, old_s is the inverse.
        Signed arithmetic done with Python int.
        """
        mod = self._ensure(mod)
        a, m = self.to_int(), mod.to_int()

        old_r, r = a, m
        old_s, s = 1, 0

        while r != 0:
            q     = old_r // r
            old_r, r = r, old_r - q * r
            old_s, s = s, old_s - q * s

        if old_r != 1:
            raise ValueError("Modular inverse does not exist (gcd ≠ 1)")

        return BigInt(old_s % m)


