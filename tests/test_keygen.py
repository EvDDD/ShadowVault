"""
Test Suite — Keygen: CSPRNG, Miller-Rabin, generate_prime, RSA (TC-KG-001 → TC-KG-006)
"""
import pytest
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.bigint import BigInt
from core.keygen import CSPRNG, miller_rabin, generate_prime, generate_rsa


class TestCSPRNG:
    """TC-KG-001: CSPRNG sinh bytes ngẫu nhiên"""

    def test_random_bytes_length(self):
        rng = CSPRNG()
        b = rng.random_bytes(32)
        assert len(b) == 32

    def test_random_bytes_different(self):
        rng = CSPRNG()
        b1 = rng.random_bytes(32)
        b2 = rng.random_bytes(32)
        assert b1 != b2

    def test_random_bytes_various_lengths(self):
        rng = CSPRNG()
        for n in [1, 16, 64, 128]:
            assert len(rng.random_bytes(n)) == n

    def test_two_instances_differ(self):
        rng1 = CSPRNG()
        rng2 = CSPRNG()
        assert rng1.random_bytes(32) != rng2.random_bytes(32)


class TestMillerRabin:
    """TC-KG-002, TC-KG-003: Miller-Rabin"""

    def setup_method(self):
        self.rng = CSPRNG()

    def test_known_primes(self):
        """TC-KG-002: nhận diện số nguyên tố đúng"""
        primes = [2, 3, 5, 7, 11, 13, 17, 97, 997, 104729]
        for p in primes:
            assert miller_rabin(BigInt(p), self.rng) is True, f"{p} should be prime"

    def test_known_composites(self):
        """TC-KG-003: phát hiện hợp số"""
        composites = [4, 9, 15, 100, 1000000]
        for n in composites:
            assert miller_rabin(BigInt(n), self.rng) is False, f"{n} should be composite"

    def test_carmichael_number(self):
        """TC-KG-003: phát hiện số Carmichael (561)"""
        assert miller_rabin(BigInt(561), self.rng) is False

    def test_even_number(self):
        assert miller_rabin(BigInt(4), self.rng) is False

    def test_one_is_not_prime(self):
        assert miller_rabin(BigInt(1), self.rng) is False


class TestGeneratePrime:
    """TC-KG-004: generate_prime sinh đúng số bit"""

    def setup_method(self):
        self.rng = CSPRNG()

    def test_prime_bit_length(self):
        p = generate_prime(64, self.rng)
        assert p.bit_length() == 64

    def test_prime_is_prime(self):
        p = generate_prime(64, self.rng)
        assert miller_rabin(p, self.rng) is True

    def test_prime_is_odd(self):
        p = generate_prime(128, self.rng)
        assert not p.is_even()


class TestGenerateRSA:
    """TC-KG-005, TC-KG-006: generate_rsa và RSA encrypt/decrypt"""

    def setup_method(self):
        self.rng = CSPRNG()
        # Dùng 512 bits cho tốc độ test
        self.kp = generate_rsa(bits=512, rng=self.rng)

    def test_e_value(self):
        """TC-KG-005: e = 65537"""
        assert self.kp.e.to_int() == 65537

    def test_n_equals_p_times_q(self):
        """TC-KG-005: n = p × q"""
        assert (self.kp.p * self.kp.q).to_int() == self.kp.n.to_int()

    def test_ed_mod_lambda(self):
        """TC-KG-005: e × d ≡ 1 (mod λ(n))"""
        p1 = self.kp.p - BigInt(1)
        q1 = self.kp.q - BigInt(1)
        lam = (p1 * q1) // p1.gcd(q1)
        assert ((self.kp.e * self.kp.d) % lam).to_int() == 1

    def test_encrypt_decrypt_roundtrip(self):
        """TC-KG-006: RSA encrypt → decrypt roundtrip"""
        msg = BigInt(123456789)
        c = self.kp.encrypt(msg)
        m = self.kp.decrypt(c)
        assert m.to_int() == msg.to_int()

    def test_encrypt_decrypt_large_message(self):
        msg = BigInt(2**64 + 42)
        c = self.kp.encrypt(msg)
        m = self.kp.decrypt(c)
        assert m.to_int() == msg.to_int()
