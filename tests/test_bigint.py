"""
Test Suite — BigInt (TC-BI-001 → TC-BI-008)
Kiểm thử các phép toán số nguyên lớn tự triển khai.
"""
import pytest
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.bigint import BigInt


class TestBigIntConstruction:
    """TC-BI-001: Khởi tạo BigInt từ int"""

    def test_from_zero(self):
        assert BigInt(0).to_int() == 0

    def test_from_small(self):
        assert BigInt(255).to_int() == 255

    def test_from_large_64bit(self):
        val = 2**64
        assert BigInt(val).to_int() == val

    def test_from_large_1024bit(self):
        val = 2**1024
        assert BigInt(val).to_int() == val

    def test_from_bytes(self):
        data = b"\x01\x00"  # 256
        assert BigInt(data).to_int() == 256

    def test_to_bytes_roundtrip(self):
        val = 2**128 - 1
        b = BigInt(val).to_bytes()
        assert BigInt.from_bytes(b).to_int() == val

    def test_negative_raises(self):
        with pytest.raises(ValueError):
            BigInt(-1)


class TestBigIntAddition:
    """TC-BI-002: Phép cộng BigInt"""

    def test_basic_add(self):
        assert (BigInt(100) + BigInt(200)).to_int() == 300

    def test_carry_propagation(self):
        a = BigInt(2**512 - 1)
        b = BigInt(1)
        assert (a + b).to_int() == 2**512

    def test_add_zero(self):
        a = BigInt(12345)
        assert (a + BigInt(0)).to_int() == 12345


class TestBigIntSubtraction:
    """TC-BI-003: Phép trừ BigInt"""

    def test_basic_sub(self):
        assert (BigInt(1000) - BigInt(999)).to_int() == 1

    def test_sub_to_zero(self):
        assert (BigInt(42) - BigInt(42)).to_int() == 0

    def test_negative_result_raises(self):
        with pytest.raises(ArithmeticError):
            BigInt(10) - BigInt(20)


class TestBigIntMultiplication:
    """TC-BI-004: Phép nhân BigInt"""

    def test_basic_mul(self):
        assert (BigInt(123) * BigInt(456)).to_int() == 123 * 456

    def test_power_of_two(self):
        a = BigInt(2**256)
        b = BigInt(2**256)
        assert (a * b).to_int() == 2**512

    def test_mul_by_zero(self):
        assert (BigInt(999) * BigInt(0)).to_int() == 0


class TestBigIntDivision:
    """TC-BI-005: Phép chia và modulo BigInt"""

    def test_basic_divmod(self):
        a = BigInt(12345678901234567890)
        b = BigInt(9876543210)
        q = a // b
        r = a % b
        assert (q * b + r).to_int() == a.to_int()

    def test_div_by_zero(self):
        with pytest.raises(ZeroDivisionError):
            BigInt(10) // BigInt(0)

    def test_smaller_dividend(self):
        assert (BigInt(5) // BigInt(10)).to_int() == 0
        assert (BigInt(5) % BigInt(10)).to_int() == 5


class TestBigIntGCD:
    """TC-BI-006: GCD (thuật toán Euclid)"""

    def test_gcd_basic(self):
        assert BigInt(48).gcd(BigInt(18)).to_int() == 6

    def test_gcd_with_zero(self):
        assert BigInt(0).gcd(BigInt(17)).to_int() == 17

    def test_gcd_equal(self):
        assert BigInt(42).gcd(BigInt(42)).to_int() == 42

    def test_gcd_coprime(self):
        assert BigInt(17).gcd(BigInt(13)).to_int() == 1


class TestBigIntModInverse:
    """TC-BI-007: Nghịch đảo modular (Extended Euclidean)"""

    def test_mod_inverse_basic(self):
        a = BigInt(65537)
        m = BigInt(3120)  # phi(3233) for small RSA
        d = a.mod_inverse(m)
        assert ((a * d) % m).to_int() == 1

    def test_mod_inverse_no_exist(self):
        with pytest.raises(ValueError):
            BigInt(6).mod_inverse(BigInt(9))  # gcd=3 ≠ 1


class TestBigIntPowMod:
    """TC-BI-008: pow_mod (lũy thừa modular)"""

    def test_pow_mod_basic(self):
        result = BigInt(2).pow_mod(BigInt(10), BigInt(1000))
        assert result.to_int() == 24  # 1024 mod 1000

    def test_pow_mod_large(self):
        # Fermat's little theorem: a^(p-1) ≡ 1 (mod p) for prime p
        p = BigInt(104729)
        result = BigInt(2).pow_mod(p - BigInt(1), p)
        assert result.to_int() == 1
