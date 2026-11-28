"""Tests for one-time operator recovery-code cryptography."""
import pytest

from isp_radius.security.operator_mfa import (
    generate_recovery_codes,
    hash_recovery_code,
    normalize_recovery_code,
)


def test_recovery_batch_contains_ten_unique_144_bit_codes():
    codes = generate_recovery_codes()
    assert len(codes) == 10
    assert len(set(codes)) == 10
    assert all(len(code) == 41 for code in codes)
    assert all(len(code.split("-")) == 6 for code in codes)
    assert len({hash_recovery_code(code) for code in codes}) == 10


def test_recovery_code_normalization_is_case_and_separator_insensitive():
    code = "abcdef-012345-6789ab-cdef01-234567-89abcd"
    assert normalize_recovery_code(code) == "ABCDEF0123456789ABCDEF0123456789ABCD"
    assert hash_recovery_code(code) == hash_recovery_code(code.replace("-", "").lower())


@pytest.mark.parametrize("value", ["", "abc", "G" * 36, "A" * 35, "A" * 37])
def test_recovery_code_rejects_invalid_values(value):
    with pytest.raises(ValueError, match="invalid recovery code"):
        hash_recovery_code(value)


def test_recovery_code_rejects_non_string_values():
    with pytest.raises(TypeError, match="invalid recovery code"):
        hash_recovery_code(None)
