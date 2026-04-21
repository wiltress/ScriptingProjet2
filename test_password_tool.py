"""
test_password_tool.py — Tests unitaires (pytest)
Couvre generator.py et checker.py.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

import pytest
from generator import generate_password, generate_passphrase
from checker import check_password, Strength


#Tests — Générateur

class TestGeneratePassword:

    def test_default_length(self):
        pwd = generate_password()
        assert len(pwd) == 16

    def test_custom_length(self):
        for length in [8, 12, 32, 64, 128]:
            assert len(generate_password(length=length)) == length

    def test_length_too_short_raises(self):
        with pytest.raises(ValueError, match="longueur"):
            generate_password(length=4)

    def test_length_too_long_raises(self):
        with pytest.raises(ValueError, match="longueur"):
            generate_password(length=200)

    def test_no_charset_raises(self):
        with pytest.raises(ValueError):
            generate_password(use_upper=False, use_lower=False,
                              use_digits=False, use_symbols=False)

    def test_uppercase_only(self):
        import string
        pwd = generate_password(length=20, use_upper=True, use_lower=False,
                                 use_digits=False, use_symbols=False)
        assert all(c in string.ascii_uppercase for c in pwd)

    def test_digits_only(self):
        import string
        pwd = generate_password(length=20, use_upper=False, use_lower=False,
                                 use_digits=True, use_symbols=False)
        assert all(c in string.digits for c in pwd)

    def test_exclude_chars(self):
        excluded = "0O1lI"
        pwd = generate_password(length=50, exclude_chars=excluded)
        for c in excluded:
            assert c not in pwd

    def test_uniqueness(self):
        """Deux mots de passe consécutifs ne doivent pas être identiques (CSPRNG)."""
        passwords = {generate_password(length=16) for _ in range(100)}
        assert len(passwords) > 95  # tolérance statistique

    def test_required_chars_present(self):
        """Chaque catégorie activée doit être représentée."""
        import string
        for _ in range(50):
            pwd = generate_password(length=12, use_upper=True, use_lower=True,
                                     use_digits=True, use_symbols=True)
            assert any(c in string.ascii_uppercase for c in pwd)
            assert any(c in string.ascii_lowercase for c in pwd)
            assert any(c in string.digits for c in pwd)
            assert any(c in string.punctuation for c in pwd)


class TestGeneratePassphrase:

    def test_word_count(self):
        phrase = generate_passphrase(word_count=4)
        assert len(phrase.split("-")) == 4

    def test_custom_separator(self):
        phrase = generate_passphrase(word_count=5, separator="_")
        assert "_" in phrase

    def test_min_word_count_raises(self):
        with pytest.raises(ValueError):
            generate_passphrase(word_count=2)


# 
# Tests — Vérificateur (pour confirmation de la structuration du MDP)
# 

class TestCheckPassword:

    def test_very_weak_common_password(self):
        result = check_password("password")
        assert result.strength in (Strength.VERY_WEAK, Strength.WEAK)
        assert result.score < 40

    def test_short_password_penalized(self):
        result = check_password("Ab1!")
        assert any("court" in issue.lower() or "court" in issue for issue in result.issues)
        assert result.score < 50

    def test_strong_password(self):
        result = check_password("X#9kPq!mZ@3rLv8&")
        assert result.strength in (Strength.STRONG, Strength.VERY_STRONG)
        assert result.score >= 70

    def test_keyboard_sequence_detected(self):
        result = check_password("qwerty123!")
        issues_text = " ".join(result.issues).lower()
        assert "séquence" in issues_text or "clavier" in issues_text

    def test_repeated_chars_detected(self):
        result = check_password("aaaBBB111@@@")
        issues_text = " ".join(result.issues).lower()
        assert "répétition" in issues_text

    def test_entropy_increases_with_length(self):
        short = check_password("Ab1!")
        long_ = check_password("Ab1!Ab1!Ab1!Ab1!")
        assert long_.entropy_bits > short.entropy_bits

    def test_crack_time_returned(self):
        result = check_password("Hello123")
        assert result.crack_time_str != ""

    def test_missing_symbol_flagged(self):
        result = check_password("HelloWorld123")
        suggestions_text = " ".join(result.suggestions).lower()
        assert "symbole" in suggestions_text or "spécial" in suggestions_text

    def test_score_bounded(self):
        for pwd in ["a", "password", "X#9kPq!mZ@3rLv8&TtYy2$", "abc123"]:
            result = check_password(pwd)
            assert 0 <= result.score <= 100
