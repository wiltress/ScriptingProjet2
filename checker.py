"""
checker.py — Vérificateur de robustesse des mots de passe
Calcule l'entropie réelle, détecte les patterns faibles,
et simule le temps de craquage par brute-force.
"""

import math
import re
import string
from dataclasses import dataclass, field
from enum import Enum


class Strength(Enum):
    VERY_WEAK = "Très faible"
    WEAK = "Faible"
    MEDIUM = "Moyen"
    STRONG = "Fort"
    VERY_STRONG = "Très fort"


# Mots de passe les plus fréquents (version réduite, car beaucoup plus imporatnt que ça )
COMMON_PASSWORDS = {
    "password", "123456", "password1", "12345678", "qwerty", "abc123",
    "111111", "1234567", "iloveyou", "adobe123", "123123", "sunshine",
    "princess", "letmein", "dragon", "master", "monkey", "shadow",
    "azerty", "motdepasse", "admin", "root", "test", "pass",
}

# Séquences clavier courantes
KEYBOARD_SEQUENCES = [
    "qwerty", "azerty", "qwertz", "asdfgh", "zxcvbn",
    "123456", "654321", "abcdef", "fedcba",
]

# Patterns répétitifs
REPEAT_PATTERN = re.compile(r"(.)\1{2,}")          # 3+ caractères identiques consécutifs
SEQUENTIAL_PATTERN = re.compile(r"(012|123|234|345|456|567|678|789|890|"
                                 r"abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|"
                                 r"jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|"
                                 r"stu|tuv|uvw|vwx|wxy|xyz)", re.IGNORECASE)


@dataclass
class CheckResult:
    password: str
    score: int                        # 0–100
    strength: Strength
    entropy_bits: float
    crack_time_str: str
    issues: list[str] = field(default_factory=list)
    suggestions: list[str] = field(default_factory=list)


def _compute_entropy(password: str) -> float:
    """
    Calcule l'entropie H = L × log2(N)
    où L = longueur, N = taille du pool de caractères utilisés.
    """
    pool_size = 0
    if any(c in string.ascii_lowercase for c in password):
        pool_size += 26
    if any(c in string.ascii_uppercase for c in password):
        pool_size += 26
    if any(c in string.digits for c in password):
        pool_size += 10
    if any(c in string.punctuation for c in password):
        pool_size += 32

    if pool_size == 0:
        return 0.0
    return len(password) * math.log2(pool_size)


def _estimate_crack_time(entropy_bits: float) -> str:
    """
    Estime le temps de craquage en supposant 10^10 tentatives/seconde
    (GPU moderne, attaque hors ligne sur hash MD5).
    """
    attempts = 2 ** entropy_bits
    rate = 1e10  # tentatives/seconde

    seconds = attempts / rate

    if seconds < 1:
        return "moins d'une seconde"
    if seconds < 60:
        return f"{seconds:.0f} secondes"
    if seconds < 3600:
        return f"{seconds/60:.0f} minutes"
    if seconds < 86400:
        return f"{seconds/3600:.1f} heures"
    if seconds < 31536000:
        return f"{seconds/86400:.0f} jours"
    if seconds < 3.154e9:
        return f"{seconds/31536000:.0f} années"
    return f"{seconds/3.154e9:.2e} siècles"


def check_password(password: str) -> CheckResult:
    """
    Analyse complète d'un mot de passe.

    Args:
        password: Mot de passe à analyser

    Returns:
        CheckResult avec score, niveau, entropie, temps de craquage,
        liste des problèmes détectés, et suggestions d'amélioration.
    """
    issues: list[str] = []
    suggestions: list[str] = []
    score = 100

    #  1. Longueur 
    length = len(password)
    if length < 8:
        issues.append(f"Trop court ({length} caractères, minimum 8 requis).")
        suggestions.append("Utilisez au moins 8 caractères (12+ recommandé).")
        score -= 40
    elif length < 12:
        score -= 10
        suggestions.append("Allongez à 12+ caractères pour plus de sécurité.")
    elif length >= 20:
        score += 5  # bonus longueur

    #2. Diversité de caractères 
    has_lower = bool(re.search(r"[a-z]", password))
    has_upper = bool(re.search(r"[A-Z]", password))
    has_digit = bool(re.search(r"\d", password))
    has_symbol = bool(re.search(r"[^a-zA-Z0-9]", password))

    diversity = sum([has_lower, has_upper, has_digit, has_symbol])

    if not has_lower:
        issues.append("Aucune lettre minuscule.")
        suggestions.append("Ajoutez des lettres minuscules.")
        score -= 10
    if not has_upper:
        issues.append("Aucune lettre majuscule.")
        suggestions.append("Ajoutez des lettres majuscules.")
        score -= 10
    if not has_digit:
        issues.append("Aucun chiffre.")
        suggestions.append("Ajoutez des chiffres.")
        score -= 10
    if not has_symbol:
        issues.append("Aucun caractère spécial.")
        suggestions.append("Ajoutez des symboles (!@#$%...).")
        score -= 10

    #  3. Mot de passe commun 
    if password.lower() in COMMON_PASSWORDS:
        issues.append("Mot de passe trop commun — présent dans les bases de données de craquage.")
        suggestions.append("Choisissez un mot de passe unique.")
        score -= 50

    #  4. Séquences clavier 
    pwd_lower = password.lower()
    for seq in KEYBOARD_SEQUENCES:
        if seq in pwd_lower:
            issues.append(f"Séquence clavier détectée : '{seq}'.")
            suggestions.append("Évitez les séquences de clavier comme 'qwerty' ou '123456'.")
            score -= 20
            break

    # ── 5. Répétitions 
    if REPEAT_PATTERN.search(password):
        issues.append("Répétition de caractères identiques consécutifs.")
        suggestions.append("Évitez de répéter le même caractère 3 fois ou plus.")
        score -= 10

    #  6. Séquences alphanumériques 
    if SEQUENTIAL_PATTERN.search(password):
        issues.append("Séquence alphabétique ou numérique simple détectée.")
        score -= 10

    #  7. Entropie et temps de craquage 
    entropy = _compute_entropy(password)
    crack_time = _estimate_crack_time(entropy)

    if entropy < 40:
        score -= 20
    elif entropy < 60:
        score -= 5

    #  Normalisation du score 
    score = max(0, min(100, score))

    #  Détermination du niveau 
    if score < 20:
        strength = Strength.VERY_WEAK
    elif score < 40:
        strength = Strength.WEAK
    elif score < 60:
        strength = Strength.MEDIUM
    elif score < 80:
        strength = Strength.STRONG
    else:
        strength = Strength.VERY_STRONG

    return CheckResult(
        password=password,
        score=score,
        strength=strength,
        entropy_bits=round(entropy, 1),
        crack_time_str=crack_time,
        issues=issues,
        suggestions=suggestions,
    )
