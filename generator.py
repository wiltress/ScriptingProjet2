"""
generator.py — Générateur de mots de passe sécurisés
Utilise uniquement `secrets` (cryptographiquement sûr, CSPRNG)
"""

import secrets
import string
from typing import Optional


# Jeux de caractères
UPPERCASE = string.ascii_uppercase
LOWERCASE = string.ascii_lowercase
DIGITS = string.digits
SYMBOLS = "!@#$%^&*()-_=+[]{}|;:,.<>?"


def generate_password(
    length: int = 16,
    use_upper: bool = True,
    use_lower: bool = True,
    use_digits: bool = True,
    use_symbols: bool = True,
    exclude_chars: str = "",
) -> str:
    """
    Génère un mot de passe cryptographiquement sûr.

    Args:
        length:        Longueur du mot de passe (min 8, max 128)
        use_upper:     Inclure des majuscules
        use_lower:     Inclure des minuscules
        use_digits:    Inclure des chiffres
        use_symbols:   Inclure des caractères spéciaux
        exclude_chars: Caractères à exclure (ex: "0O1lI" pour éviter la confusion)

    Returns:
        Mot de passe généré sous forme de chaîne

    Raises:
        ValueError: Si les paramètres sont invalides
    """
    #  Validation (condition de validation de MDP)
    if not (8 <= length <= 128):
        raise ValueError("La longueur doit être comprise entre 8 et 128 caractères.")

    if not any([use_upper, use_lower, use_digits, use_symbols]):
        raise ValueError("Au moins un jeu de caractères doit être sélectionné.")

    #  Construction du pool 
    pool = ""
    required: list[str] = []  # garantit la présence d'au moins 1 caractère de chaque catégorie

    if use_upper:
        chars = "".join(c for c in UPPERCASE if c not in exclude_chars)
        pool += chars
        required.append(secrets.choice(chars))

    if use_lower:
        chars = "".join(c for c in LOWERCASE if c not in exclude_chars)
        pool += chars
        required.append(secrets.choice(chars))

    if use_digits:
        chars = "".join(c for c in DIGITS if c not in exclude_chars)
        pool += chars
        required.append(secrets.choice(chars))

    if use_symbols:
        chars = "".join(c for c in SYMBOLS if c not in exclude_chars)
        pool += chars
        required.append(secrets.choice(chars))

    if not pool:
        raise ValueError("Le pool de caractères est vide après exclusion.")

    #  Génération sécurisée 
    # Remplir les positions restantes depuis le pool complet
    remaining_length = length - len(required)
    password_chars = required + [secrets.choice(pool) for _ in range(remaining_length)]

    # Mélange cryptographiquement sûr (Fisher-Yates via secrets)
    secrets.SystemRandom().shuffle(password_chars)

    return "".join(password_chars)


def generate_passphrase(word_count: int = 4, separator: str = "-") -> str:
    """
    Génère une phrase de passe style Diceware (mémorisable + robuste).
    Utilise une liste de mots intégrée réduite (production: charger EFF word list).

    Args:
        word_count: Nombre de mots (min 4)
        separator:  Séparateur entre les mots

    Returns:
        Phrase de passe
    """
    if word_count < 4:
        raise ValueError("Minimum 4 mots pour une phrase de passe sécurisée.")

    # mise en place d'une EFF liste, (dans notre cas réduite) 
    word_pool = [
        "apple", "bridge", "cloud", "delta", "eagle", "forest", "giant",
        "harbor", "island", "jacket", "kernel", "lemon", "mirror", "noble",
        "ocean", "planet", "quartz", "river", "stone", "tiger", "ultra",
        "valley", "winter", "xenon", "yellow", "zenith", "amber", "blaze",
        "cedar", "drift", "ember", "flame", "grace", "heron", "ivory",
        "jewel", "karma", "lance", "maple", "north", "ozone", "pearl",
    ]
    words = [secrets.choice(word_pool) for _ in range(word_count)]
    return separator.join(words)
