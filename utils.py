"""
utils.py — Utilitaires partagés
Affichage CLI, validation des entrées, journalisation d'audit.
"""

import logging
import os
import sys
from datetime import datetime


# Journalisation: car en prod 
# necessaire pour l'audit de sécurité, de conformité 
def setup_audit_logger(log_file: str = "audit.log") -> logging.Logger:
    """
    Configure un logger d'audit. Les événements sont horodatés et ne
    contiennent JAMAIS le mot de passe en clair (conformité RGPD / ISO 27001).
    """
    logger = logging.getLogger("password_tool.audit")
    logger.setLevel(logging.INFO)

    # Évite de dupliquer les handlers si appelé plusieurs fois
    if not logger.handlers:
        fh = logging.FileHandler(log_file, encoding="utf-8")
        fh.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(message)s"))
        logger.addHandler(fh)

    return logger


AUDIT_LOG = setup_audit_logger()


def log_event(event: str, detail: str = "") -> None:
    """Enregistre un événement d'audit sans stocker de données sensibles."""
    AUDIT_LOG.info(f"{event} | {detail}")


# Affichage coloré (ANSI, désactivé sur Windows sans support) 
_USE_COLOR = sys.stdout.isatty() and os.name != "nt"

_COLORS = {
    "red":     "\033[91m",
    "yellow":  "\033[93m",
    "green":   "\033[92m",
    "cyan":    "\033[96m",
    "bold":    "\033[1m",
    "reset":   "\033[0m",
}


def colorize(text: str, color: str) -> str:
    if not _USE_COLOR:
        return text
    return f"{_COLORS.get(color, '')}{text}{_COLORS['reset']}"


def print_banner() -> None:
    banner = """
--------------------------------------------
|      🔐 Password Security Tool           |
|   Générateur & Vérificateur v1.0          |
--------------------------------------------
"""
    print(colorize(banner, "cyan"))


def print_strength_bar(score: int) -> None:
    """Affiche une barre de progression colorée pour le score de sécurité."""
    bar_length = 30
    filled = int(bar_length * score / 100)
    empty = bar_length - filled

    color = "red" if score < 40 else "yellow" if score < 70 else "green"
    bar = colorize("█" * filled, color) + "░" * empty
    print(f"  Score : [{bar}] {score}/100")


def get_int_input(prompt: str, min_val: int, max_val: int) -> int:
    """Demande un entier à l'utilisateur avec validation de plage."""
    while True:
        try:
            value = int(input(prompt))
            if min_val <= value <= max_val:
                return value
            print(colorize(f"  ⚠ Veuillez entrer un nombre entre {min_val} et {max_val}.", "yellow"))
        except ValueError:
            print(colorize("  ⚠ Entrée invalide. Veuillez entrer un nombre entier.", "yellow"))


def get_yes_no(prompt: str, default: bool = True) -> bool:
    """Demande une confirmation oui/non."""
    hint = "[O/n]" if default else "[o/N]"
    while True:
        raw = input(f"{prompt} {hint} : ").strip().lower()
        if raw in ("o", "oui", "y", "yes", ""):
            return True if (raw == "" and default) else raw in ("o", "oui", "y", "yes")
        if raw in ("n", "non", "no"):
            return False
        print(colorize("  ⚠ Répondez par 'o' (oui) ou 'n' (non).", "yellow"))
