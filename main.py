"""
main.py — Point d'entrée principal
Interface en ligne de commande (CLI) pour l'outil de sécurité des mots de passe.
"""

import sys
from checker import check_password, Strength
from generator import generate_password, generate_passphrase
from utils import (
    colorize, get_int_input, get_yes_no,
    log_event, print_banner, print_strength_bar
)


#  Module : Générateur 
def menu_generate() -> None:
    print(colorize("\n── Générateur de mot de passe ──", "bold"))

    mode = input("  Mode — (1) Mot de passe  (2) Phrase de passe : ").strip()

    if mode == "2":
        count = get_int_input("  Nombre de mots [4–8] : ", 4, 8)
        sep = input("  Séparateur [défaut '-'] : ").strip() or "-"
        passphrase = generate_passphrase(word_count=count, separator=sep)
        print(colorize(f"\n  ✔ Phrase générée : {passphrase}", "green"))
        log_event("GENERATE_PASSPHRASE", f"words={count}")
        return

    # Mot de passe classique
    length = get_int_input("  Longueur [8–128] : ", 8, 128)
    use_upper   = get_yes_no("  Majuscules", default=True)
    use_lower   = get_yes_no("  Minuscules", default=True)
    use_digits  = get_yes_no("  Chiffres", default=True)
    use_symbols = get_yes_no("  Caractères spéciaux", default=True)
    exclude     = input("  Caractères à exclure [laisser vide si aucun] : ").strip()

    quantity = get_int_input("  Nombre de mots de passe à générer [1–10] : ", 1, 10)

    print()
    for i in range(quantity):
        try:
            pwd = generate_password(
                length=length,
                use_upper=use_upper,
                use_lower=use_lower,
                use_digits=use_digits,
                use_symbols=use_symbols,
                exclude_chars=exclude,
            )
            print(colorize(f"  [{i+1}] {pwd}", "green"))
            log_event("GENERATE_PASSWORD", f"length={length}")
        except ValueError as e:
            print(colorize(f"  ✖ Erreur : {e}", "red"))
            return


# Module : Vérificateur 
def menu_check() -> None:
    print(colorize("\n── Vérificateur de mot de passe ──", "bold"))

    import getpass
    # getpass masque la saisie dans le terminal (pas d'écho)
    password = getpass.getpass("  Mot de passe à analyser (saisie masquée) : ")

    if not password:
        print(colorize("  ✖ Aucun mot de passe saisi.", "red"))
        return

    result = check_password(password) 

    strength_colors = {
        Strength.VERY_WEAK:   "red",
        Strength.WEAK:        "red",
        Strength.MEDIUM:      "yellow",
        Strength.STRONG:      "green",
        Strength.VERY_STRONG: "green",
    }
    color = strength_colors[result.strength]

    print(f"\n  Niveau   : {colorize(result.strength.value.upper(), color)}")
    print_strength_bar(result.score)
    print(f"  Entropie : {result.entropy_bits} bits")
    print(f"  Résistance au brute-force (GPU) : {result.crack_time_str}")

    if result.issues:
        print(colorize("\n  Problèmes détectés :", "yellow"))
        for issue in result.issues:
            print(f"    • {issue}")

    if result.suggestions:
        print(colorize("\n  Recommandations :", "cyan"))
        for sug in result.suggestions:
            print(f"    → {sug}")

    # Journalisation sans stocker le mot de passe
    log_event(
        "CHECK_PASSWORD",
        f"length={len(password)} | score={result.score} | entropy={result.entropy_bits}bits"
    )


#  Module : Bonnes pratiques

def menu_tips() -> None:
    tips = """
  
           Bonnes pratiques — Mots de passe           
 
    • Utilisez un gestionnaire de mots de passe         
      (Bitwarden, KeePassXC, 1Password)                 
    • Un mot de passe unique par compte                 
    • Activez le MFA / 2FA partout où c'est possible    
    • Ne réutilisez jamais un mot de passe              
    • Minimum 12 caractères pour les comptes critiques  
    • Changez immédiatement en cas de fuite de données  
      (vérifiez sur haveibeenpwned.com)                 
  
"""
    print(colorize(tips, "cyan"))


#  Boucle principale 

def main() -> None:
    print_banner()
    log_event("SESSION_START")

    menu = """
  ---------------------------------------
  │  1. Générer un mot de passe         │
  │  2. Vérifier un mot de passe        │
  │  3. Bonnes pratiques                │
  │  4. Quitter                         │
  ---------------------------------------
"""
    actions = {
        "1": menu_generate,
        "2": menu_check,
        "3": menu_tips,
    }

    while True:
        print(menu)
        choice = input("  Votre choix : ").strip()

        if choice == "4":
            log_event("SESSION_END")
            print(colorize("\n  Au revoir. Pensez à utiliser un gestionnaire de mots de passe !\n", "cyan"))
            sys.exit(0)

        action = actions.get(choice)
        if action:
            action()
        else:
            print(colorize("  ⚠ Choix invalide. Entrez 1, 2, 3 ou 4.", "yellow"))


if __name__ == "__main__":
    main()
