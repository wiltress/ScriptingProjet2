# Password Security Tool — Générateur & Analyseur de Sécurité

Outil modulaire en Python dédié à la gestion de la robustesse des mots de passe. Il permet de générer des secrets cryptographiquement sûrs et d'évaluer la résistance des mots de passe face aux cyberattaques.

---

## Architecture

Le projet est structuré en cinq modules principaux et un module de test :

- **main.py** : Point d'entrée, orchestration du menu CLI et interaction utilisateur.
- **checker.py** : Logique d'analyse (entropie, détection de patterns, calcul de force brute).
- **generator.py** : Moteur de génération sécurisée (CSPRNG) et phrases de passe (Diceware).
- **utils.py** : Utilitaires d'affichage, validation des entrées et journalisation d'audit.
- **test_password_tool.py** : Suite de tests unitaires pour valider la robustesse du code.
- **audit.log** : Journal des événements de sécurité (généré automatiquement).

## Prérequis

- **Python 3.10+** (pour l'utilisation des dataclasses et du typage moderne).
- **Dépendances externes** : `pytest` (uniquement pour l'exécution des tests).
- **Modules standards** : `secrets`, `re`, `math`, `logging`, `getpass`.

## Utilisation

### Lancement de l'application
```bash
python main.py