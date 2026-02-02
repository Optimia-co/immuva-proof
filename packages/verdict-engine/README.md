# @immuva/verdict-engine

## Rôle
Construction d'un verdict VALID uniquement.

## Invariant fondamental
- Ce module ne rend JAMAIS INVALID, PENDING ou NON_CLOSABLE
- Il suppose que tous les checks ont déjà été faits
- Toute autre utilisation est un bug

## Responsabilité
- Rendre un verdict VALID pur et déterministe
- Ne contenir aucune logique de décision

## Sécurité
Ce découplage empêche toute élévation de privilège logique.
