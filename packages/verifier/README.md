# @immuva/verifier

## Rôle
Pipeline normatif de décision.

Le verifier :
- orchestre l'ordre des validations
- décide du statut final (INVALID / PENDING / VALID)
- applique le mode offline
- produit le verdict conforme au output contract

## Ordre normatif
1. Checks structurels
2. ResultSet gate
3. Evidence / Outcome coherence
4. Appel du verdict-engine UNIQUEMENT si VALID

## Invariants
- Le verifier est la source de vérité comportementale
- Toute divergence de verdict est un bug critique

## Ne fait PAS
- Canonicalisation bas niveau
- Cryptographie
- Interprétation métier
