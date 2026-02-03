export const ORDER = ["BASIC","KEY_BOUND","TIME_ANCHORED","TRANSPARENCY_LOGGED"] as const;
export type ProofLevel = typeof ORDER[number];

export const rank = (p: ProofLevel) => ORDER.indexOf(p);
