import type { StubInput, Verdict } from "@immuva/protocol";

/**
 * Verdict engine (pur)
 * Construit UNIQUEMENT un verdict VALID.
 * Le choix du status (INVALID/PENDING/...) reste dans verifier.
 */
export function renderValidVerdict(
  input: StubInput,
  opts?: { offline?: boolean }
): Verdict {
  return {
    status: "VALID",
    evidence: input.evidence!,
    outcome: input.outcome!,
    pointers: input.pointers,
    ...(opts?.offline ? { mode: "offline" } : {})
  };
}

// Alias de compat temporaire (si des imports existent encore)
export const computeStatus = renderValidVerdict;
