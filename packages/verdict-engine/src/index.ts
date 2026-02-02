import type { StubInput, Verdict } from "@immuva/protocol";

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
