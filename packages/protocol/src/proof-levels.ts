/**
 * Proof Levels define the strength of guarantees
 * attached to a verdict.
 *
 * Normative ordering (weak → strong):
 * - BASIC
 * - KEY_BOUND
 * - TIME_ANCHORED
 * - TRANSPARENCY_LOGGED
 */

export type ProofLevel =
  | "BASIC"
  | "KEY_BOUND"
  | "TIME_ANCHORED"
  | "TRANSPARENCY_LOGGED";

export const PROOF_LEVEL_ORDER: ProofLevel[] = [
  "BASIC",
  "KEY_BOUND",
  "TIME_ANCHORED",
  "TRANSPARENCY_LOGGED",
];
