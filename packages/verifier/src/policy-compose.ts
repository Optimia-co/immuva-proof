import { ProofLevel, PROOF_LEVEL_ORDER } from "@immuva/protocol";

export type RawPolicy = {
  policy_id: string;
  min_proof_level?: ProofLevel;
  require?: {
    key_bound?: boolean;
    time_anchor?: boolean;
    transparency_log?: boolean;
  };
};

export type EffectivePolicy = {
  min_proof_level?: ProofLevel;
  require: {
    key_bound: boolean;
    time_anchor: boolean;
    transparency_log: boolean;
  };
  sources: string[];
};

const maxProof = (
  a?: ProofLevel,
  b?: ProofLevel
): ProofLevel | undefined => {
  if (!a) return b;
  if (!b) return a;
  return PROOF_LEVEL_ORDER.indexOf(a) >= PROOF_LEVEL_ORDER.indexOf(b)
    ? a
    : b;
};

export function composePolicies(
  policies: RawPolicy[]
): EffectivePolicy {
  let min_proof_level: ProofLevel | undefined = undefined;

  const require = {
    key_bound: false,
    time_anchor: false,
    transparency_log: false
  };

  const sources: string[] = [];

  for (const p of policies) {
    sources.push(p.policy_id);

    min_proof_level = maxProof(
      min_proof_level,
      p.min_proof_level
    );

    if (p.require?.key_bound) require.key_bound = true;
    if (p.require?.time_anchor) require.time_anchor = true;
    if (p.require?.transparency_log) require.transparency_log = true;
  }

  return { min_proof_level, require, sources };
}
