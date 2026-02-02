export type TLLeaf = {
  leaf_index: number;
  payload_hash: string;   // sha256(canonical_event)
};

export type TLInclusionProof = {
  leaf_index: number;
  leaf_hash: string;
  proof: string[];        // merkle path (hex)
  root: string;           // merkle root (hex)
};

export type TLRoot = {
  root: string;
  tree_size: number;
  generated_at: string;  // ISO8601
};
