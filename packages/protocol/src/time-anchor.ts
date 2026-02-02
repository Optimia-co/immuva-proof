export type TimeAnchorType =
  | "RFC3161"
  | "BLOCKCHAIN"
  | "TRANSPARENCY_LOG";

export type TimeAnchor = {
  type: TimeAnchorType;
  anchor_id: string;      // hash(tx, log entry, TSA token)
  anchored_at: string;    // ISO8601
  payload_hash: string;   // sha256(canonical_event)
  proof?: string;         // opaque (DER / JSON / CBOR)
};
