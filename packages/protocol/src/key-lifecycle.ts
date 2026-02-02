export type KeyStatus = "ACTIVE" | "ROTATED" | "REVOKED";

export type KeyDescriptor = {
  key_id: string;              // sha256(public_key_der)
  public_key: string;          // DER hex
  status: KeyStatus;
  activated_at: string;        // ISO8601
  rotated_at?: string;         // ISO8601
  revoked_at?: string;         // ISO8601
};
