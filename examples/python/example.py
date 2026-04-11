"""
Immuva Python SDK — end-to-end example.

Run:
    pip install -r requirements.txt
    python example.py
"""

from immuva import keygen, prove, verify


def main() -> None:
    # 1. Generate a key pair for the agent
    keys = keygen()
    print(f"Public key  : {keys['public_key_hex']}")
    print(f"Private key : {keys['private_key_hex'][:8]}…")

    # 2. Prove an agent action
    proof = prove(
        event={
            "agent_id": "python-agent-001",
            "kind":     "PAYMENT_DECISION",
            "amount":   1500,
            "currency": "EUR",
            "decision": "approve",
        },
        public_key_hex=keys["public_key_hex"],
        private_key_hex=keys["private_key_hex"],
        evidence={"effective": "R1", "required": "R1", "qualified": True},
        outcome={"value": "approve", "basis": "R1"},
    )
    print(f"\nProof generated:")
    print(f"  crypto_suite : {proof['signing']['crypto_suite']}")
    print(f"  signature    : {proof['signing']['signature'][:16]}…")
    print(f"  key_id       : {proof['key_binding']['key_id'][:16]}…")

    # 3. Verify the proof (offline)
    result = verify(proof)
    print(f"\nVerification : {result['status']}")  # → VALID

    # 4. Tamper with the proof and verify again
    tampered = {**proof, "canonical_event": proof["canonical_event"].replace("1500", "99999")}
    result2 = verify(tampered)
    print(f"Tampered     : {result2['status']} — {result2.get('violations', [])}")  # → INVALID


if __name__ == "__main__":
    main()
