import { keygen, prove } from "./index.js";

async function main() {
  const { public_key_hex, private_key_hex } = await keygen({ out: "testkey" });

  const event = {
    action: "demo",
    value: 42
  };

  const proof = await prove({
    event,
    private_key_hex,
    public_key_hex
  });

  console.log("SDK V2 OK");
  console.log("Public key:", public_key_hex.slice(0, 16) + "…");
  console.log("Signature:", proof.signing?.signature?.slice(0, 16) + "…");
  console.log("Canonical:", proof.canonical_event?.slice(0, 32) + "…");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
