import type { ICredentialType, INodeProperties } from "n8n-workflow";

export class ImmuvaApi implements ICredentialType {
  name = "immuvaApi";
  displayName = "Immuva API";
  documentationUrl = "https://docs.immuva.io";

  properties: INodeProperties[] = [
    {
      displayName: "API Key",
      name: "apiKey",
      type: "string",
      typeOptions: { password: true },
      default: "",
      required: true,
      description: "Your Immuva API key (starts with imv_live_)",
    },
    {
      displayName: "Public Key (hex)",
      name: "publicKeyHex",
      type: "string",
      default: "",
      required: true,
      description: "Ed25519 public key in hex format (64 characters)",
    },
    {
      displayName: "Private Key (hex)",
      name: "privateKeyHex",
      type: "string",
      typeOptions: { password: true },
      default: "",
      required: true,
      description: "Ed25519 private key in hex format (64 characters)",
    },
  ];
}
