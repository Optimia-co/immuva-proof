type SDK = {
  keygen: () => Promise<{ public_key_hex: string; private_key_hex: string }>;
  prove: (params: any) => Promise<any>;
  verify: (proof: any, opts?: any) => Promise<any>;
};

export async function loadSDK(): Promise<SDK> {
  const mod: any = await import("@immuva/sdk");
  return mod as SDK;
}
