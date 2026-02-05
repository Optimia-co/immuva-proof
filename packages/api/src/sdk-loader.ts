type SDK = {
  keygen: () => Promise<{ public_key_hex: string; private_key_hex: string }>;
  prove: (params: any) => Promise<any>;
  verify: (proof: any, opts?: any) => Promise<any>;
};

export async function loadSDK(): Promise<SDK> {
  // SDK est hors workspace: on importe le dist directement.
  // Le chemin est depuis packages/api/dist -> ../sdk/dist/index.js (en runtime)
  const mod: any = await import("../../sdk/dist/index.js");
  return mod as SDK;
}
