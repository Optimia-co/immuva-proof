import fs from "node:fs";
import path from "node:path";

export type RegistryProvider = {
  loadJson: (name: string, version: string) => any;
};

export function fsRegistryProvider(root: string): RegistryProvider {
  return {
    loadJson(name, version) {
      const p = path.join(root, "registries", version, `${name}.json`);
      if (!fs.existsSync(p)) {
        throw new Error(`REGISTRY_NOT_FOUND:${p}`);
      }
      return JSON.parse(fs.readFileSync(p, "utf8"));
    }
  };
}
