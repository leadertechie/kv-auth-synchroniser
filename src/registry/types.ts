import type { RegistryEntry } from "../types";

export interface PublicKeyRegistry {
  getPublicKey(serviceName: string): Promise<RegistryEntry | null>;
  publishPublicKey(serviceName: string, entry: RegistryEntry): Promise<void>;
}
