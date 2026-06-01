import type { PublicKeyRegistry } from "./types";
import type { RegistryEntry } from "../types";
import { DEFAULT_KV_PREFIX } from "../constants";

export class KVPublicKeyRegistry implements PublicKeyRegistry {
  constructor(
    private readonly kv: any,
    private readonly prefix: string = DEFAULT_KV_PREFIX
  ) {}

  async getPublicKey(serviceName: string): Promise<RegistryEntry | null> {
    const key = `${this.prefix}${serviceName}`;
    const raw = await this.kv.get(key);
    if (!raw) return null;
    return JSON.parse(raw) as RegistryEntry;
  }

  async publishPublicKey(serviceName: string, entry: RegistryEntry): Promise<void> {
    const key = `${this.prefix}${serviceName}`;
    await this.kv.put(key, JSON.stringify(entry));
  }
}
