import type { SignedIdentity } from "../types";
import { ConfigurationError } from "./errors";

export interface AuthorityConfig {
  baseUrl: string;
  apiToken?: string;
}

/**
 * AuthorityClient - Interacts with the central Identity Authority
 */
export class AuthorityClient {
  constructor(private readonly config: AuthorityConfig) {
    if (!config.baseUrl) {
      throw new ConfigurationError("Authority baseUrl is required");
    }
  }

  /**
   * Request a signed identity document (certificate) from the CA
   */
  async requestIdentity(
    serviceName: string, 
    publicKeySpkiB64: string
  ): Promise<SignedIdentity> {
    const response = await fetch(`${this.config.baseUrl}/issue`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...(this.config.apiToken ? { "Authorization": `Bearer ${this.config.apiToken}` } : {})
      },
      body: JSON.stringify({
        service: serviceName,
        publicKey: publicKeySpkiB64
      })
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Failed to request identity from CA: ${response.status} ${errorText}`);
    }

    return response.json();
  }
}
