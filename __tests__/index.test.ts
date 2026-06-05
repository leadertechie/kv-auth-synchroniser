import { describe, it, expect, beforeAll } from "vitest";
import { KVAuth, generateKeypair, signRequest, verifyRequest, verifyIncomingRequest } from "../src/index";

class MockKV {
  private store = new Map<string, string>();
  async get(key: string) { return this.store.get(key) ?? null; }
  async put(key: string, value: string) { this.store.set(key, value); }
  async delete(key: string) { this.store.delete(key); }
  async list() { return { keys: [] }; }
  getWithMetadata() { return Promise.resolve({ value: null, metadata: null }); }
}

describe("KVAuth", () => {
  let authA: KVAuth;
  let authB: KVAuth;
  let kv: KVNamespace;

  beforeAll(async () => {
    kv = new MockKV() as unknown as KVNamespace;
    const kpA = await generateKeypair();
    const kpB = await generateKeypair();

    authA = new KVAuth({ privateKey: kpA.privateKey, serviceName: "service-a", kv });
    await authA.init();
    await authA.publishPublicKey();

    authB = new KVAuth({ privateKey: kpB.privateKey, serviceName: "service-b", kv });
    await authB.init();
    await authB.publishPublicKey();
  });

  it("generates keys and publishes public keys to KV", async () => {
    const pubA = await kv.get("pubkeys/service-a");
    expect(pubA).toBeTruthy();
    const parsedA = JSON.parse(pubA!);
    expect(parsedA.document.algorithm).toBe("Ed25519");
    expect(parsedA.document.publicKey).toBeTruthy();
    expect(parsedA.signature).toBeDefined();
  });

  it("signs a GET request and verifies it correctly", async () => {
    const headers = await authA.signRequest("GET", "/api/test");
    const request = new Request("http://localhost/api/test", {
      headers: headers as unknown as Record<string, string>,
    });
    const result = await authB.verifyRequest(request);
    expect(result.valid).toBe(true);
    expect(result.caller).toBe("service-a");
  });

  it("signs a POST request with body and verifies it", async () => {
    const body = JSON.stringify({ name: "test" });
    const headers = await authA.signRequest("POST", "/api/register", { body });
    const request = new Request("http://localhost/api/register", {
      method: "POST",
      headers: { "Content-Type": "application/json", ...headers } as Record<string, string>,
      body,
    });
    const result = await authB.verifyRequest(request);
    expect(result.valid).toBe(true);
  });

  it("passes user email through X-Toldby-Auth", async () => {
    const headers = await authA.signRequest("GET", "/api/admin", { userEmail: "admin@toldby.com" });
    expect(headers["X-Toldby-Auth"]).toBe("admin@toldby.com");
    const request = new Request("http://localhost/api/admin", {
      headers: headers as unknown as Record<string, string>,
    });
    const result = await authB.verifyRequest(request);
    expect(result.valid).toBe(true);
    expect(result.userEmail).toBe("admin@toldby.com");
  });

  it("rejects a request with wrong signature", async () => {
    const headers = await authA.signRequest("GET", "/api/test");
    const tampered = new Request("http://localhost/api/test", {
      headers: { ...headers, "X-Toldby-Signature": "AAAA" + headers["X-Toldby-Signature"].slice(4) } as Record<string, string>,
    });
    const result = await authB.verifyRequest(tampered);
    expect(result.valid).toBe(false);
  });

  it("rejects when body hash doesn't match (tampered body)", async () => {
    const body = JSON.stringify({ name: "original" });
    const headers = await authA.signRequest("POST", "/api/data", { body });
    const tamperedBody = JSON.stringify({ name: "tampered" });
    const request = new Request("http://localhost/api/data", {
      method: "POST",
      headers: headers as unknown as Record<string, string>,
      body: tamperedBody,
    });
    const result = await authB.verifyRequest(request);
    expect(result.valid).toBe(false);
  });

  it("rejects a request from an unknown service", async () => {
    const kp = await generateKeypair();
    const sigResult = await signRequest(kp.privateKey, "GET", "/api/unknown", {});
    const request = new Request("http://localhost/api/unknown", {
      headers: {
        "X-Toldby-Signature": sigResult.signature,
        "X-Toldby-Caller": "unknown-service",
        "X-Toldby-Timestamp": String(Date.now()),
      },
    });
    const result = await verifyIncomingRequest(request, kv);
    expect(result.valid).toBe(false);
  });

  it("rejects a request with missing headers", async () => {
    const request = new Request("http://localhost/api/noauth");
    const result = await verifyIncomingRequest(request, kv);
    expect(result.valid).toBe(false);
    expect(result.caller).toBeNull();
  });

  it("uses UTC epoch timestamps (Date.now) in X-Toldby-Timestamp", async () => {
    const headers = await authA.signRequest("GET", "/api/test");
    const ts = parseInt(headers["X-Toldby-Timestamp"], 10);
    expect(typeof ts).toBe("number");
    expect(ts).toBeGreaterThan(1700000000000); // well into 2023+
    expect(ts).toBeLessThan(2000000000000);    // before 2033
    expect(new Date(ts).toISOString()).toMatch(/^202[4567]/); // roughly correct year
  });

  it("allows explicit UTC timestamp override on KVAuth.signRequest", async () => {
    // The functional signRequest now passes timestamp through correctly
    const kp = await generateKeypair();
    const auth = new KVAuth({ privateKey: kp.privateKey, serviceName: "ts-test", kv: new MockKV() as unknown as KVNamespace });
    await auth.init();
    await auth.publishPublicKey();

    // Sign with an explicit timestamp
    const explicitTs = Date.now() - 10000; // 10 seconds ago — within TTL
    const headers = await auth.signRequest("POST", "/api/data", { body: "test", timestamp: explicitTs });
    expect(headers["X-Toldby-Timestamp"]).toBe(String(explicitTs));

    // Verify using the same headers (includes the explicit timestamp)
    const request = new Request("http://localhost/api/data", {
      method: "POST",
      headers: headers as Record<string, string>,
      body: "test",
    });
    const result = await auth.verifyRequest(request);
    expect(result.valid).toBe(true);
    expect(result.caller).toBe("ts-test");
  });

  it("generates unique keypairs each time", async () => {
    const kp1 = await generateKeypair();
    const kp2 = await generateKeypair();
    expect(kp1.privateKey).not.toBe(kp2.privateKey);
    expect(kp1.publicKey.raw).not.toBe(kp2.publicKey.raw);
  });

  describe("Security Enhancements", () => {
    it("successfully verifies if query params are included in both signRequest and the request URL", async () => {
      const pathWithQuery = "/api/test?foo=bar";
      const headers = await authA.signRequest("GET", pathWithQuery);
      
      const request = new Request("http://localhost" + pathWithQuery, {
        headers: headers as unknown as Record<string, string>,
      });

      const result = await authB.verifyRequest(request);
      expect(result.valid).toBe(true);
    });

    it("fails to verify if query params are added to the URL but were NOT signed", async () => {
      const path = "/api/test";
      const headers = await authA.signRequest("GET", path);
      
      const request = new Request("http://localhost" + path + "?foo=bar", {
        headers: headers as unknown as Record<string, string>,
      });

      const result = await authB.verifyRequest(request);
      expect(result.valid).toBe(false);
    });

    it("rejects request if X-Toldby-Auth (userEmail) is tampered with", async () => {
      const headers = await authA.signRequest("GET", "/api/admin", { userEmail: "user@example.com" });
      const tamperedHeaders = { ...headers, "X-Toldby-Auth": "attacker@example.com" };
      const request = new Request("http://localhost/api/admin", {
        headers: tamperedHeaders as Record<string, string>,
      });
      const result = await authB.verifyRequest(request);
      expect(result.valid).toBe(false);
    });

    it("rejects request if X-Toldby-Caller is tampered with", async () => {
      const headers = await authA.signRequest("GET", "/api/data");
      const tamperedHeaders = { ...headers, "X-Toldby-Caller": "service-b" };
      const request = new Request("http://localhost/api/data", {
        headers: tamperedHeaders as Record<string, string>,
      });
      const result = await authB.verifyRequest(request);
      expect(result.valid).toBe(false);
    });
  });
});
