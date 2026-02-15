import { TokenManager } from "../../../src/core/TokenManager";
import jwt from "jsonwebtoken";

describe("TokenManager.generateAccessToken", () => {
  const config = {
    accessSecret: "access-secret",
    refreshSecret: "refresh-secret",
    issuer: "test-issuer",
    audience: "test-audience",
  };
  const manager = new TokenManager(config);

  it("should generate token with valid userId", () => {
    const { token, jti } = manager.generateAccessToken("user-123");
    expect(token).toBeDefined();
    expect(jti).toBeDefined();
    
    const decoded = jwt.decode(token) as any;
    expect(decoded.sub).toBe("user-123");
    expect(decoded.typ).toBe("access");
    expect(decoded.jti).toBe(jti);
  });

  it("should handle empty string userId", () => {
    const { token } = manager.generateAccessToken("");
    const decoded = jwt.decode(token) as any;
    expect(decoded.sub).toBe("");
  });

  it("should handle special characters in userId", () => {
    const userId = "user!@#$%^&*()_+";
    const { token } = manager.generateAccessToken(userId);
    const decoded = jwt.decode(token) as any;
    expect(decoded.sub).toBe(userId);
  });

  it("should handle very long userId", () => {
    const userId = "a".repeat(1001);
    const { token } = manager.generateAccessToken(userId);
    const decoded = jwt.decode(token) as any;
    expect(decoded.sub).toBe(userId);
  });

  it("should include extra payload properties", () => {
    const extra = { role: "admin", scope: ["read", "write"], nested: { key: "value" } };
    const { token } = manager.generateAccessToken("user-1", extra);
    const decoded = jwt.decode(token) as any;
    expect(decoded.role).toBe("admin");
    expect(decoded.scope).toEqual(["read", "write"]);
    expect(decoded.nested.key).toBe("value");
  });

  it("original userId should take precedence over extra sub property", () => {
    const { token } = manager.generateAccessToken("real-user", { sub: "fake-user" });
    const decoded = jwt.decode(token) as any;
    expect(decoded.sub).toBe("real-user");
  });

  it("generated jti should take precedence over extra jti property", () => {
    const { token, jti } = manager.generateAccessToken("user-1", { jti: "custom-jti" });
    const decoded = jwt.decode(token) as any;
    expect(decoded.jti).toBe(jti);
    expect(decoded.jti).not.toBe("custom-jti");
  });

  it("typ 'access' should take precedence over extra typ property", () => {
    const { token } = manager.generateAccessToken("user-1", { typ: "refresh" });
    const decoded = jwt.decode(token) as any;
    expect(decoded.typ).toBe("access");
  });

  it("should include issuer and audience when configured", () => {
    const { token } = manager.generateAccessToken("user-1");
    const decoded = jwt.decode(token) as any;
    expect(decoded.iss).toBe(config.issuer);
    expect(decoded.aud).toBe(config.audience);
  });

  it("token should have correct iat and exp", () => {
    const { token } = manager.generateAccessToken("user-1");
    const decoded = jwt.decode(token) as any;
    expect(decoded.iat).toBeDefined();
    expect(decoded.exp).toBeDefined();
    // Default 15m = 900s
    expect(decoded.exp - decoded.iat).toBe(900);
  });

  it("should generate unique jti across multiple calls", () => {
    const { jti: jti1 } = manager.generateAccessToken("user-1");
    const { jti: jti2 } = manager.generateAccessToken("user-1");
    expect(jti1).not.toBe(jti2);
  });

  it("should handle null/undefined userId", () => {
    // Current implementation doesn't throw, just passes it to jwt.sign
    const { token: t1 } = manager.generateAccessToken(null as any);
    expect((jwt.decode(t1) as any).sub).toBe(null);

    const { token: t2 } = manager.generateAccessToken(undefined as any);
    expect((jwt.decode(t2) as any).sub).toBe(undefined);
  });

  it("reserved JWT claims in extraPayload should not overwrite required claims", () => {
    const extra = { exp: 9999999999, iat: 1, nbf: 1 };
    const { token } = manager.generateAccessToken("user-1", extra);
    const decoded = jwt.decode(token) as any;
    
    // exp and iat are overwritten by buildSignOptions/jwt.sign logic
    expect(decoded.exp).not.toBe(extra.exp);
    expect(decoded.iat).not.toBe(extra.iat);
  });

  it("should work with numeric userId", () => {
    const { token } = manager.generateAccessToken(123 as any);
    const decoded = jwt.decode(token) as any;
    expect(decoded.sub).toBe(123);
  });

  it("should handle circular references in extra payload (should fail serialization)", () => {
    const circular: any = {};
    circular.self = circular;
    expect(() => manager.generateAccessToken("user-1", circular)).toThrow();
  });
});
