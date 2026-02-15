import { TokenManager } from "../../../src/core/TokenManager";
import { TokenError } from "../../../src/errors/TokenError";
import jwt from "jsonwebtoken";

describe("TokenManager.verifyAccessToken", () => {
  const config = {
    accessSecret: "access-secret",
    refreshSecret: "refresh-secret",
  };
  const manager = new TokenManager(config);

  it("should verify valid access token succeeds", () => {
    const { token } = manager.generateAccessToken("user-1");
    const decoded = manager.verifyAccessToken(token);
    expect(decoded.sub).toBe("user-1");
    expect(decoded.typ).toBe("access");
  });

  it("should throw TokenError for wrong type (refresh)", () => {
    const token = jwt.sign(
      { sub: "user-1", typ: "refresh", jti: "123" },
      config.accessSecret
    );
    expect(() => manager.verifyAccessToken(token)).toThrow(TokenError);
    expect(() => manager.verifyAccessToken(token)).toThrow("Invalid token type");
  });

  it("should fail for malformed token", () => {
    expect(() => manager.verifyAccessToken("not-a-token")).toThrow();
  });

  it("should fail for token with tampered signature", () => {
    const { token } = manager.generateAccessToken("user-1");
    const tampered = token.substring(0, token.lastIndexOf(".") + 1) + "tampered";
    expect(() => manager.verifyAccessToken(tampered)).toThrow();
  });

  it("should fail for token with wrong secret", () => {
    const token = jwt.sign(
      { sub: "user-1", typ: "access", jti: "123" },
      "wrong-secret"
    );
    expect(() => manager.verifyAccessToken(token)).toThrow();
  });

  it("should fail for expired token", () => {
    const token = jwt.sign(
      { sub: "user-1", typ: "access", jti: "123", exp: Math.floor(Date.now() / 1000) - 100 },
      config.accessSecret
    );
    expect(() => manager.verifyAccessToken(token)).toThrow();
  });

  it("should respect issuer and audience if configured", () => {
    const configWithIss = { ...config, issuer: "iss", audience: "aud" };
    const mgrWithIss = new TokenManager(configWithIss);
    const { token } = mgrWithIss.generateAccessToken("user-1");
    
    expect(mgrWithIss.verifyAccessToken(token).iss).toBe("iss");
    expect(mgrWithIss.verifyAccessToken(token).aud).toBe("aud");
  });

  it("should fail if issuer doesn't match", () => {
    const mgr1 = new TokenManager({ ...config, issuer: "iss1" });
    const mgr2 = new TokenManager({ ...config, issuer: "iss2" });
    const { token } = mgr1.generateAccessToken("user-1");
    
    expect(() => mgr2.verifyAccessToken(token)).toThrow();
  });

  it("should fail if audience doesn't match", () => {
    const mgr1 = new TokenManager({ ...config, audience: "aud1" });
    const mgr2 = new TokenManager({ ...config, audience: "aud2" });
    const { token } = mgr1.generateAccessToken("user-1");
    
    expect(() => mgr2.verifyAccessToken(token)).toThrow();
  });
});
