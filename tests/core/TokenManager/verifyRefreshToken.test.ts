import { TokenManager } from "../../../src/core/TokenManager";
import { TokenError } from "../../../src/errors/TokenError";
import jwt from "jsonwebtoken";

describe("TokenManager.verifyRefreshToken", () => {
  const config = {
    accessSecret: "access-secret",
    refreshSecret: "refresh-secret",
  };
  const manager = new TokenManager(config);

  it("should verify valid refresh token succeeds", async () => {
    const { token } = await manager.generateRefreshToken("user-1");
    const decoded = manager.verifyRefreshToken(token);
    expect(decoded.sub).toBe("user-1");
    expect(decoded.typ).toBe("refresh");
  });

  it("should throw TokenError for wrong type (access)", () => {
    const token = jwt.sign(
      { sub: "user-1", typ: "access", jti: "123" },
      config.refreshSecret
    );
    expect(() => manager.verifyRefreshToken(token)).toThrow(TokenError);
    expect(() => manager.verifyRefreshToken(token)).toThrow("Invalid token type");
  });

  it("should fail for malformed token", () => {
    expect(() => manager.verifyRefreshToken("not-a-token")).toThrow();
  });

  it("should fail for token with wrong secret (accessSecret)", async () => {
    const { token } = await manager.generateRefreshToken("user-1");
    // Try verifying with access secret (externally)
    expect(() => {
        jwt.verify(token, config.accessSecret);
    }).toThrow();
  });

  it("should fail for expired token", () => {
    const token = jwt.sign(
      { sub: "user-1", typ: "refresh", jti: "123", exp: Math.floor(Date.now() / 1000) - 100 },
      config.refreshSecret
    );
    expect(() => manager.verifyRefreshToken(token)).toThrow();
  });

  it("should reject access token as refresh token", () => {
    const { token } = manager.generateAccessToken("user-1");
    // This should fail because generateAccessToken uses accessSecret, 
    // and verifyRefreshToken uses refreshSecret.
    expect(() => manager.verifyRefreshToken(token)).toThrow();
  });
});
