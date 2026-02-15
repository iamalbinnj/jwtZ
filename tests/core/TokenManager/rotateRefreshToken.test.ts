import { TokenManager } from "../../../src/core/TokenManager";
import { RefreshTokenStore } from "../../../src/contracts/RefreshTokenStore";
import { ReuseDetectedError } from "../../../src/errors/ReuseDetectedError";
import jwt from "jsonwebtoken";

describe("TokenManager.rotateRefreshToken", () => {
  const config = {
    accessSecret: "access-secret",
    refreshSecret: "refresh-secret",
  };

  const createMockStore = () => ({
    save: jest.fn().mockResolvedValue(undefined),
    find: jest.fn(),
    revoke: jest.fn().mockResolvedValue(undefined),
    revokeAllByUser: jest.fn().mockResolvedValue(undefined),
  });

  it("should rotate valid refresh token succeeds", async () => {
    const mockStore = createMockStore();
    const manager = new TokenManager(config, mockStore);
    
    const { token: oldToken, jti: oldJti } = await manager.generateRefreshToken("user-1");
    
    mockStore.find.mockResolvedValue({
      userId: "user-1",
      jti: oldJti,
      revoked: false,
      expiresAt: new Date(Date.now() + 10000),
    });

    const { token: newToken, jti: newJti } = await manager.rotateRefreshToken(oldToken);

    expect(newToken).toBeDefined();
    expect(newJti).not.toBe(oldJti);
    expect(mockStore.revoke).toHaveBeenCalledWith(oldJti);
    expect(mockStore.save).toHaveBeenCalledWith(expect.objectContaining({ jti: newJti }));
  });

  it("should throw ReuseDetectedError and revoke all user tokens if token is already revoked", async () => {
    const mockStore = createMockStore();
    const manager = new TokenManager(config, mockStore);
    
    const { token, jti } = await manager.generateRefreshToken("user-1");
    
    mockStore.find.mockResolvedValue({
      userId: "user-1",
      jti,
      revoked: true,
      expiresAt: new Date(Date.now() + 10000),
    });

    await expect(manager.rotateRefreshToken(token)).rejects.toThrow(ReuseDetectedError);
    expect(mockStore.revokeAllByUser).toHaveBeenCalledWith("user-1");
  });

  it("should throw ReuseDetectedError and revoke all user tokens if record not found", async () => {
    const mockStore = createMockStore();
    const manager = new TokenManager(config, mockStore);
    
    const { token } = await manager.generateRefreshToken("user-1");
    
    mockStore.find.mockResolvedValue(null);

    await expect(manager.rotateRefreshToken(token)).rejects.toThrow(ReuseDetectedError);
    expect(mockStore.revokeAllByUser).toHaveBeenCalledWith("user-1");
  });

  it("should throw error if store is not configured", async () => {
    const manager = new TokenManager(config);
    const { token } = await manager.generateRefreshToken("user-1");
    
    await expect(manager.rotateRefreshToken(token)).rejects.toThrow("RefreshTokenStore not configured.");
  });

  it("should fail if token is invalid signature", async () => {
    const mockStore = createMockStore();
    const manager = new TokenManager(config, mockStore);
    
    await expect(manager.rotateRefreshToken("invalid.token.string")).rejects.toThrow();
  });

  it("should fail if token is expired", async () => {
    const mockStore = createMockStore();
    const manager = new TokenManager(config, mockStore);
    
    const expiredToken = jwt.sign(
      { sub: "user-1", typ: "refresh", jti: "123", exp: Math.floor(Date.now() / 1000) - 100 },
      config.refreshSecret
    );

    await expect(manager.rotateRefreshToken(expiredToken)).rejects.toThrow();
  });

  it("should fail if access token is provided instead of refresh token", async () => {
    const mockStore = createMockStore();
    const manager = new TokenManager(config, mockStore);
    
    const { token } = manager.generateAccessToken("user-1");

    await expect(manager.rotateRefreshToken(token)).rejects.toThrow();
  });
});
