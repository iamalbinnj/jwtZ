import { TokenManager } from "../../../src/core/TokenManager";
import { RefreshTokenStore } from "../../../src/contracts/RefreshTokenStore";
import jwt from "jsonwebtoken";

describe("TokenManager.generateRefreshToken", () => {
  const config = {
    accessSecret: "access-secret",
    refreshSecret: "refresh-secret",
  };
  
  const mockStore: RefreshTokenStore = {
    save: jest.fn().mockResolvedValue(undefined),
    find: jest.fn(),
    revoke: jest.fn(),
    revokeAllByUser: jest.fn(),
  };

  it("should generate refresh token with valid userId", async () => {
    const manager = new TokenManager(config);
    const { token, jti } = await manager.generateRefreshToken("user-1");
    
    expect(token).toBeDefined();
    expect(jti).toBeDefined();
    
    const decoded = jwt.decode(token) as any;
    expect(decoded.sub).toBe("user-1");
    expect(decoded.typ).toBe("refresh");
    expect(decoded.jti).toBe(jti);
  });

  it("should save record to store if provided", async () => {
    const manager = new TokenManager(config, mockStore);
    const { jti } = await manager.generateRefreshToken("user-1");
    
    expect(mockStore.save).toHaveBeenCalledWith(expect.objectContaining({
      userId: "user-1",
      jti,
      revoked: false,
      expiresAt: expect.any(Date),
    }));
  });

  it("should calculate expiresAt correctly with default config (7d)", async () => {
    const manager = new TokenManager(config, mockStore);
    const now = Date.now();
    await manager.generateRefreshToken("user-1");
    
    const saveCall = (mockStore.save as jest.Mock).mock.calls[1][0];
    const expiresAt = saveCall.expiresAt.getTime();
    const diff = expiresAt - now;
    
    // 7 days = 604800000ms. Allow for some execution time drift (e.g., 5s)
    expect(diff).toBeGreaterThanOrEqual(604800000);
    expect(diff).toBeLessThan(604800000 + 5000);
  });

  it("should calculate expiresAt correctly with custom config (30d)", async () => {
    const manager = new TokenManager({ ...config, refreshExpiresIn: "30d" }, mockStore);
    const now = Date.now();
    await manager.generateRefreshToken("user-1");
    
    const saveCall = (mockStore.save as jest.Mock).mock.calls[2][0];
    const expiresAt = saveCall.expiresAt.getTime();
    const diff = expiresAt - now;
    
    const thirtyDays = 30 * 24 * 60 * 60 * 1000;
    expect(diff).toBeGreaterThanOrEqual(thirtyDays);
    expect(diff).toBeLessThan(thirtyDays + 5000);
  });

  it("should handle custom refreshExpiresIn like '1h'", async () => {
    const manager = new TokenManager({ ...config, refreshExpiresIn: "1h" }, mockStore);
    const now = Date.now();
    await manager.generateRefreshToken("user-1");
    
    const saveCall = (mockStore.save as jest.Mock).mock.calls[3][0];
    const diff = saveCall.expiresAt.getTime() - now;
    expect(diff).toBeGreaterThanOrEqual(3600000);
    expect(diff).toBeLessThan(3600000 + 5000);
  });

  it("should succeed even if no store is configured", async () => {
    const manager = new TokenManager(config);
    const result = await manager.generateRefreshToken("user-1");
    expect(result.token).toBeDefined();
  });

  it("should propagate store errors", async () => {
    const errorStore = { ...mockStore, save: jest.fn().mockRejectedValue(new Error("Storage failed")) };
    const manager = new TokenManager(config, errorStore);
    await expect(manager.generateRefreshToken("user-1")).rejects.toThrow("Storage failed");
  });
});
