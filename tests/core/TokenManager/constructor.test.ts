import { TokenManager } from "../../../src/core/TokenManager";
import { RefreshTokenStore } from "../../../src/contracts/RefreshTokenStore";

describe("TokenManager constructor", () => {
  const validConfig = {
    accessSecret: "access-secret",
    refreshSecret: "refresh-secret",
  };

  it("should succeed with valid config", () => {
    const manager = new TokenManager(validConfig);
    expect(manager).toBeInstanceOf(TokenManager);
  });

  it("should fail without accessSecret", () => {
    expect(() => new TokenManager({ refreshSecret: "r" } as any)).toThrow(
      "Both accessSecret and refreshSecret are required."
    );
  });

  it("should fail without refreshSecret", () => {
    expect(() => new TokenManager({ accessSecret: "a" } as any)).toThrow(
      "Both accessSecret and refreshSecret are required."
    );
  });

  it("should fail with null/undefined secrets", () => {
    expect(() => new TokenManager({ accessSecret: null, refreshSecret: "r" } as any)).toThrow();
    expect(() => new TokenManager({ accessSecret: "a", refreshSecret: undefined } as any)).toThrow();
  });

  it("should accept optional store", () => {
    const mockStore: RefreshTokenStore = {
      save: jest.fn(),
      find: jest.fn(),
      revoke: jest.fn(),
      revokeAllByUser: jest.fn(),
    };
    const manager = new TokenManager(validConfig, mockStore);
    expect(manager).toBeInstanceOf(TokenManager);
  });

  it("should use default expiration values if not provided", () => {
    const manager = new TokenManager(validConfig) as any;
    expect(manager.config.accessExpiresIn).toBe("15m");
    expect(manager.config.refreshExpiresIn).toBe("7d");
  });

  it("should use custom expiration values if provided", () => {
    const manager = new TokenManager({
      ...validConfig,
      accessExpiresIn: "1h",
      refreshExpiresIn: "30d",
    }) as any;
    expect(manager.config.accessExpiresIn).toBe("1h");
    expect(manager.config.refreshExpiresIn).toBe("30d");
  });

  it("should store optional issuer and audience", () => {
    const manager = new TokenManager({
      ...validConfig,
      issuer: "my-issuer",
      audience: "my-audience",
    }) as any;
    expect(manager.config.issuer).toBe("my-issuer");
    expect(manager.config.audience).toBe("my-audience");
  });

  it("should handle empty string issuer and audience", () => {
    const manager = new TokenManager({
      ...validConfig,
      issuer: "",
      audience: "",
    }) as any;
    expect(manager.config.issuer).toBe("");
    expect(manager.config.audience).toBe("");
  });
});
