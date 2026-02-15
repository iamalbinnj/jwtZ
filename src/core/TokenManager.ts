import jwt, { JwtPayload, SignOptions, VerifyOptions } from "jsonwebtoken";
import { JwtConfig } from "./JwtConfig";
import { BaseClaims } from "./Claims";
import { generateId } from "../utils/id";
import { RefreshTokenStore } from "../contracts/RefreshTokenStore";
import { TokenError } from "../errors/TokenError";
import { ReuseDetectedError } from "../errors/ReuseDetectedError";

export class TokenManager {
  private config: Required<
    Pick<JwtConfig, "accessSecret" | "refreshSecret">
  > &
    Omit<JwtConfig, "accessSecret" | "refreshSecret">;

  private store?: RefreshTokenStore;

  constructor(config: JwtConfig, store?: RefreshTokenStore) {
    if (!config.accessSecret || !config.refreshSecret) {
      throw new Error("Both accessSecret and refreshSecret are required.");
    }

    this.config = {
      accessExpiresIn: "15m",
      refreshExpiresIn: "7d",
      ...config,
      accessSecret: config.accessSecret,
      refreshSecret: config.refreshSecret,
    };

    this.store = store;
  }

  // ---------- INTERNAL HELPERS ----------

  private buildSignOptions(expiresIn?: SignOptions["expiresIn"]): SignOptions {
    const options: SignOptions = {};

    if (expiresIn) options.expiresIn = expiresIn;
    if (typeof this.config.issuer === "string")
      options.issuer = this.config.issuer;
    if (typeof this.config.audience === "string")
      options.audience = this.config.audience;

    return options;
  }

  private buildVerifyOptions(): VerifyOptions {
    const options: VerifyOptions = {};

    if (typeof this.config.issuer === "string")
      options.issuer = this.config.issuer;
    if (typeof this.config.audience === "string")
      options.audience = this.config.audience;

    return options;
  }

  // ---------- ACCESS TOKEN ----------

  public generateAccessToken(
    userId: string,
    extraPayload: Record<string, any> = {}
  ) {
    const jti = generateId();
    const { exp, iat, nbf, jti: _jti, sub: _sub, typ: _typ, ...cleanPayload } = extraPayload;

    const token = jwt.sign(
      {
        ...cleanPayload,
        sub: userId,
        jti,
        typ: "access",
      },
      this.config.accessSecret,
      this.buildSignOptions(this.config.accessExpiresIn)
    );

    return { token, jti };
  }

  public verifyAccessToken(token: string): JwtPayload & BaseClaims {
    const decoded = jwt.verify(
      token,
      this.config.accessSecret,
      this.buildVerifyOptions()
    ) as JwtPayload & BaseClaims;

    if (decoded.typ !== "access") {
      throw new TokenError("Invalid token type");
    }

    return decoded;
  }

  // ---------- REFRESH TOKEN ----------

  public async generateRefreshToken(userId: string) {
    const jti = generateId();

    const token = jwt.sign(
      {
        sub: userId,
        jti,
        typ: "refresh",
      },
      this.config.refreshSecret,
      this.buildSignOptions(this.config.refreshExpiresIn)
    );

    if (this.store) {
      const expiresAt =
        typeof this.config.refreshExpiresIn === "string"
          ? new Date(Date.now() + this.parseExpiry(this.config.refreshExpiresIn))
          : new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // fallback

      await this.store.save({
        userId,
        jti,
        revoked: false,
        expiresAt,
      });
    }

    return { token, jti };
  }

  public verifyRefreshToken(token: string): JwtPayload & BaseClaims {
    const decoded = jwt.verify(
      token,
      this.config.refreshSecret,
      this.buildVerifyOptions()
    ) as JwtPayload & BaseClaims;

    if (decoded.typ !== "refresh") {
      throw new TokenError("Invalid token type");
    }

    return decoded;
  }

  // ---------- ROTATION ----------

  public async rotateRefreshToken(oldToken: string) {
    if (!this.store) {
      throw new Error("RefreshTokenStore not configured.");
    }

    const decoded = this.verifyRefreshToken(oldToken);
    const record = await this.store.find(decoded.jti);

    if (!record || record.revoked) {
      await this.store.revokeAllByUser(decoded.sub);
      throw new ReuseDetectedError();
    }

    await this.store.revoke(decoded.jti);

    return this.generateRefreshToken(decoded.sub);
  }

  // ---------- EXPIRY PARSER ----------

  private parseExpiry(exp: string): number {
    const match = exp.match(/^(\d+)([smhd])$/);
    if (!match) return 7 * 24 * 60 * 60 * 1000;

    const value = parseInt(match[1], 10);
    const unit = match[2];

    const multipliers: Record<string, number> = {
      s: 1000,
      m: 60 * 1000,
      h: 60 * 60 * 1000,
      d: 24 * 60 * 60 * 1000,
    };

    return value * multipliers[unit];
  }
}
