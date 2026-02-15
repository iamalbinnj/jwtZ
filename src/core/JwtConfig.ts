import { SignOptions } from "jsonwebtoken";

export interface JwtConfig {
  accessSecret: string;
  refreshSecret: string;
  accessExpiresIn?: SignOptions["expiresIn"];
  refreshExpiresIn?: SignOptions["expiresIn"];
  issuer?: string;
  audience?: string;
}
