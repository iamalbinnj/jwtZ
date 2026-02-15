export type TokenType = "access" | "refresh";

export interface BaseClaims {
  sub: string;
  jti: string;
  typ: TokenType;
}
