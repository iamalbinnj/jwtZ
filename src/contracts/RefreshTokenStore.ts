export interface RefreshTokenRecord {
  userId: string;
  jti: string;
  revoked: boolean;
  expiresAt: Date;
}

export interface RefreshTokenStore {
  save(record: RefreshTokenRecord): Promise<void>;
  find(jti: string): Promise<RefreshTokenRecord | null>;
  revoke(jti: string): Promise<void>;
  revokeAllByUser(userId: string): Promise<void>;
}
