# jwtz 🛡️

**A Simple, Secure, and Type-Safe JWT Management Library for Node.js.**

[![npm version](https://img.shields.io/npm/v/jwtz.svg?style=flat-square)](https://www.npmjs.com/package/jwtz)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](https://opensource.org/licenses/MIT)

`jwtz` simplifies high-level JWT operations like access token generation, refresh token management, and secure token rotation with built-in reuse detection.

---

## ✨ Features

- 🔑 **Simple API**: Easy-to-use methods for token management.
- 🔄 **Refresh Token Rotation**: Built-in support for secure token rotation.
- 🛡️ **Reuse Detection**: Automatically detects and handles refresh token reuse attempts (securing against stolen tokens).
- 🏷️ **Type-Safe**: Full TypeScript support with custom claim definitions.
- 📦 **Pluggable Storage**: Use any database or cache (Redis, MongoDB, etc.) for refresh tokens.

---

## 🚀 Installation

```bash
npm install jwtz
```

---

## 🛠️ Quick Start

### 1. Basic Setup

```typescript
import { TokenManager } from 'jwtz';

const tokenManager = new TokenManager({
  accessSecret: 'your-access-secret',
  refreshSecret: 'your-refresh-secret',
  accessExpiresIn: '15m',
  refreshExpiresIn: '7d',
  issuer: 'your-app-name',
});
```

### 2. Generate and Verify Access Tokens

```typescript
// Generate
const { token, jti } = tokenManager.generateAccessToken('user-123', { role: 'admin' });

// Verify
try {
  const payload = tokenManager.verifyAccessToken(token);
  console.log(payload.sub); // 'user-123'
} catch (err) {
  console.error('Invalid token');
}
```

---

## 🔄 Advanced Usage: Refresh Token Rotation

To use refresh tokens with rotation and security, implement the `RefreshTokenStore` interface.

### Implement a Store

```typescript
import { RefreshTokenStore } from 'jwtz';

const myStore: RefreshTokenStore = {
  async save(record) { /* Save to DB */ },
  async find(jti) { /* Find in DB */ },
  async revoke(jti) { /* Mark as revoked */ },
  async revokeAllByUser(userId) { /* Revoke all tokens for user */ }
};

const tokenManager = new TokenManager(config, myStore);
```

### Rotating a Token

When a user requests a new access token using their refresh token:

```typescript
try {
  const { token, jti } = await tokenManager.rotateRefreshToken(oldRefreshToken);
  // Send new token pair to client
} catch (err) {
  if (err instanceof ReuseDetectedError) {
    // SECURITY ALERT: Someone tried to reuse an old refresh token!
    // All tokens for this user have been revoked automatically.
  }
}
```

---

## 📖 API Reference

### `TokenManager`

| Method | Description |
| :--- | :--- |
| `generateAccessToken(userId, payload?)` | Creates a new access token. |
| `verifyAccessToken(token)` | Verifies and decodes an access token. |
| `generateRefreshToken(userId)` | Creates a new refresh token and saves it to the store. |
| `verifyRefreshToken(token)` | Verifies and decodes a refresh token. |
| `rotateRefreshToken(oldToken)` | Revokes the old token and issues a new one. |

---

## 🔒 Security

- **Secrets**: Never commit your `accessSecret` or `refreshSecret` to version control.
- **Rotation**: Always use `rotateRefreshToken` to minimize the window of opportunity for stolen tokens.
- **Reuse Detection**: If `jwtz` detects a reuse, it immediately revokes all family members of that token, protecting the user account.

---

## 🤝 Contributing

Contributions are welcome! Please read our [Code of Conduct](CODE_OF_CONDUCT.md) before contributing.

## 🛡️ Security

If you find a security vulnerability, please refer to our [Security Policy](SECURITY.md).

## 📄 License

[MIT](LICENSE) © Albin N J
