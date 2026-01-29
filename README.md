# JWT Abstraction

Stop writing the same JWT auth code in every project.

## Install

```bash
npm install @dax-side/jwt-abstraction
```

## Use it

```typescript
import { useJwt } from '@dax-side/jwt-abstraction';

const jwt = useJwt();

// Create tokens
const tokens = jwt.create({ userId: 123, email: 'user@example.com' });

// Verify tokens
const payload = await jwt.verify(tokens.accessToken);

// Protect Express routes
app.get('/profile', jwt.protect(), (req, res) => {
  res.json({ user: req.user });
});
```

Three lines. Done.

## How it works

Set a secret in your environment:

```bash
JWT_SECRET=your-secret-here
```

Or pass it directly:

```typescript
const jwt = useJwt({ secret: 'your-secret' });
```

The package creates two tokens: an access token (15 minutes) and a refresh token (7 days). Both use HS256 signing by default.

## Better security: separate secrets

Use different secrets for access and refresh tokens:

```typescript
// In your .env file
JWT_SECRET=your-access-secret
JWT_REFRESH_SECRET=your-refresh-secret

const jwt = useJwt();
```

Why? Refresh tokens live longer. If your access secret leaks, refresh tokens stay safe.

Generate strong secrets:

```bash
node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"
```

## Use your own environment variable names

```typescript
const jwt = useJwt({
  secret: process.env.AUTH_KEY,
  refreshTokenSecret: process.env.REFRESH_KEY,
});
```

`JWT_SECRET` is just a convention. Name your variables whatever you want.

## Complete example

```typescript
import express from 'express';
import { useJwt, TokenExpiredError, InvalidTokenError } from '@dax-side/jwt-abstraction';

const app = express();
const jwt = useJwt();

app.use(express.json());

app.post('/login', (req, res) => {
  const user = { userId: 123, email: 'user@example.com' };
  const tokens = jwt.create(user);
  res.json(tokens);
});
app.get('/profile', jwt.protect(), (req, res) => {
  res.json({ user: req.user });
});

app.post('/refresh', async (req, res) => {
  try {
    const { refreshToken } = req.body;
    const newTokens = await jwt.refresh(refreshToken);
    res.json(newTokens);
  } catch (error) {
    res.status(401).json({ error: 'Invalid refresh token' });
  }
});

app.post('/logout', jwt.protect(), async (req, res) => {
  res.json({ message: 'Logged out' });
});

app.listen(3000);
```

## Error handling

Catch specific error types:

```typescript
import { TokenExpiredError, InvalidTokenError, NoSecretError } from '@dax-side/jwt-abstraction';

try {
  const payload = await jwt.verify(token);
} catch (error) {
  if (error instanceof TokenExpiredError) {
    // Token expired
  } else if (error instanceof InvalidTokenError) {
    // Token malformed or tampered with
  } else if (error instanceof NoSecretError) {
    // Secret not configured
  }
}
```

## Configuration options

```typescript
const jwt = useJwt({
  secret: 'your-secret',
  refreshTokenSecret: 'refresh-secret',
  accessTokenTTL: '30m',
  refreshTokenTTL: '14d',
  algorithm: 'HS512',
  issuer: 'myapp.com',
  audience: 'api-users',
});
```

## Issuer and audience (probably skip these)

For a single backend API, `issuer` and `audience` add complexity without real security benefit. Your secret is the security.

These matter for:
- Multiple microservices sharing secrets
- OAuth/OpenID flows
- Tokens crossing organizational boundaries

If you're building a standard web app, ignore them.

## What this package doesn't do

**Token storage**: Storing tokens (Redis, database) is your job. This package creates and verifies them.

**Token blacklisting**: When you refresh a token, the old one stays valid until expiry. If you want to invalidate tokens, build your own blacklist.

**Social login**: Use Passport or similar. This handles JWT operations only.

**Password hashing**: Use bcrypt. Different concern.

**Framework support**: Works with Express. Other frameworks might come later.

## Token invalidation example

Using Redis to track used refresh tokens:

```typescript
app.post('/refresh', async (req, res) => {
  const { refreshToken } = req.body;
  
  if (await redis.exists(`used:${refreshToken}`)) {
    return res.status(401).json({ error: 'Token already used' });
  }
  
  const newTokens = await jwt.refresh(refreshToken);
  await redis.setex(`used:${refreshToken}`, 604800, '1');
  
  res.json(newTokens);
});
```

## Standalone functions

Don't want the factory pattern? Import functions directly:

```typescript
import { createTokens, verifyToken, protect } from '@dax-side/jwt-abstraction';

const tokens = createTokens({ userId: 1 }, { secret: 'my-secret' });
const payload = await verifyToken(token, { secret: 'my-secret' });
app.get('/protected', protect({ secret: 'my-secret' }), handler);
```

## TypeScript

Written in TypeScript with strict mode. Full type definitions included.

## Testing

100% test coverage. 94 tests covering all functionality.

## Why this package exists

Writing JWT auth means:
- Importing jsonwebtoken
- Configuring algorithms and expiry times
- Creating access and refresh tokens separately
- Building Express middleware
- Handling three different error types
- Writing the same boilerplate in every project

This package does all that. You get secure defaults, TypeScript support, and Express middleware out of the box.
