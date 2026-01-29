/**
 * Tests for standalone exported functions
 */

describe('Standalone Exports', () => {
  const SECRET = 'test-standalone-secret';
  const originalEnv = process.env;

  beforeEach(() => {
    jest.resetModules();
    process.env = { ...originalEnv, JWT_SECRET: SECRET };
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  it('should export createTokens as standalone function', () => {
    const { createTokens } = require('../src/index');
    const tokens = createTokens({ userId: 1 });

    expect(tokens).toHaveProperty('accessToken');
    expect(tokens).toHaveProperty('refreshToken');
  });

  it('should export verifyToken as standalone function', async () => {
    const { createTokens, verifyToken } = require('../src/index');
    const tokens = createTokens({ userId: 2 });

    const decoded = await verifyToken(tokens.accessToken);
    expect(decoded.userId).toBe(2);
  });

  it('should export protect as standalone function', async () => {
    const { createTokens, protect } = require('../src/index');
    const tokens = createTokens({ userId: 3 });

    const middleware = protect();
    const req: any = {
      headers: { authorization: `Bearer ${tokens.accessToken}` },
      header: function (name: string) {
        return this.headers[name.toLowerCase()];
      },
    };
    const res: any = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn().mockReturnThis(),
    };
    const next = jest.fn();

    await middleware(req, res, next);

    expect(req.user.userId).toBe(3);
    expect(next).toHaveBeenCalled();
  });

  it('should export all error classes', () => {
    const { TokenExpiredError, InvalidTokenError, NoSecretError } = require('../src/index');

    expect(TokenExpiredError).toBeDefined();
    expect(InvalidTokenError).toBeDefined();
    expect(NoSecretError).toBeDefined();
  });

  it('should export all types', () => {
    const index = require('../src/index');

    // Types are erased at runtime but we can check the module exports them
    expect(index.useJwt).toBeDefined();
  });

  it('should export config utilities', () => {
    const { DEFAULTS, resolveSecret, mergeOptions } = require('../src/index');

    expect(DEFAULTS).toBeDefined();
    expect(resolveSecret).toBeDefined();
    expect(mergeOptions).toBeDefined();
    expect(DEFAULTS.algorithm).toBe('HS256');
  });
});
