/**
 * RED Phase: Error Classes Tests
 * These tests will fail until we implement src/errors.ts
 */

describe('Error Classes', () => {
  describe('TokenExpiredError', () => {
    it('should extend Error', () => {
      // This will fail - TokenExpiredError not yet imported
      const { TokenExpiredError } = require('../src/errors');
      const error = new TokenExpiredError('Token has expired');

      expect(error).toBeInstanceOf(Error);
      expect(error).toBeInstanceOf(TokenExpiredError);
    });

    it('should have correct name', () => {
      const { TokenExpiredError } = require('../src/errors');
      const error = new TokenExpiredError('Token has expired');

      expect(error.name).toBe('TokenExpiredError');
    });

    it('should have correct message', () => {
      const { TokenExpiredError } = require('../src/errors');
      const error = new TokenExpiredError('Custom expired message');

      expect(error.message).toBe('Custom expired message');
    });

    it('should have stack trace', () => {
      const { TokenExpiredError } = require('../src/errors');
      const error = new TokenExpiredError('Token has expired');

      expect(error.stack).toBeDefined();
      expect(error.stack).toContain('TokenExpiredError');
    });
  });

  describe('InvalidTokenError', () => {
    it('should extend Error', () => {
      const { InvalidTokenError } = require('../src/errors');
      const error = new InvalidTokenError('Invalid token');

      expect(error).toBeInstanceOf(Error);
      expect(error).toBeInstanceOf(InvalidTokenError);
    });

    it('should have correct name', () => {
      const { InvalidTokenError } = require('../src/errors');
      const error = new InvalidTokenError('Invalid token');

      expect(error.name).toBe('InvalidTokenError');
    });

    it('should have correct message', () => {
      const { InvalidTokenError } = require('../src/errors');
      const error = new InvalidTokenError('Custom invalid message');

      expect(error.message).toBe('Custom invalid message');
    });

    it('should have stack trace', () => {
      const { InvalidTokenError } = require('../src/errors');
      const error = new InvalidTokenError('Invalid token');

      expect(error.stack).toBeDefined();
      expect(error.stack).toContain('InvalidTokenError');
    });
  });

  describe('NoSecretError', () => {
    it('should extend Error', () => {
      const { NoSecretError } = require('../src/errors');
      const error = new NoSecretError('No secret provided');

      expect(error).toBeInstanceOf(Error);
      expect(error).toBeInstanceOf(NoSecretError);
    });

    it('should have correct name', () => {
      const { NoSecretError } = require('../src/errors');
      const error = new NoSecretError('No secret provided');

      expect(error.name).toBe('NoSecretError');
    });

    it('should have correct message', () => {
      const { NoSecretError } = require('../src/errors');
      const error = new NoSecretError('Custom no secret message');

      expect(error.message).toBe('Custom no secret message');
    });

    it('should have stack trace', () => {
      const { NoSecretError } = require('../src/errors');
      const error = new NoSecretError('No secret provided');

      expect(error.stack).toBeDefined();
      expect(error.stack).toContain('NoSecretError');
    });
  });

  describe('Error distinguishability', () => {
    it('should be distinguishable from each other', () => {
      const { TokenExpiredError, InvalidTokenError, NoSecretError } = require('../src/errors');

      const expiredError = new TokenExpiredError('expired');
      const invalidError = new InvalidTokenError('invalid');
      const noSecretError = new NoSecretError('no secret');

      expect(expiredError).toBeInstanceOf(TokenExpiredError);
      expect(expiredError).not.toBeInstanceOf(InvalidTokenError);
      expect(expiredError).not.toBeInstanceOf(NoSecretError);

      expect(invalidError).toBeInstanceOf(InvalidTokenError);
      expect(invalidError).not.toBeInstanceOf(TokenExpiredError);
      expect(invalidError).not.toBeInstanceOf(NoSecretError);

      expect(noSecretError).toBeInstanceOf(NoSecretError);
      expect(noSecretError).not.toBeInstanceOf(TokenExpiredError);
      expect(noSecretError).not.toBeInstanceOf(InvalidTokenError);
    });
  });
});
