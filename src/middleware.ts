import { Request, Response, NextFunction } from 'express';
import { verifyToken, VerifyOptions } from './verifier';
import { TokenExpiredError, InvalidTokenError, NoSecretError } from './errors';
import { JwtPayload } from './types';

declare global {
  namespace Express {
    interface Request {
      user?: JwtPayload;
    }
  }
}

function extractBearerToken(req: Request): string | null {
  const authHeader = req.header('authorization') || req.header('Authorization');

  if (!authHeader) {
    return null;
  }

  const parts = authHeader.split(' ');
  if (parts.length !== 2 || parts[0].toLowerCase() !== 'bearer') {
    return null;
  }

  return parts[1];
}

export function protect(options?: VerifyOptions) {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const token = extractBearerToken(req);

      if (!token) {
        res.status(401).json({ error: 'No authentication token provided' });
        return;
      }

      const verifyOpts: VerifyOptions = {
        ...options,
        expectedType: options?.expectedType || 'access',
      };

      const decoded = await verifyToken(token, verifyOpts);

      req.user = decoded;

      next();
    } catch (error) {
      if (error instanceof TokenExpiredError) {
        res.status(401).json({ error: 'Token has expired' });
        return;
      }

      if (error instanceof InvalidTokenError) {
        if (error.message.includes('type mismatch')) {
          res.status(401).json({ error: 'Invalid token type' });
        } else {
          res.status(401).json({ error: 'Invalid or malformed token' });
        }
        return;
      }

      if (error instanceof NoSecretError) {
        res.status(401).json({ error: 'Authentication configuration error' });
        return;
      }

      res.status(401).json({ error: 'Authentication failed' });
    }
  };
}
