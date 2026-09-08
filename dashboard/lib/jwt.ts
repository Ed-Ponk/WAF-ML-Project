/**
 * ══════════════════════════════════════════════════════════════════
 * JWT Secret — Single source of truth
 *
 * Centralises JWT_SECRET resolution for all runtimes (Edge, Node.js).
 * LAZY: reads process.env.JWT_SECRET only when a token must be signed
 * or verified (request time), so `next build` never needs the variable.
 * FAILS CLOSED: throws at request time when the variable is missing.
 * There is no fallback, no default, and no baked-in value — the secret
 * exists only as a runtime environment variable (see docker-compose.yml).
 * ══════════════════════════════════════════════════════════════════
 */

export function getJwtSecret(): string {
  const secret = process.env.JWT_SECRET;
  if (!secret) {
    throw new Error(
      "JWT_SECRET environment variable is not set. " +
      "Generate one with: node -e \"console.log(require('crypto').randomBytes(32).toString('hex'))\""
    );
  }
  return secret;
}