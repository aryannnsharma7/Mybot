import { createPublicKey, verify as verifySignature } from 'node:crypto';

const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
const MAX_CLOCK_SKEW_SECONDS = 5 * 60;

/** Verify Telnyx API v2 webhook signature against the unmodified raw request body. */
export function verifyTelnyxWebhook({ rawBody, headers, publicKeyBase64, nowMs = Date.now() }) {
  const signatureBase64 = headers['telnyx-signature-ed25519'];
  const timestamp = headers['telnyx-timestamp'];
  if (typeof signatureBase64 !== 'string' || typeof timestamp !== 'string') return { valid: false, reason: 'Missing Telnyx signature headers.' };
  if (!/^\d{10}$/.test(timestamp)) return { valid: false, reason: 'Invalid Telnyx timestamp.' };
  const timestampSeconds = Number(timestamp);
  if (!Number.isSafeInteger(timestampSeconds) || Math.abs(Math.floor(nowMs / 1000) - timestampSeconds) > MAX_CLOCK_SKEW_SECONDS) return { valid: false, reason: 'Webhook timestamp is outside the five-minute acceptance window.' };
  const rawKey = Buffer.from(publicKeyBase64, 'base64');
  const signature = Buffer.from(signatureBase64, 'base64');
  if (rawKey.length !== 32 || signature.length !== 64) return { valid: false, reason: 'Unexpected Ed25519 key or signature length.' };
  try {
    const publicKey = createPublicKey({ key: Buffer.concat([ED25519_SPKI_PREFIX, rawKey]), format: 'der', type: 'spki' });
    const signedPayload = Buffer.concat([Buffer.from(`${timestamp}|`, 'utf8'), Buffer.isBuffer(rawBody) ? rawBody : Buffer.from(rawBody, 'utf8')]);
    const valid = verifySignature(null, signedPayload, publicKey, signature);
    return { valid, reason: valid ? null : 'Webhook signature verification failed.' };
  } catch {
    return { valid: false, reason: 'Could not parse the Telnyx public key or verify the signature.' };
  }
}
