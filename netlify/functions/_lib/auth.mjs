import { getStore } from '@netlify/blobs';
import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

const CODE_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
const MAX_DEVICES = 3;
const TOKEN_AGE_MS = 1000 * 60 * 60 * 24 * 90;

export const json = (body, status = 200) => new Response(JSON.stringify(body), {
  status,
  headers: {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store, private, max-age=0',
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer',
  },
});
export const configured = () => Boolean(process.env.VAMOS_ADMIN_SECRET && process.env.VAMOS_TOKEN_SECRET);
export const store = () => getStore({ name: 'vamos-premium-codes', consistency: 'strong' });
export const hashCode = code => createHash('sha256').update(code).digest('hex');
export const keyFor = hash => `codes/${hash}`;
export const normalizeCode = value => typeof value === 'string' ? value.trim().toUpperCase().replace(/\s+/g, '') : '';
export const validCode = code => /^PACO(?:-[A-HJ-NP-Z2-9]{5}){4}$/.test(code);
export const validDevice = id => typeof id === 'string' && /^[a-f0-9-]{36}$/.test(id);

export function createCode() {
  const bytes = randomBytes(20);
  const chars = [...bytes].map(b => CODE_ALPHABET[b & 31]).join('');
  return 'PACO-' + chars.match(/.{5}/g).join('-');
}
function base64url(value) { return Buffer.from(value).toString('base64url'); }
function sign(value) { return createHmac('sha256', process.env.VAMOS_TOKEN_SECRET).update(value).digest('base64url'); }
export function issueToken(hash, deviceId) {
  const body = base64url(JSON.stringify({ v: 1, h: hash, d: deviceId, exp: Date.now() + TOKEN_AGE_MS }));
  return body + '.' + sign(body);
}
export function parseToken(token, deviceId) {
  if (typeof token !== 'string' || token.length > 1024) return null;
  const [body, signature, extra] = token.split('.');
  if (!body || !signature || extra !== undefined) return null;
  const expected = sign(body);
  const a = Buffer.from(signature); const b = Buffer.from(expected);
  if (a.length !== b.length || !timingSafeEqual(a, b)) return null;
  try {
    const data = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
    if (data.v !== 1 || data.d !== deviceId || !/^[a-f0-9]{64}$/.test(data.h) || !Number.isSafeInteger(data.exp) || data.exp < Date.now()) return null;
    return data;
  } catch { return null; }
}
export function isAdmin(req) {
  const actual = (req.headers.get('authorization') || '').replace(/^Bearer\s+/i, '');
  const expected = process.env.VAMOS_ADMIN_SECRET || '';
  if (!expected || actual.length > 1024) return false;
  const a = createHash('sha256').update(actual).digest();
  const b = createHash('sha256').update(expected).digest();
  return timingSafeEqual(a, b);
}
export async function getRecord(hash) {
  return await store().getWithMetadata(keyFor(hash), { type: 'json' });
}
export async function addDevice(hash, deviceId) {
  for (let tries = 0; tries < 6; tries++) {
    const found = await getRecord(hash);
    if (!found?.data) return { error: 'invalid_code' };
    const record = found.data;
    if (record.revoked) return { error: 'revoked' };
    if ((record.devices || []).includes(deviceId)) return { record };
    if ((record.devices || []).length >= MAX_DEVICES) return { error: 'device_limit' };
    const next = { ...record, devices: [...(record.devices || []), deviceId] };
    const saved = await store().setJSON(keyFor(hash), next, { onlyIfMatch: found.etag });
    if (saved.modified) return { record: next };
  }
  return { error: 'retry' };
}
export async function updateRecord(hash, fn) {
  for (let tries = 0; tries < 6; tries++) {
    const found = await getRecord(hash);
    if (!found?.data) return { error: 'not_found' };
    const next = fn(found.data);
    const saved = await store().setJSON(keyFor(hash), next, { onlyIfMatch: found.etag });
    if (saved.modified) return { record: next };
  }
  return { error: 'retry' };
}
