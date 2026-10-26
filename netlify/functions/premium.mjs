import { configured, json, hashCode, normalizeCode, validCode, validDevice, addDevice, getRecord, issueToken, parseToken } from './_lib/auth.mjs';
import { premiumLessons, premiumDialogues } from './_lib/premium-data.mjs';

export default async function premium(req) {
  if (req.method !== 'POST') return json({ ok: false, error: 'method_not_allowed' }, 405);
  if (!configured()) return json({ ok: false, error: 'not_configured' }, 503);
  try {
    if (Number(req.headers.get('content-length') || 0) > 4096) return json({ ok: false, error: 'bad_request' }, 400);
    const body = await req.json();
    if (!validDevice(body.deviceId)) return json({ ok: false, error: 'bad_request' }, 400);
    if (body.action === 'activate') {
      const code = normalizeCode(body.code);
      if (!validCode(code)) return json({ ok: false, error: 'invalid_code' }, 401);
      const hash = hashCode(code);
      const result = await addDevice(hash, body.deviceId);
      if (result.error) return json({ ok: false, error: result.error }, result.error === 'device_limit' ? 403 : 401);
      return json({ ok: true, token: issueToken(hash, body.deviceId), lessons: premiumLessons, dialogues: premiumDialogues });
    }
    if (body.action === 'restore') {
      const data = parseToken(body.token, body.deviceId);
      if (!data) return json({ ok: false, error: 'invalid_token' }, 401);
      const found = await getRecord(data.h);
      if (!found?.data || found.data.revoked) return json({ ok: false, error: 'revoked' }, 401);
      if (!found.data.devices?.includes(body.deviceId)) return json({ ok: false, error: 'invalid_token' }, 401);
      return json({ ok: true, token: issueToken(data.h, body.deviceId), lessons: premiumLessons, dialogues: premiumDialogues });
    }
    return json({ ok: false, error: 'bad_request' }, 400);
  } catch (err) {
    if (err instanceof SyntaxError) return json({ ok: false, error: 'bad_request' }, 400);
    console.error('Premium backend error:', err?.message);
    return json({ ok: false, error: 'server_error' }, 500);
  }
}
