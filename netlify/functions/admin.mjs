import { configured, json, isAdmin, createCode, hashCode, keyFor, store, updateRecord } from './_lib/auth.mjs';

export default async function admin(req) {
  if (req.method !== 'POST') return json({ ok: false, error: 'method_not_allowed' }, 405);
  if (!configured()) return json({ ok: false, error: 'not_configured' }, 503);
  if (!isAdmin(req)) return json({ ok: false, error: 'unauthorized' }, 401);
  try {
    if (Number(req.headers.get('content-length') || 0) > 4096) return json({ ok: false, error: 'bad_request' }, 400);
    const body = await req.json();
    if (body.action === 'issue') {
      const label = String(body.label || '').trim().slice(0, 100);
      if (!label) return json({ ok: false, error: 'label_required' }, 400);
      for (let tries = 0; tries < 4; tries++) {
        const code = createCode();const hash = hashCode(code);
        const record = { label, createdAt: new Date().toISOString(), revoked: false, devices: [] };
        const result = await store().setJSON(keyFor(hash), record, { onlyIfNew: true });
        if (result.modified) return json({ ok: true, code, hash, label });
      }
      return json({ ok: false, error: 'retry' }, 500);
    }
    if (body.action === 'list') {
      const { blobs } = await store().list({ prefix: 'codes/' });
      const records = await Promise.all(blobs.slice(0, 200).map(async b => {
        const value = await store().get(b.key, { type: 'json' });
        return { hash: b.key.slice(6), label: value?.label || '', createdAt: value?.createdAt || '', revoked: Boolean(value?.revoked), devices: value?.devices?.length || 0 };
      }));
      records.sort((a, b) => b.createdAt.localeCompare(a.createdAt));
      return json({ ok: true, records });
    }
    if (body.action === 'revoke' || body.action === 'reset' || body.action === 'restore') {
      const hash = String(body.hash || '');
      if (!/^[a-f0-9]{64}$/.test(hash)) return json({ ok: false, error: 'bad_request' }, 400);
      const result = await updateRecord(hash, record => ({ ...record,
        revoked: body.action === 'revoke' ? true : body.action === 'restore' ? false : record.revoked,
        devices: body.action === 'reset' ? [] : record.devices,
      }));
      if (result.error) return json({ ok: false, error: result.error }, 404);
      return json({ ok: true });
    }
    return json({ ok: false, error: 'bad_request' }, 400);
  } catch (err) {
    if (err instanceof SyntaxError) return json({ ok: false, error: 'bad_request' }, 400);
    console.error('Premium admin backend error:', err?.message);
    return json({ ok: false, error: 'server_error' }, 500);
  }
}
