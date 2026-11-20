import { sendJson } from './_handler.js';

export const config = { api: { bodyParser: false } };

export default function handler(req, res) {
  if (req.method === 'GET') sendJson(res, 200, { status: 'ok' });
  else sendJson(res, 405, { error: { code: 'method_not_allowed', message: 'Требуется GET-запрос' } });
}
