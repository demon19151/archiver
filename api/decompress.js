import { handleCodec } from './_handler.js';

export const config = { api: { bodyParser: false } };

export default function handler(req, res) {
  return handleCodec(req, res, 'decompress');
}
