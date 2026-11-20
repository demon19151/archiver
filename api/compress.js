import { handleCodec } from './_handler.js';

export default function handler(req, res) {
  return handleCodec(req, res, 'compress');
}
