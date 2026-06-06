const express = require('express');
const cors    = require('cors');
const path    = require('path');
const db      = require('./db/database');

const app  = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const ADMIN_TOKEN = process.env.ADMIN_TOKEN || 'mude-isso-aqui';

function adminAuth(req, res, next) {
  const token = (req.headers['authorization'] || '').replace('Bearer ', '').trim();
  if (token !== ADMIN_TOKEN) return res.status(401).json({ error: 'Não autorizado' });
  next();
}

// ── ADMIN: listar keys pendentes ──────────────────────────────
app.get('/admin/keys', adminAuth, async (req, res) => {
  const rows = await db.all2('SELECT * FROM keys WHERE ativada = 0 ORDER BY criada_em DESC', []);
  res.json(rows);
});

// ── ADMIN: gerar keys ─────────────────────────────────────────
app.post('/admin/keys/gerar', adminAuth, async (req, res) => {
  const { tipo, prefixo = 'Key', quantidade = 1 } = req.body;
  const tipos = ['diario', 'semanal', 'mensal', 'vitalicio'];
  if (!tipos.includes(tipo)) return res.status(400).json({ error: 'Tipo inválido' });
  const qtd = Math.min(parseInt(quantidade) || 1, 100);
  const geradas = [];
  for (let i = 0; i < qtd; i++) {
    const key = `${prefixo}-${rand(5)}-${rand(5)}-${rand(5)}-${rand(5)}`;
    await db.run2('INSERT INTO keys (key, tipo, criada_em) VALUES (?, ?, ?)', [key, tipo, new Date().toISOString()]);
    geradas.push(key);
  }
  res.json({ geradas });
});

// ── ADMIN: deletar key pendente ───────────────────────────────
app.delete('/admin/keys/:key', adminAuth, async (req, res) => {
  await db.run2('DELETE FROM keys WHERE key = ? AND ativada = 0', [req.params.key]);
  res.json({ ok: true });
});

// ── ADMIN: limpar tipo ────────────────────────────────────────
app.delete('/admin/keys/tipo/:tipo', adminAuth, async (req, res) => {
  await db.run2('DELETE FROM keys WHERE tipo = ? AND ativada = 0', [req.params.tipo]);
  res.json({ ok: true });
});

// ── ADMIN: listar ativadas ────────────────────────────────────
app.get('/admin/ativadas', adminAuth, async (req, res) => {
  const q = req.query.q ? `%${req.query.q}%` : '%';
  const rows = await db.all2(
    'SELECT * FROM ativadas WHERE key LIKE ? OR hwid LIKE ? OR ip LIKE ? ORDER BY ativada_em DESC',
    [q, q, q]
  );
  res.json(rows);
});

// ── ADMIN: deletar ativada ────────────────────────────────────
app.delete('/admin/ativadas/:key', adminAuth, async (req, res) => {
  await db.run2('DELETE FROM ativadas WHERE key = ?', [req.params.key]);
  await db.run2('UPDATE keys SET ativada = 0 WHERE key = ?', [req.params.key]);
  res.json({ ok: true });
});

// ── ADMIN: reset HWID ─────────────────────────────────────────
app.post('/admin/hwid/reset', adminAuth, async (req, res) => {
  const { key } = req.body;
  if (!key) return res.status(400).json({ error: 'Key obrigatória' });
  const found = await db.get2('SELECT * FROM ativadas WHERE key = ?', [key]);
  if (!found) return res.status(404).json({ error: 'Key não encontrada' });
  await db.run2('UPDATE ativadas SET hwid = NULL, mb = NULL, reset_at = ? WHERE key = ?', [new Date().toISOString(), key]);
  res.json({ ok: true });
});

// ── ADMIN: estender validade ──────────────────────────────────
app.post('/admin/ativadas/:key/estender', adminAuth, async (req, res) => {
  const { valor, unidade } = req.body;
  const row = await db.get2('SELECT * FROM ativadas WHERE key = ?', [req.params.key]);
  if (!row) return res.status(404).json({ error: 'Key não encontrada' });
  const d = new Date(row.expiracao);
  if      (unidade === 'horas')   d.setHours(d.getHours() + valor);
  else if (unidade === 'dias')    d.setDate(d.getDate() + valor);
  else if (unidade === 'semanas') d.setDate(d.getDate() + valor * 7);
  else if (unidade === 'meses')   d.setMonth(d.getMonth() + valor);
  await db.run2('UPDATE ativadas SET expiracao = ? WHERE key = ?', [d.toISOString(), row.key]);
  res.json({ ok: true, expiracao: d.toISOString() });
});

// ── ADMIN: stats ──────────────────────────────────────────────
app.get('/admin/stats', adminAuth, async (req, res) => {
  const tipos = ['diario', 'semanal', 'mensal', 'vitalicio'];
  const stats = {};
  for (const t of tipos) {
    const r = await db.get2('SELECT COUNT(*) as c FROM keys WHERE tipo = ? AND ativada = 0', [t]);
    stats[t] = r.c;
  }
  const at = await db.get2('SELECT COUNT(*) as c FROM ativadas', []);
  stats.ativadas  = at.c;
  stats.pendentes = tipos.reduce((s, t) => s + stats[t], 0);
  res.json(stats);
});

// ── PÚBLICO: validar key ──────────────────────────────────────
app.post('/api/auth', async (req, res) => {
  const { key, hwid, mb } = req.body;
  if (!key || !hwid) return res.status(400).json({ valid: false, reason: 'key e hwid obrigatórios' });

  const ativada = await db.get2('SELECT * FROM ativadas WHERE key = ?', [key]);

  if (ativada) {
    if (ativada.hwid && ativada.hwid !== hwid)
      return res.json({ valid: false, reason: 'HWID não corresponde' });
    if (ativada.tipo !== 'vitalicio' && new Date(ativada.expiracao) < new Date())
      return res.json({ valid: false, reason: 'Key expirada' });
    if (!ativada.hwid)
      await db.run2('UPDATE ativadas SET hwid = ?, mb = ?, ip = ? WHERE key = ?', [hwid, mb || null, getIP(req), key]);
    return res.json({ valid: true, tipo: ativada.tipo, expiracao: ativada.expiracao });
  }

  const pending = await db.get2('SELECT * FROM keys WHERE key = ? AND ativada = 0', [key]);
  if (!pending) return res.json({ valid: false, reason: 'Key inválida' });

  const expiracao = calcExp(pending.tipo);
  const ip = getIP(req);
  await db.run2(
    'INSERT INTO ativadas (key, tipo, hwid, mb, ip, expiracao, ativada_em) VALUES (?, ?, ?, ?, ?, ?, ?)',
    [key, pending.tipo, hwid, mb || null, ip, expiracao.toISOString(), new Date().toISOString()]
  );
  await db.run2('UPDATE keys SET ativada = 1 WHERE key = ?', [key]);
  res.json({ valid: true, tipo: pending.tipo, expiracao: expiracao.toISOString() });
});

// ── Helpers ───────────────────────────────────────────────────
function rand(n) {
  const c = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  return Array.from({ length: n }, () => c[Math.floor(Math.random() * c.length)]).join('');
}
function calcExp(tipo) {
  const d = new Date();
  if      (tipo === 'diario')   d.setDate(d.getDate() + 1);
  else if (tipo === 'semanal')  d.setDate(d.getDate() + 7);
  else if (tipo === 'mensal')   d.setMonth(d.getMonth() + 1);
  else                          d.setFullYear(d.getFullYear() + 99);
  return d;
}
function getIP(req) {
  return (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
}

app.listen(PORT, () => console.log(`KeyAuth rodando na porta ${PORT}`));
