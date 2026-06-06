const express = require('express');
const cors    = require('cors');
const path    = require('path');
const db      = require('./db/database');

const app  = express();
const PORT = process.env.PORT || 3000;

// ─── Middleware ───────────────────────────────────────────────
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ─── Auth simples por header ──────────────────────────────────
// O painel envia: Authorization: Bearer <ADMIN_TOKEN>
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || 'mude-isso-aqui';

function adminAuth(req, res, next) {
  const auth = req.headers['authorization'] || '';
  const token = auth.replace('Bearer ', '').trim();
  if (token !== ADMIN_TOKEN) return res.status(401).json({ error: 'Não autorizado' });
  next();
}

// ═══════════════════════════════════════════════════════════════
// ROTAS ADMIN (painel)
// ═══════════════════════════════════════════════════════════════

// Listar keys pendentes
app.get('/admin/keys', adminAuth, (req, res) => {
  const keys = db.prepare('SELECT * FROM keys WHERE ativada = 0 ORDER BY criada_em DESC').all();
  res.json(keys);
});

// Gerar keys
app.post('/admin/keys/gerar', adminAuth, (req, res) => {
  const { tipo, prefixo = 'Key', quantidade = 1 } = req.body;
  const tipos = ['diario', 'semanal', 'mensal', 'vitalicio'];
  if (!tipos.includes(tipo)) return res.status(400).json({ error: 'Tipo inválido' });

  const qtd   = Math.min(parseInt(quantidade) || 1, 100);
  const geradas = [];
  const stmt  = db.prepare('INSERT INTO keys (key, tipo, criada_em) VALUES (?, ?, ?)');

  for (let i = 0; i < qtd; i++) {
    const key = `${prefixo}-${randStr(5)}-${randStr(5)}-${randStr(5)}-${randStr(5)}`;
    stmt.run(key, tipo, new Date().toISOString());
    geradas.push(key);
  }
  res.json({ geradas });
});

// Deletar key pendente
app.delete('/admin/keys/:key', adminAuth, (req, res) => {
  db.prepare('DELETE FROM keys WHERE key = ? AND ativada = 0').run(req.params.key);
  res.json({ ok: true });
});

// Limpar todas pendentes de um tipo
app.delete('/admin/keys/tipo/:tipo', adminAuth, (req, res) => {
  db.prepare('DELETE FROM keys WHERE tipo = ? AND ativada = 0').run(req.params.tipo);
  res.json({ ok: true });
});

// Listar ativadas
app.get('/admin/ativadas', adminAuth, (req, res) => {
  const q = req.query.q ? `%${req.query.q}%` : '%';
  const rows = db.prepare(`
    SELECT * FROM ativadas
    WHERE key LIKE ? OR hwid LIKE ? OR ip LIKE ?
    ORDER BY ativada_em DESC
  `).all(q, q, q);
  res.json(rows);
});

// Deletar ativada
app.delete('/admin/ativadas/:key', adminAuth, (req, res) => {
  db.prepare('DELETE FROM ativadas WHERE key = ?').run(req.params.key);
  db.prepare("UPDATE keys SET ativada = 0 WHERE key = ?").run(req.params.key);
  res.json({ ok: true });
});

// Resetar HWID
app.post('/admin/hwid/reset', adminAuth, (req, res) => {
  const { key } = req.body;
  if (!key) return res.status(400).json({ error: 'Key obrigatória' });
  const found = db.prepare('SELECT * FROM ativadas WHERE key = ?').get(key);
  if (!found) return res.status(404).json({ error: 'Key não encontrada' });
  db.prepare('UPDATE ativadas SET hwid = NULL, mb = NULL, reset_at = ? WHERE key = ?')
    .run(new Date().toISOString(), key);
  res.json({ ok: true });
});

// Estender validade
app.post('/admin/ativadas/:key/estender', adminAuth, (req, res) => {
  const { valor, unidade } = req.body;
  const row = db.prepare('SELECT * FROM ativadas WHERE key = ?').get(req.params.key);
  if (!row) return res.status(404).json({ error: 'Key não encontrada' });

  const d = new Date(row.expiracao);
  if      (unidade === 'horas')   d.setHours(d.getHours() + valor);
  else if (unidade === 'dias')    d.setDate(d.getDate() + valor);
  else if (unidade === 'semanas') d.setDate(d.getDate() + valor * 7);
  else if (unidade === 'meses')   d.setMonth(d.getMonth() + valor);

  db.prepare('UPDATE ativadas SET expiracao = ? WHERE key = ?').run(d.toISOString(), row.key);
  res.json({ ok: true, expiracao: d.toISOString() });
});

// Stats
app.get('/admin/stats', adminAuth, (req, res) => {
  const tipos = ['diario', 'semanal', 'mensal', 'vitalicio'];
  const stats = {};
  tipos.forEach(t => {
    stats[t] = db.prepare('SELECT COUNT(*) as c FROM keys WHERE tipo = ? AND ativada = 0').get(t).c;
  });
  stats.ativadas = db.prepare('SELECT COUNT(*) as c FROM ativadas').get().c;
  stats.pendentes = tipos.reduce((s, t) => s + stats[t], 0);
  res.json(stats);
});

// ═══════════════════════════════════════════════════════════════
// ROTA PÚBLICA — validar key (usado pelo seu app/script)
// ═══════════════════════════════════════════════════════════════

/*
  POST /api/auth
  Body: { key, hwid, mb? }

  Respostas:
    200 { valid: true,  tipo, expiracao }
    200 { valid: false, reason }
*/
app.post('/api/auth', (req, res) => {
  const { key, hwid, mb } = req.body;
  if (!key || !hwid) return res.status(400).json({ valid: false, reason: 'key e hwid obrigatórios' });

  // Checar se a key existe nas pendentes
  const pending = db.prepare('SELECT * FROM keys WHERE key = ? AND ativada = 0').get(key);

  // Checar se já está ativada
  const ativada = db.prepare('SELECT * FROM ativadas WHERE key = ?').get(key);

  if (ativada) {
    // Já ativada — checar HWID
    if (ativada.hwid && ativada.hwid !== hwid) {
      return res.json({ valid: false, reason: 'HWID não corresponde' });
    }

    // Checar expiração
    if (ativada.tipo !== 'vitalicio') {
      if (new Date(ativada.expiracao) < new Date()) {
        return res.json({ valid: false, reason: 'Key expirada' });
      }
    }

    // Atualizar HWID se estava vazio (após reset)
    if (!ativada.hwid) {
      db.prepare('UPDATE ativadas SET hwid = ?, mb = ?, ip = ? WHERE key = ?')
        .run(hwid, mb || null, getIP(req), key);
    }

    return res.json({ valid: true, tipo: ativada.tipo, expiracao: ativada.expiracao });
  }

  if (!pending) {
    return res.json({ valid: false, reason: 'Key inválida' });
  }

  // Primeira ativação
  const expiracao = calcExpiracao(pending.tipo);
  const ip = getIP(req);

  db.prepare(`
    INSERT INTO ativadas (key, tipo, hwid, mb, ip, expiracao, ativada_em)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(key, pending.tipo, hwid, mb || null, ip, expiracao.toISOString(), new Date().toISOString());

  db.prepare('UPDATE keys SET ativada = 1 WHERE key = ?').run(key);

  res.json({ valid: true, tipo: pending.tipo, expiracao: expiracao.toISOString() });
});

// ─── Helpers ─────────────────────────────────────────────────
function randStr(n) {
  const c = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  return Array.from({ length: n }, () => c[Math.floor(Math.random() * c.length)]).join('');
}

function calcExpiracao(tipo) {
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

// ─── Start ────────────────────────────────────────────────────
app.listen(PORT, () => console.log(`KeyAuth rodando na porta ${PORT}`));
