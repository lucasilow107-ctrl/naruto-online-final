const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');
const cors = require('cors');

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*", methods: ["GET", "POST"] } });

const PORT = process.env.PORT || 3000;
const DB_FILE = path.join(__dirname, 'users_db.json');

app.use(cors());
app.use(express.json());
app.use(express.static(__dirname));

function loadDB() {
  if (!fs.existsSync(DB_FILE)) fs.writeFileSync(DB_FILE, JSON.stringify({ users: {} }, null, 2));
  try { return JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); } catch (e) { return { users: {} }; }
}
function saveDB(db) {
  try { fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2)); } catch (e) {}
}

const sessions = new Map();
const rooms = new Map();
const alliances = new Map(); // Lưu thông tin liên minh

// --- NIGHT MARKET LOGIC ---
let nightMarketActive = false;
let nightMarketTimer = 1800; // 30 phút xuất hiện 1 lần
setInterval(() => {
  nightMarketTimer--;
  if (nightMarketTimer <= 0) {
    nightMarketActive = !nightMarketActive;
    nightMarketTimer = nightMarketActive ? 900 : 1800; // 15 phút mở, 30 phút đóng
    io.emit('night_market_status', { active: nightMarketActive, timeLeft: nightMarketTimer });
  }
}, 1000);

app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password || username.length < 3) return res.status(400).json({ error: "Tên ngắn quá!" });
  const db = loadDB(), uKey = username.toLowerCase();
  if (db.users[uKey]) return res.status(400).json({ error: "Tài khoản đã tồn tại." });
  const hash = await bcrypt.hash(password, 10);
  db.users[uKey] = { username: uKey, passwordHash: hash, saves: {} };
  saveDB(db);
  return res.json({ ok: true, username: uKey });
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  const db = loadDB(), uKey = (username || '').toLowerCase(), user = db.users[uKey];
  if (!user || !(await bcrypt.compare(password, user.passwordHash))) return res.status(400).json({ error: "Sai tài khoản/mật khẩu." });
  const token = Math.random().toString(36).substring(2) + Date.now().toString(36);
  sessions.set(token, uKey);
  return res.json({ ok: true, username: uKey, token });
});

app.get('/api/me', (req, res) => {
  const token = (req.headers.authorization || '').replace('Bearer ', '');
  if (token && sessions.has(token)) return res.json({ loggedIn: true, username: sessions.get(token) });
  res.json({ loggedIn: false });
});

app.post('/api/save', (req, res) => {
  const { character, data } = req.body;
  const token = (req.headers.authorization || '').replace('Bearer ', '');
  const username = sessions.get(token);
  if (!username) return res.status(400).json({ error: "Lỗi lưu" });
  const db = loadDB();
  if (db.users[username]) {
    if (!db.users[username].saves) db.users[username].saves = {};
    db.users[username].saves[character] = data;
    saveDB(db);
    return res.json({ ok: true });
  }
  res.status(404).json({ error: "Không thấy user" });
});

app.get('/api/save/:char', (req, res) => {
  const token = (req.headers.authorization || '').replace('Bearer ', '');
  const username = sessions.get(token);
  if (username) {
    const db = loadDB();
    if (db.users[username]?.saves?.[req.params.char]) return res.json({ data: db.users[username].saves[req.params.char] });
  }
  res.json({ data: null });
});

io.on('connection', (socket) => {
  let pState = { id: socket.id, account: '', room: 'world', name: 'Khách', char: 'Naruto', x: 20000, y: 20000, hp: 100, maxHp: 100, lvl: 1, score: 0, face: 1, dead: 0, allianceId: null };

  socket.emit('night_market_status', { active: nightMarketActive, timeLeft: nightMarketTimer });

  socket.on('join', (data) => {
    pState.name = data.name || 'Khách'; pState.char = data.char || 'Naruto'; pState.account = data.account || '';
    pState.room = data.roomId || 'world';
    socket.join(pState.room);
    io.to(pState.room).emit('feed', `${pState.name} đã tham gia!`);
  });

  socket.on('state', (st) => {
    Object.assign(pState, st);
    socket.to(pState.room).emit('player_update', pState);
  });

  socket.on('fire', (projectiles) => {
    socket.to(pState.room).emit('fire', { id: socket.id, a: projectiles });
  });

  // REAL-TIME PVP DAMAGE SYNC
  socket.on('deal_damage', (data) => {
    // Send hit event to specific target player
    io.to(data.targetId).emit('take_damage', { dmg: data.dmg, attackerId: socket.id, attackerName: pState.name, fx: data.fx });
  });

  // CHAT SYSTEM
  socket.on('send_chat', (data) => {
    io.to(pState.room).emit('chat_msg', { sender: pState.name, text: data.text, channel: data.channel, allianceId: pState.allianceId });
  });

  // LIÊN MINH (ALLIANCE)
  socket.on('invite_alliance', (targetId) => {
    io.to(targetId).emit('alliance_invite_req', { fromId: socket.id, fromName: pState.name });
  });

  socket.on('accept_alliance', (fromId) => {
    const allianceId = 'ally_' + Date.now();
    pState.allianceId = allianceId;
    io.to(fromId).emit('alliance_joined', { allianceId, partnerName: pState.name });
    socket.emit('alliance_joined', { allianceId, partnerName: 'Đồng đội' });
  });

  // GIAO DỊCH (TRADE)
  socket.on('trade_request', (data) => {
    io.to(data.targetId).emit('trade_offer', { fromId: socket.id, fromName: pState.name, item: data.item });
  });

  socket.on('trade_accept', (data) => {
    io.to(data.fromId).emit('trade_completed', { item: data.item, partnerName: pState.name });
  });

  socket.on('disconnect', () => {
    if (pState.account && pState.gameData) {
      const db = loadDB(), uKey = pState.account.toLowerCase();
      if (db.users[uKey]) {
        if (!db.users[uKey].saves) db.users[uKey].saves = {};
        db.users[uKey].saves[pState.char] = pState.gameData;
        saveDB(db);
      }
    }
  });
});

server.listen(PORT, () => console.log(`Server running at http://localhost:${PORT}`));
