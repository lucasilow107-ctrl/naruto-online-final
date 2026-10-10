'use strict';

const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const path = require('path');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const mongoose = require('mongoose');

const app = express();
const server = http.createServer(app);
const allowedOrigins = (process.env.FRONTEND_URL || '').split(',').map(s => s.trim()).filter(Boolean);
const corsOrigin = (origin, callback) => {
  if (!origin || allowedOrigins.length === 0 || allowedOrigins.includes(origin)) return callback(null, true);
  return callback(new Error('Origin is not allowed by FRONTEND_URL'));
};
const io = new Server(server, {
  cors: { origin: corsOrigin, methods: ['GET', 'POST'], credentials: true }
});

const PORT = Number(process.env.PORT) || 3000;
// Render Environment: DATABASE_URL phải là MongoDB URI, không phải tên biến hay URL web.
// Hỗ trợ cả tên biến thay thế nếu đã cấu hình từ trước.
function readMongoUri() {
  let value = process.env.DATABASE_URL || process.env.MONGODB_URI || process.env.MONGO_URL || '';
  value = String(value).trim();
  // Loại dấu nháy bao ngoài nếu người dùng lỡ dán: "mongodb+srv://..."
  if ((value.startsWith('\"') && value.endsWith('\"')) || (value.startsWith("'") && value.endsWith("'"))) {
    value = value.slice(1, -1).trim();
  }
  // Phòng trường hợp người dùng dán cả "DATABASE_URL=..." vào ô value.
  value = value.replace(/^(DATABASE_URL|MONGODB_URI|MONGO_URL)\s*=\s*/i, '').trim();
  if ((value.startsWith('\"') && value.endsWith('\"')) || (value.startsWith("'") && value.endsWith("'"))) {
    value = value.slice(1, -1).trim();
  }
  return value;
}
const DATABASE_URL = readMongoUri();
const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000;

app.use(cors({
  origin: corsOrigin,
  credentials: true,
  methods: ['GET', 'POST', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json({ limit: '1mb' }));
app.use(express.static(__dirname));

// MongoDB Atlas: dùng URI trong biến môi trường DATABASE_URL trên Render.
// Không tắt kiểm tra TLS/chứng chỉ; mongodb+srv tự bật TLS cho Atlas.
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true, lowercase: true, trim: true, minlength: 3, maxlength: 24 },
  passwordHash: { type: String, required: true },
  saves: { type: mongoose.Schema.Types.Mixed, default: {} },
  createdAt: { type: Date, default: Date.now }
}, { minimize: false });
const User = mongoose.models.User || mongoose.model('User', userSchema);

// Sessions tồn tại trong RAM; khi Render khởi động lại, người chơi cần đăng nhập lại.
const sessions = new Map();
function makeToken() {
  return crypto.randomBytes(32).toString('hex');
}
function getToken(req) {
  const header = req.headers.authorization || '';
  const match = header.match(/^Bearer\s+(.+)$/i);
  return match ? match[1].trim() : null;
}
function getSessionUsername(token) {
  if (typeof token !== 'string' || !token) return null;
  const session = sessions.get(token);
  if (!session) return null;
  if (session.expiresAt <= Date.now()) {
    sessions.delete(token);
    return null;
  }
  return session.username;
}
function requireAuth(req, res, next) {
  const username = getSessionUsername(getToken(req));
  if (!username) return res.status(401).json({ error: 'Phiên đăng nhập hết hạn hoặc không hợp lệ. Hãy đăng nhập lại.' });
  req.username = username;
  next();
}
function validUsername(value) {
  return typeof value === 'string' && /^[a-zA-Z0-9_-]{3,24}$/.test(value.trim());
}
function validPassword(value) {
  return typeof value === 'string' && value.length >= 6 && value.length <= 128;
}
function safeCharacterName(value) {
  return typeof value === 'string' && value.trim().length > 0 && value.trim().length <= 40;
}

app.get('/api/health', (req, res) => {
  res.json({ ok: true, service: 'Naruto RPG API', database: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected' });
});

app.get('/', (req, res) => {
  // Giữ nguyên trang index.html nếu nó có trong thư mục dự án.
  res.sendFile(path.join(__dirname, 'index.html'), err => {
    if (err && !res.headersSent) res.status(200).send('Naruto RPG API is running. Open the frontend hosted on GitHub Pages.');
  });
});

app.post('/api/register', async (req, res) => {
  try {
    const username = typeof req.body.username === 'string' ? req.body.username.trim().toLowerCase() : '';
    const password = req.body.password;
    if (!validUsername(username)) {
      return res.status(400).json({ error: 'Tên tài khoản phải dài 3–24 ký tự, chỉ gồm chữ, số, dấu gạch dưới hoặc gạch ngang.' });
    }
    if (!validPassword(password)) {
      return res.status(400).json({ error: 'Mật khẩu phải dài từ 6 đến 128 ký tự.' });
    }
    const existing = await User.findOne({ username }).lean();
    if (existing) return res.status(409).json({ error: 'Tài khoản đã tồn tại.' });

    const passwordHash = await bcrypt.hash(password, 12);
    await User.create({ username, passwordHash, saves: {} });
    const token = makeToken();
    sessions.set(token, { username, expiresAt: Date.now() + SESSION_TTL_MS });
    return res.status(201).json({ ok: true, username, token, expiresIn: SESSION_TTL_MS });
  } catch (err) {
    if (err && err.code === 11000) return res.status(409).json({ error: 'Tài khoản đã tồn tại.' });
    console.error('[Register]', err.message);
    return res.status(500).json({ error: 'Không thể tạo tài khoản lúc này.' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const username = typeof req.body.username === 'string' ? req.body.username.trim().toLowerCase() : '';
    const password = req.body.password;
    if (!username || typeof password !== 'string') {
      return res.status(400).json({ error: 'Vui lòng nhập tên tài khoản và mật khẩu.' });
    }
    const user = await User.findOne({ username });
    if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
      return res.status(401).json({ error: 'Sai tên tài khoản hoặc mật khẩu.' });
    }
    const token = makeToken();
    sessions.set(token, { username, expiresAt: Date.now() + SESSION_TTL_MS });
    return res.json({ ok: true, username, token, expiresIn: SESSION_TTL_MS });
  } catch (err) {
    console.error('[Login]', err.message);
    return res.status(500).json({ error: 'Không thể đăng nhập lúc này.' });
  }
});

app.post('/api/logout', requireAuth, (req, res) => {
  const token = getToken(req);
  if (token) sessions.delete(token);
  res.json({ ok: true });
});

app.get('/api/me', (req, res) => {
  const username = getSessionUsername(getToken(req));
  if (username) return res.json({ loggedIn: true, username });
  return res.json({ loggedIn: false });
});

app.post('/api/save', requireAuth, async (req, res) => {
  try {
    const { character, data } = req.body || {};
    if (!safeCharacterName(character) || !data || typeof data !== 'object' || Array.isArray(data)) {
      return res.status(400).json({ error: 'Dữ liệu lưu không hợp lệ.' });
    }
    const user = await User.findOne({ username: req.username });
    if (!user) return res.status(404).json({ error: 'Không tìm thấy tài khoản.' });
    const saves = user.saves && typeof user.saves === 'object' ? user.saves : {};
    saves[character.trim()] = data;
    user.saves = saves;
    user.markModified('saves');
    await user.save();
    return res.json({ ok: true });
  } catch (err) {
    console.error('[Save]', err.message);
    return res.status(500).json({ error: 'Không thể lưu dữ liệu lúc này.' });
  }
});

app.delete('/api/save/:char', requireAuth, async (req, res) => {
  try {
    const charName = decodeURIComponent(req.params.char);
    const user = await User.findOne({ username: req.username });
    if (!user) return res.status(404).json({ error: 'Không tìm thấy tài khoản.' });
    const saves = user.saves && typeof user.saves === 'object' ? user.saves : {};
    delete saves[charName];
    user.saves = saves;
    user.markModified('saves');
    await user.save();
    return res.json({ ok: true });
  } catch (err) {
    console.error('[Delete save]', err.message);
    return res.status(500).json({ error: 'Không thể xóa dữ liệu lưu lúc này.' });
  }
});

app.get('/api/save/:char', requireAuth, async (req, res) => {
  try {
    const charName = decodeURIComponent(req.params.char);
    const user = await User.findOne({ username: req.username }).lean();
    if (!user) return res.status(404).json({ error: 'Không tìm thấy tài khoản.' });
    return res.json({ data: user.saves && user.saves[charName] ? user.saves[charName] : null });
  } catch (err) {
    console.error('[Load save]', err.message);
    return res.status(500).json({ error: 'Không thể tải dữ liệu lúc này.' });
  }
});

// Rooms chỉ nằm trong RAM; khi server restart, phòng sẽ được tạo lại khi có người tham gia.
const rooms = new Map();
app.get('/api/rooms', (req, res) => {
  const list = [];
  for (const [id, room] of rooms.entries()) {
    list.push({ id, name: room.name, count: room.players.size });
  }
  res.json({ rooms: list });
});

function removeSocketFromRoom(socket, pState) {
  const room = rooms.get(pState.room);
  if (!room) return;
  room.players.delete(socket.id);
  if (room.players.size === 0 && pState.room !== 'world') rooms.delete(pState.room);
  else socket.to(pState.room).emit('feed', `${pState.name} đã ngắt kết nối.`);
}

io.on('connection', socket => {
  const pState = {
    id: socket.id, account: '', token: null, room: 'world', name: 'Khách', char: 'Naruto',
    x: 20000, y: 20000, hp: 100, maxHp: 100, lvl: 1, score: 0, face: 1, dead: 0, gameData: null
  };
  socket.data.rpgPlayer = pState;

  socket.on('join', async data => {
    try {
      data = data && typeof data === 'object' ? data : {};
      pState.name = typeof data.name === 'string' ? data.name.slice(0, 24) : 'Khách';
      pState.char = safeCharacterName(data.char) ? data.char.trim() : 'Naruto';
      // Chỉ liên kết socket với tài khoản khi token đăng nhập hợp lệ; không tin data.account do client gửi.
      const token = typeof data.token === 'string' ? data.token : null;
      const username = getSessionUsername(token);
      pState.token = username ? token : null;
      pState.account = username || '';
      const rId = typeof data.roomId === 'string' && data.roomId.trim() ? data.roomId.trim().slice(0, 48) : 'world';
      const oldRoom = pState.room;
      if (socket.rooms.has(oldRoom) && oldRoom !== rId) socket.leave(oldRoom);
      if (rooms.has(oldRoom)) {
        rooms.get(oldRoom).players.delete(socket.id);
        if (rooms.get(oldRoom).players.size === 0 && oldRoom !== 'world') rooms.delete(oldRoom);
      }
      pState.room = rId;
      if (!rooms.has(rId)) rooms.set(rId, { name: typeof data.roomName === 'string' ? data.roomName.slice(0, 48) : `Server ${rId}`, players: new Map() });
      socket.join(rId);
      rooms.get(rId).players.set(socket.id, pState);
      io.to(rId).emit('feed', `${pState.name} đã tham gia Server!`);
    } catch (err) {
      console.error('[Socket join]', err.message);
    }
  });

  socket.on('switch_room', data => {
    data = data && typeof data === 'object' ? data : {};
    const roomId = typeof data.roomId === 'string' && data.roomId.trim() ? data.roomId.trim().slice(0, 48) : 'world';
    const roomName = typeof data.roomName === 'string' ? data.roomName.slice(0, 48) : `Server ${roomId}`;
    socket.leave(pState.room);
    if (rooms.has(pState.room)) {
      rooms.get(pState.room).players.delete(socket.id);
      if (rooms.get(pState.room).players.size === 0 && pState.room !== 'world') rooms.delete(pState.room);
    }
    pState.room = roomId;
    if (!rooms.has(roomId)) rooms.set(roomId, { name: roomName, players: new Map() });
    socket.join(roomId);
    rooms.get(roomId).players.set(socket.id, pState);
    io.to(roomId).emit('feed', `${pState.name} đã tham gia Server!`);
  });

  socket.on('state', st => {
    if (!st || typeof st !== 'object') return;
    // Chỉ nhận các trường trạng thái cần đồng bộ; không cho client ghi đè id/account/room/token.
    const allowed = ['name', 'char', 'x', 'y', 'hp', 'maxHp', 'lvl', 'score', 'face', 'dead', 'gameData'];
    for (const key of allowed) {
      if (Object.prototype.hasOwnProperty.call(st, key)) {
        if (key === 'name' && typeof st[key] === 'string') pState.name = st[key].slice(0, 24);
        else if (key === 'char' && safeCharacterName(st[key])) pState.char = st[key].trim();
        else if (key === 'gameData' && st[key] && typeof st[key] === 'object' && !Array.isArray(st[key])) pState.gameData = st[key];
        else if (['x', 'y', 'hp', 'maxHp', 'lvl', 'score', 'face', 'dead'].includes(key) && Number.isFinite(Number(st[key]))) pState[key] = Number(st[key]);
      }
    }
    const room = rooms.get(pState.room);
    if (room) room.players.set(socket.id, pState);
  });

  socket.on('fire', projectiles => {
    if (!Array.isArray(projectiles)) return;
    socket.to(pState.room).emit('fire', { id: socket.id, a: projectiles.slice(0, 100) });
  });

  // Đồng bộ hiệu ứng kỹ năng cho người chơi cùng phòng. Đây là VFX; sát thương vẫn phải được đồng bộ riêng.
  socket.on('skill_fx', data => {
    if (!data || !Number.isFinite(Number(data.x)) || !Number.isFinite(Number(data.y))) return;
    const color = typeof data.color === 'string' && /^#[0-9a-fA-F]{6}$/.test(data.color) ? data.color : '#80deea';
    socket.to(pState.room).emit('skill_fx', {
      id: socket.id, x: Math.max(-50000, Math.min(50000, Number(data.x))),
      y: Math.max(-50000, Math.min(50000, Number(data.y))),
      angle: Number.isFinite(Number(data.angle)) ? Number(data.angle) : 0,
      skill: String(data.skill || 'Kỹ năng').slice(0, 40),
      char: safeCharacterName(data.char) ? data.char.trim().slice(0, 20) : pState.char, color
    });
  });

  socket.on('died', data => {
    if (data && typeof data.by === 'string' && data.by.length <= 40) {
      io.to(pState.room).emit('feed', `${pState.name} bị hạ gục bởi ${data.by}!`);
    }
  });

  // Chat chỉ phát trong phòng hiện tại; nội dung là plain text, giới hạn độ dài.
  socket.on('server_chat', data => {
    if (!data || typeof data.message !== 'string') return;
    const message = data.message.replace(/[\u0000-\u001f\u007f]/g, '').trim().slice(0, 180);
    if (!message) return;
    io.to(pState.room).emit('server_chat', { name: pState.name, message, at: Date.now() });
  });

  socket.on('ally_invite', data => {
    const targetId = data && typeof data.to === 'string' ? data.to : '';
    const target = io.sockets.sockets.get(targetId);
    const targetState = target && target.data && target.data.rpgPlayer;
    if (!target || !targetState || targetId === socket.id || targetState.room !== pState.room) {
      socket.emit('ally_result', { ok: false, message: 'Người chơi không còn ở cùng server.' });
      return;
    }
    target.emit('ally_invite', { from: socket.id, name: pState.name });
  });

  socket.on('ally_reply', data => {
    const fromId = data && typeof data.to === 'string' ? data.to : '';
    const inviter = io.sockets.sockets.get(fromId);
    const inviterState = inviter && inviter.data && inviter.data.rpgPlayer;
    if (!inviter || !inviterState || inviterState.room !== pState.room) {
      socket.emit('ally_result', { ok: false, message: 'Người mời đã rời server.' });
      return;
    }
    if (data.accept === true) {
      inviter.emit('ally_result', { ok: true, id: socket.id, name: pState.name });
      socket.emit('ally_update', { id: fromId, name: inviterState.name });
      io.to(pState.room).emit('system_chat', { message: `${pState.name} và ${inviterState.name} đã trở thành đồng minh.` });
    } else {
      inviter.emit('ally_result', { ok: false, message: `${pState.name} đã từ chối lời mời.` });
    }
  });

  const syncTimer = setInterval(() => {
    const room = rooms.get(pState.room);
    if (room) socket.emit('players', Array.from(room.players.values()).filter(p => p.id !== socket.id));
  }, 100);

  socket.on('disconnect', async () => {
    clearInterval(syncTimer);
    try {
      // Auto-save chỉ chạy với socket có token hợp lệ và dữ liệu nhân vật.
      if (pState.account && pState.token && getSessionUsername(pState.token) === pState.account && pState.gameData) {
        const user = await User.findOne({ username: pState.account });
        if (user) {
          const saves = user.saves && typeof user.saves === 'object' ? user.saves : {};
          saves[pState.char] = pState.gameData;
          user.saves = saves;
          user.markModified('saves');
          await user.save();
          console.log(`[Auto-Save] Đã lưu tiến trình cho ${pState.account} (${pState.char}) khi disconnect.`);
        }
      }
    } catch (err) {
      console.error('[Auto-Save]', err.message);
    }
    removeSocketFromRoom(socket, pState);
  });
});

async function start() {
  if (!DATABASE_URL) {
    console.error('THIẾU DATABASE_URL: Render > Environment > DATABASE_URL phải chứa URI MongoDB Atlas.');
    process.exit(1);
  }
  if (!/^mongodb(?:\+srv)?:\/\//i.test(DATABASE_URL)) {
    console.error('[MongoDB] DATABASE_URL sai định dạng. Giá trị phải bắt đầu bằng mongodb:// hoặc mongodb+srv://.');
    console.error('[MongoDB] Không in URI ra log để tránh làm lộ mật khẩu. Hãy sửa Render > Environment.');
    process.exit(1);
  }
  try {
    await mongoose.connect(DATABASE_URL, {
      serverSelectionTimeoutMS: 15000,
      connectTimeoutMS: 15000,
      socketTimeoutMS: 45000,
      maxPoolSize: 10,
      family: 4
    });
    console.log('[MongoDB] Đã kết nối MongoDB Atlas.');
    server.listen(PORT, '0.0.0.0', () => {
      console.log(`Naruto RPG API đang chạy trên cổng ${PORT}.`);
    });
  } catch (err) {
    console.error('[MongoDB] Kết nối thất bại:', err.message);
    console.error('Kiểm tra DATABASE_URL, mật khẩu đã URL-encode, và Atlas Network Access (IP Access List).');
    process.exit(1);
  }
}

process.on('SIGTERM', async () => {
  console.log('Đang tắt Naruto RPG API...');
  await mongoose.disconnect().catch(() => {});
  server.close(() => process.exit(0));
});

start();
