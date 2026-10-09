const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');
const cors = require('cors');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: "*", methods: ["GET", "POST"] }
});

const PORT = process.env.PORT || 3000;
const DB_FILE = path.join(__dirname, 'users_db.json');

app.use(cors());
app.use(express.json());
app.use(express.static(__dirname));

// --- CƠ SỞ DỮ LIỆU TẬP TIN JSON ---
function loadDB() {
  if (!fs.existsSync(DB_FILE)) fs.writeFileSync(DB_FILE, JSON.stringify({ users: {} }, null, 2));
  try { return JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); } 
  catch (e) { return { users: {} }; }
}

function saveDB(db) {
  try { fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2)); } 
  catch (e) { console.error("Lỗi ghi DB:", e); }
}

const sessions = new Map();

// API Đăng ký
app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password || username.length < 3) {
    return res.status(400).json({ error: "Tên tài khoản tối thiểu 3 ký tự." });
  }
  const db = loadDB();
  const uKey = username.toLowerCase();
  if (db.users[uKey]) return res.status(400).json({ error: "Tài khoản đã tồn tại." });

  const hash = await bcrypt.hash(password, 10);
  db.users[uKey] = { username: uKey, passwordHash: hash, saves: {} };
  saveDB(db);
  return res.json({ ok: true, username: uKey });
});

// API Đăng nhập
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  const db = loadDB();
  const uKey = (username || '').toLowerCase();
  const user = db.users[uKey];

  if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
    return res.status(400).json({ error: "Sai tên tài khoản hoặc mật khẩu." });
  }

  const token = Math.random().toString(36).substring(2) + Date.now().toString(36);
  sessions.set(token, uKey);
  return res.json({ ok: true, username: uKey, token });
});

// API Kiểm tra phiên
app.get('/api/me', (req, res) => {
  const auth = req.headers.authorization;
  const token = auth ? auth.replace('Bearer ', '') : null;
  if (token && sessions.has(token)) {
    return res.json({ loggedIn: true, username: sessions.get(token) });
  }
  res.json({ loggedIn: false });
});

// API Lưu thủ công
app.post('/api/save', (req, res) => {
  const { character, data } = req.body;
  const auth = req.headers.authorization;
  const token = auth ? auth.replace('Bearer ', '') : null;
  const username = sessions.get(token);

  if (!username || !character || !data) return res.status(400).json({ error: "Lỗi lưu dữ liệu" });
  
  const db = loadDB();
  if (db.users[username]) {
    if (!db.users[username].saves) db.users[username].saves = {};
    db.users[username].saves[character] = data;
    saveDB(db);
    return res.json({ ok: true });
  }
  res.status(404).json({ error: "Không tìm thấy tài khoản" });
});

// API Tải dữ liệu
app.get('/api/save/:char', (req, res) => {
  const auth = req.headers.authorization;
  const token = auth ? auth.replace('Bearer ', '') : null;
  const username = sessions.get(token);
  const charName = req.params.char;

  if (username) {
    const db = loadDB();
    if (db.users[username]?.saves?.[charName]) {
      return res.json({ data: db.users[username].saves[charName] });
    }
  }
  res.json({ data: null });
});

// --- PHÒNG CHƠI CHUNG (ROOMS & SERVERS) ---
const rooms = new Map();

app.get('/api/rooms', (req, res) => {
  const list = [];
  for (const [id, room] of rooms.entries()) {
    list.push({ id, name: room.name, count: room.players.size });
  }
  res.json({ rooms: list });
});

// --- SOCKET.IO MULTIPLAYER ENGINE ---
io.on('connection', (socket) => {
  let pState = {
    id: socket.id,
    account: '',
    room: 'world',
    name: 'Khách',
    char: 'Naruto',
    x: 20000, y: 20000, hp: 100, maxHp: 100, lvl: 1, score: 0, face: 1, dead: 0,
    gameData: null
  };

  socket.on('join', (data) => {
    pState.name = data.name || 'Khách';
    pState.char = data.char || 'Naruto';
    pState.account = data.account || '';
    
    const rId = data.roomId || 'world';
    pState.room = rId;

    if (!rooms.has(rId)) {
      rooms.set(rId, { name: data.roomName || `Server ${rId}`, players: new Map() });
    }

    socket.join(rId);
    rooms.get(rId).players.set(socket.id, pState);
    io.to(rId).emit('feed', `${pState.name} đã tham gia Server!`);
  });

  socket.on('switch_room', ({ roomId, roomName }) => {
    socket.leave(pState.room);
    if (rooms.has(pState.room)) {
      rooms.get(pState.room).players.delete(socket.id);
    }

    pState.room = roomId;
    if (!rooms.has(roomId)) {
      rooms.set(roomId, { name: roomName || `Server ${roomId}`, players: new Map() });
    }

    socket.join(roomId);
    rooms.get(roomId).players.set(socket.id, pState);
    io.to(roomId).emit('feed', `${pState.name} đã tham gia Server!`);
  });

  socket.on('state', (st) => {
    Object.assign(pState, st);
    if (st.gameData) pState.gameData = st.gameData;
    const rObj = rooms.get(pState.room);
    if (rObj) rObj.players.set(socket.id, pState);
  });

  socket.on('fire', (projectiles) => {
    socket.to(pState.room).emit('fire', { id: socket.id, a: projectiles });
  });

  socket.on('died', (data) => {
    if (data && data.by) {
      io.to(pState.room).emit('feed', `${pState.name} bị hạ gục bởi ${data.by}!`);
    }
  });

  // Đồng bộ danh sách người chơi định kỳ trong phòng
  const syncTimer = setInterval(() => {
    const rObj = rooms.get(pState.room);
    if (rObj) {
      const plist = Array.from(rObj.players.values());
      socket.emit('players', plist.filter(p => p.id !== socket.id));
    }
  }, 50);

  // TỰ ĐỘNG LƯU KHI OUT GAME / DISCONNECT
  socket.on('disconnect', () => {
    clearInterval(syncTimer);

    if (pState.account && pState.gameData) {
      const db = loadDB();
      const uKey = pState.account.toLowerCase();
      if (db.users[uKey]) {
        if (!db.users[uKey].saves) db.users[uKey].saves = {};
        db.users[uKey].saves[pState.char] = pState.gameData;
        saveDB(db);
        console.log(`[Auto-Save] Đã tự động lưu tiến trình cho ${uKey} (${pState.char}) khi disconnect.`);
      }
    }

    if (rooms.has(pState.room)) {
      const r = rooms.get(pState.room);
      r.players.delete(socket.id);
      if (r.players.size === 0 && pState.room !== 'world') {
        rooms.delete(pState.room);
      } else {
        io.to(pState.room).emit('feed', `${pState.name} đã ngắt kết nối.`);
      }
    }
  });
});

server.listen(PORT, () => {
  console.log(`Server Naruto RPG Online đang chạy tại http://localhost:${PORT}`);
});
