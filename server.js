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

const allowedOrigins = process.env.FRONTEND_URL
  ? process.env.FRONTEND_URL.split(',').map(s => s.trim())
  : '*';

const io = new Server(server, {
  cors: {
    origin: allowedOrigins,
    methods: ['GET', 'POST']
  }
});

const PORT = Number(process.env.PORT) || 3000;
const DATABASE_URL = process.env.DATABASE_URL;
const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000;

app.use(cors({
  origin: allowedOrigins,
  methods: ['GET', 'POST', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json({ limit: '1mb' }));
app.use(express.static(__dirname));

const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true,
    minlength: 3,
    maxlength: 24
  },
  passwordHash: {
    type: String,
    required: true
  },
  saves: {
    type: mongoose.Schema.Types.Mixed,
    default: {}
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
}, { minimize: false });

const User = mongoose.models.User ||
  mongoose.model('User', userSchema);

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
  if (!token) return null;

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

  if (!username) {
    return res.status(401).json({
      error: 'Phiên đăng nhập hết hạn. Hãy đăng nhập lại.'
    });
  }

  req.username = username;
  next();
}

function validUsername(value) {
  return typeof value === 'string' &&
    /^[a-zA-Z0-9_-]{3,24}$/.test(value.trim());
}

function validPassword(value) {
  return typeof value === 'string' &&
    value.length >= 6 &&
    value.length <= 128;
}

function safeCharacterName(value) {
  return typeof value === 'string' &&
    value.trim().length > 0 &&
    value.trim().length <= 40;
}

app.get('/api/health', (req, res) => {
  res.json({
    ok: true,
    service: 'Naruto RPG API',
    database: mongoose.connection.readyState === 1
      ? 'connected'
      : 'disconnected'
  });
});

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'), err => {
    if (err && !res.headersSent) {
      res.status(200).send(
        'Naruto RPG API is running. Open the frontend hosted on GitHub Pages.'
      );
    }
  });
});

app.post('/api/register', async (req, res) => {
  try {
    const username = typeof req.body.username === 'string'
      ? req.body.username.trim().toLowerCase()
      : '';
    const password = req.body.password;

    if (!validUsername(username)) {
      return res.status(400).json({
        error: 'Tên tài khoản phải dài 3–24 ký tự, chỉ gồm chữ, số, _ hoặc -.'
      });
    }

    if (!validPassword(password)) {
      return res.status(400).json({
        error: 'Mật khẩu phải dài từ 6 đến 128 ký tự.'
      });
    }

    const existing = await User.findOne({ username }).lean();
    if (existing) {
      return res.status(409).json({ error: 'Tài khoản đã tồn tại.' });
    }

    const passwordHash = await bcrypt.hash(password, 12);
    await User.create({ username, passwordHash, saves: {} });

    const token = makeToken();
    sessions.set(token, {
      username,
      expiresAt: Date.now() + SESSION_TTL_MS
    });

    res.status(201).json({
      ok: true,
      username,
      token,
      expiresIn: SESSION_TTL_MS
    });
  } catch (err) {
    if (err && err.code === 11000) {
      return res.status(409).json({ error: 'Tài khoản đã tồn tại.' });
    }
    console.error('[Register]', err.message);
    res.status(500).json({ error: 'Không thể tạo tài khoản lúc này.' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const username = typeof req.body.username === 'string'
      ? req.body.username.trim().toLowerCase()
      : '';
    const password = req.body.password;

    if (!username || typeof password !== 'string') {
      return res.status(400).json({
        error: 'Vui lòng nhập tên tài khoản và mật khẩu.'
      });
    }

    const user = await User.findOne({ username });
    if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
      return res.status(401).json({
        error: 'Sai tên tài khoản hoặc mật khẩu.'
      });
    }

    const token = makeToken();
    sessions.set(token, {
      username,
      expiresAt: Date.now() + SESSION_TTL_MS
    });

    res.json({ ok: true, username, token, expiresIn: SESSION_TTL_MS });
  } catch (err) {
    console.error('[Login]', err.message);
    res.status(500).json({ error: 'Không thể đăng nhập lúc này.' });
  }
});

app.post('/api/logout', requireAuth, (req, res) => {
  const token = getToken(req);
  if (token) sessions.delete(token);
  res.json({ ok: true });
});

app.get('/api/me', (req, res) => {
  const username = getSessionUsername(getToken(req));
  res.json(username ? { loggedIn: true, username } : { loggedIn: false });
});

// Lưu dữ liệu nhân vật vào MongoDB Atlas.
app.post('/api/save', requireAuth, async (req, res) => {
  try {
    const { character, data } = req.body || {};

    if (
      !safeCharacterName(character) ||
      !data ||
      typeof data !== 'object' ||
      Array.isArray(data)
    ) {
      return res.status(400).json({ error: 'Dữ liệu lưu không hợp lệ.' });
    }

    const user = await User.findOne({ username: req.username });
    if (!user) {
      return res.status(404).json({ error: 'Không tìm thấy tài khoản.' });
    }

    const saves = user.saves && typeof user.saves === 'object'
      ? user.saves
      : {};

    saves[character.trim()] = data;
    user.saves = saves;
    user.markModified('saves');
    await user.save();

    res.json({ ok: true });
  } catch (err) {
    console.error('[Save]', err.message);
    res.status(500).json({ error: 'Không thể lưu dữ liệu lúc này.' });
  }
});

app.get('/api/save/:char', requireAuth, async (req, res) => {
  try {
    const charName = decodeURIComponent(req.params.char);
    const user = await User.findOne({ username: req.username }).lean();

    if (!user) {
      return res.status(404).json({ error: 'Không tìm thấy tài khoản.' });
    }

    res.json({
      data: user.saves && user.saves[charName]
        ? user.saves[charName]
        : null
    });
  } catch (err) {
    console.error('[Load save]', err.message);
    res.status(500).json({ error: 'Không thể tải dữ liệu lúc này.' });
  }
});

app.delete('/api/save/:char', requireAuth, async (req, res) => {
  try {
    const charName = decodeURIComponent(req.params.char);
    const user = await User.findOne({ username: req.username });

    if (!user) {
      return res.status(404).json({ error: 'Không tìm thấy tài khoản.' });
    }

    const saves = user.saves && typeof user.saves === 'object'
      ? user.saves
      : {};

    delete saves[charName];
    user.saves = saves;
    user.markModified('saves');
    await user.save();

    res.json({ ok: true });
  } catch (err) {
    console.error('[Delete save]', err.message);
    res.status(500).json({ error: 'Không thể xóa dữ liệu lúc này.' });
  }
});

const rooms = new Map();

app.get('/api/rooms', (req, res) => {
  const list = [];
  for (const [id, room] of rooms.entries()) {
    list.push({
      id,
      name: room.name,
      count: room.players.size
    });
  }
  res.json({ rooms: list });
});

function removeSocketFromRoom(socket, pState) {
  const room = rooms.get(pState.room);
  if (!room) return;

  room.players.delete(socket.id);

  if (room.players.size === 0 && pState.room !== 'world') {
    rooms.delete(pState.room);
  } else {
    socket.to(pState.room).emit(
      'feed',
      `${pState.name} đã ngắt kết nối.`
    );
  }
}

io.on('connection', socket => {
  const pState = {
    id: socket.id,
    account: '',
    token: null,
    room: 'world',
    name: 'Khách',
    char: 'Naruto',
    x: 20000,
    y: 20000,
    hp: 100,
    maxHp: 100,
    lvl: 1,
    score: 0,
    face: 1,
    dead: 0,
    gameData: null
  };

  socket.data.rpgPlayer = pState;

  socket.on('join', async data => {
    try {
      data = data && typeof data === 'object' ? data : {};

      pState.name = typeof data.name === 'string'
        ? data.name.slice(0, 24)
        : 'Khách';

      pState.char = safeCharacterName(data.char)
        ? data.char.trim()
        : 'Naruto';

      const token = typeof data.token === 'string'
        ? data.token
        : null;

      const username = getSessionUsername(token);

      pState.token = username ? token : null;
      pState.account = username || '';

      const roomId =
        typeof data.roomId === 'string' && data.roomId.trim()
          ? data.roomId.trim().slice(0, 48)
          : 'world';

      if (rooms.has(pState.room)) {
        rooms.get(pState.room).players.delete(socket.id);

        if (
          rooms.get(pState.room).players.size === 0 &&
          pState.room !== 'world'
        ) {
          rooms.delete(pState.room);
        }
      }

      socket.leave(pState.room);
      pState.room = roomId;

      if (!rooms.has(roomId)) {
        rooms.set(roomId, {
          name: typeof data.roomName === 'string'
            ? data.roomName.slice(0, 48)
            : `Server ${roomId}`,
          players: new Map()
        });
      }

      socket.join(roomId);
      rooms.get(roomId).players.set(socket.id, pState);

      io.to(roomId).emit(
        'feed',
        `${pState.name} đã tham gia Server!`
      );
    } catch (err) {
      console.error('[Socket join]', err.message);
    }
  });

  socket.on('switch_room', data => {
    data = data && typeof data === 'object' ? data : {};

    const roomId =
      typeof data.roomId === 'string' && data.roomId.trim()
        ? data.roomId.trim().slice(0, 48)
        : 'world';

    const roomName =
      typeof data.roomName === 'string'
        ? data.roomName.slice(0, 48)
        : `Server ${roomId}`;

    socket.leave(pState.room);

    if (rooms.has(pState.room)) {
      rooms.get(pState.room).players.delete(socket.id);

      if (
        rooms.get(pState.room).players.size === 0 &&
        pState.room !== 'world'
      ) {
        rooms.delete(pState.room);
      }
    }

    pState.room = roomId;

    if (!rooms.has(roomId)) {
      rooms.set(roomId, {
        name: roomName,
        players: new Map()
      });
    }

    socket.join(roomId);
    rooms.get(roomId).players.set(socket.id, pState);

    io.to(roomId).emit(
      'feed',
      `${pState.name} đã tham gia Server!`
    );
  });

  socket.on('state', st => {
    if (!st || typeof st !== 'object') return;

    const allowed = [
      'name', 'char', 'x', 'y', 'hp', 'maxHp',
      'lvl', 'score', 'face', 'dead', 'gameData'
    ];

    for (const key of allowed) {
      if (!Object.prototype.hasOwnProperty.call(st, key)) continue;

      if (key === 'name' && typeof st[key] === 'string') {
        pState.name = st[key].slice(0, 24);
      } else if (key === 'char' && safeCharacterName(st[key])) {
        pState.char = st[key].trim();
      } else if (
        key === 'gameData' &&
        st[key] &&
        typeof st[key] === 'object' &&
        !Array.isArray(st[key])
      ) {
        pState.gameData = st[key];
      } else if (
        ['x', 'y', 'hp', 'maxHp', 'lvl', 'score', 'face', 'dead']
          .includes(key) &&
        Number.isFinite(Number(st[key]))
      ) {
        pState[key] = Number(st[key]);
      }
    }

    const room = rooms.get(pState.room);
    if (room) room.players.set(socket.id, pState);
  });

  socket.on('fire', projectiles => {
    if (!Array.isArray(projectiles)) return;

    socket.to(pState.room).emit('fire', {
      id: socket.id,
      a: projectiles.slice(0, 100)
    });
  });

  socket.on('died', data => {
    if (data && typeof data.by === 'string' && data.by.length <= 40) {
      io.to(pState.room).emit(
        'feed',
        `${pState.name} bị hạ gục bởi ${data.by}!`
      );
    }
  });

  socket.on('server_chat', data => {
    if (!data || typeof data.message !== 'string') return;

    const message = data.message
      .replace(/[\u0000-\u001f\u007f]/g, '')
      .trim()
      .slice(0, 180);

    if (!message) return;

    io.to(pState.room).emit('server_chat', {
      name: pState.name,
      message,
      at: Date.now()
    });
  });

  // Hệ thống mời đồng minh
  socket.on('ally_invite', data => {
    const targetId =
      data && typeof data.to === 'string' ? data.to : '';

    const target = io.sockets.sockets.get(targetId);
    const targetState = target?.data?.rpgPlayer;

    if (
      !target ||
      !targetState ||
      targetId === socket.id ||
      targetState.room !== pState.room
    ) {
      socket.emit('ally_result', {
        ok: false,
        message: 'Người chơi không còn ở cùng server.'
      });
      return;
    }

    target.emit('ally_invite', {
      from: socket.id,
      name: pState.name
    });
  });

  socket.on('ally_reply', data => {
    const fromId =
      data && typeof data.to === 'string' ? data.to : '';

    const inviter = io.sockets.sockets.get(fromId);
    const inviterState = inviter?.data?.rpgPlayer;

    if (!inviter || !inviterState ||
        inviterState.room !== pState.room) {
      socket.emit('ally_result', {
        ok: false,
        message: 'Người mời đã rời server.'
      });
      return;
    }

    if (data.accept === true) {
      inviter.emit('ally_result', {
        ok: true,
        id: socket.id,
        name: pState.name
      });

      socket.emit('ally_update', {
        id: fromId,
        name: inviterState.name
      });

      io.to(pState.room).emit('system_chat', {
        message: `${pState.name} và ${inviterState.name} đã trở thành đồng minh.`
      });
    } else {
      inviter.emit('ally_result', {
        ok: false,
        message: `${pState.name} đã từ chối lời mời.`
      });
    }
  });

  const syncTimer = setInterval(() => {
    const room = rooms.get(pState.room);

    if (room) {
      socket.emit(
        'players',
        Array.from(room.players.values())
          .filter(player => player.id !== socket.id)
      );
    }
  }, 100);

  socket.on('disconnect', async () => {
    clearInterval(syncTimer);

    try {
      // Tự lưu tiến trình khi ngắt kết nối
      if (
        pState.account &&
        pState.token &&
        getSessionUsername(pState.token) === pState.account &&
        pState.gameData
      ) {
        const user = await User.findOne({
          username: pState.account
        });

        if (user) {
          const saves =
            user.saves && typeof user.saves === 'object'
              ? user.saves
              : {};

          saves[pState.char] = pState.gameData;
          user.saves = saves;
          user.markModified('saves');
          await user.save();

          console.log(
            `[Auto-Save] Đã lưu tiến trình cho ${pState.account}.`
          );
        }
      }
    } catch (err) {
      console.error('[Auto-Save]', err.message);
    }

    removeSocketFromRoom(socket, pState);
  });
});

// Khởi động server và kết nối MongoDB Atlas
async function start() {
  if (!DATABASE_URL) {
    console.error(
      'THIẾU DATABASE_URL: hãy thêm MongoDB Atlas URI trong Render > Environment.'
    );
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
    console.error(
      'Kiểm tra DATABASE_URL, mật khẩu đã URL-encode và Atlas Network Access.'
    );
    process.exit(1);
  }
}

process.on('SIGTERM', async () => {
  console.log('Đang tắt Naruto RPG API...');
  await mongoose.disconnect().catch(() => {});
  server.close(() => process.exit(0));
});

start();
