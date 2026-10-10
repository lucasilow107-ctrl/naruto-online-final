// server.js
const express = require("express");
const http = require("http");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const mongoose = require("mongoose");
const crypto = require("crypto");
const { Server } = require("socket.io");

const app = express();
const server = http.createServer(app);

const PORT = process.env.PORT || 3000;
const DATABASE_URL = process.env.DATABASE_URL;
const FRONTEND_URL = process.env.FRONTEND_URL || "*";

if (!DATABASE_URL) {
  console.error("❌ Missing DATABASE_URL. Set it in Render Environment.");
  process.exit(1);
}

app.use(cors({
  origin: FRONTEND_URL === "*"
    ? "*"
    : FRONTEND_URL.split(",").map(url => url.trim()),
  methods: ["GET", "POST", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));

app.use(express.json({ limit: "2mb" }));

const io = new Server(server, {
  cors: {
    origin: FRONTEND_URL === "*"
      ? "*"
      : FRONTEND_URL.split(",").map(url => url.trim()),
    methods: ["GET", "POST"],
    credentials: false
  }
});

// ==================== DATABASE ====================

const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true
  },
  password: {
    type: String,
    required: true
  },
  saves: {
    type: mongoose.Schema.Types.Mixed,
    default: {}
  }
}, { timestamps: true });

const User = mongoose.model("User", userSchema);

// Tokens are kept in memory; users may need to log in again after a restart.
const sessions = new Map();
const SESSION_DURATION = 7 * 24 * 60 * 60 * 1000;

function createSession(userId) {
  const token = crypto.randomBytes(32).toString("hex");
  sessions.set(token, {
    userId: String(userId),
    expiresAt: Date.now() + SESSION_DURATION
  });
  return token;
}

function getToken(req) {
  const header = req.headers.authorization || "";
  if (header.startsWith("Bearer ")) {
    return header.slice(7).trim();
  }
  return "";
}

async function authMiddleware(req, res, next) {
  try {
    const token = getToken(req);
    const session = sessions.get(token);

    if (!token || !session || session.expiresAt < Date.now()) {
      if (token) sessions.delete(token);
      return res.status(401).json({
        ok: false,
        error: "Please log in again."
      });
    }

    const user = await User.findById(session.userId);

    if (!user) {
      sessions.delete(token);
      return res.status(401).json({
        ok: false,
        error: "Account not found."
      });
    }

    req.user = user;
    req.token = token;
    next();
  } catch (error) {
    console.error("Authentication error:", error.message);
    res.status(500).json({ ok: false, error: "Authentication failed." });
  }
}

// ==================== API ====================

app.get("/", (req, res) => {
  res.send("Naruto RPG API is running");
});

app.get("/api/health", (req, res) => {
  res.json({
    ok: true,
    service: "Naruto RPG API",
    database: mongoose.connection.readyState === 1
      ? "connected"
      : "disconnected"
  });
});

app.post("/api/register", async (req, res) => {
  try {
    const username = String(req.body.username || "").trim();
    const password = String(req.body.password || "");

    if (!/^[a-zA-Z0-9_-]{3,24}$/.test(username)) {
      return res.status(400).json({
        ok: false,
        error: "Username must be 3-24 characters using letters, numbers, _ or -."
      });
    }

    if (password.length < 6 || password.length > 128) {
      return res.status(400).json({
        ok: false,
        error: "Password must be between 6 and 128 characters."
      });
    }

    const normalized = username.toLowerCase();
    const existing = await User.findOne({ username: normalized });

    if (existing) {
      return res.status(409).json({
        ok: false,
        error: "Username already exists."
      });
    }

    const hashedPassword = await bcrypt.hash(password, 12);

    const user = await User.create({
      username: normalized,
      password: hashedPassword,
      saves: {}
    });

    const token = createSession(user._id);

    return res.status(201).json({
      ok: true,
      username: user.username,
      token,
      expiresIn: SESSION_DURATION
    });
  } catch (error) {
    if (error.code === 11000) {
      return res.status(409).json({
        ok: false,
        error: "Username already exists."
      });
    }

    console.error("Register error:", error);
    return res.status(500).json({
      ok: false,
      error: "Could not register account."
    });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const username = String(req.body.username || "").trim().toLowerCase();
    const password = String(req.body.password || "");

    if (!username || !password) {
      return res.status(400).json({
        ok: false,
        error: "Enter your username and password."
      });
    }

    const user = await User.findOne({ username });

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({
        ok: false,
        error: "Incorrect username or password."
      });
    }

    const token = createSession(user._id);

    return res.json({
      ok: true,
      username: user.username,
      token,
      expiresIn: SESSION_DURATION
    });
  } catch (error) {
    console.error("Login error:", error);
    return res.status(500).json({
      ok: false,
      error: "Could not log in."
    });
  }
});

app.post("/api/logout", (req, res) => {
  const token = getToken(req);
  if (token) sessions.delete(token);

  res.json({ ok: true });
});

app.get("/api/me", authMiddleware, (req, res) => {
  res.json({
    ok: true,
    username: req.user.username
  });
});

app.post("/api/save", authMiddleware, async (req, res) => {
  try {
    const character = String(
      req.body.character || req.body.char || "default"
    ).slice(0, 50);

    const gameData = req.body.gameData ?? req.body.data ?? req.body;

    if (!gameData || typeof gameData !== "object" || Array.isArray(gameData)) {
      return res.status(400).json({
        ok: false,
        error: "Invalid save data."
      });
    }

    req.user.set(`saves.${character}`, gameData);
    req.user.markModified("saves");
    await req.user.save();

    res.json({ ok: true, character });
  } catch (error) {
    console.error("Save error:", error);
    res.status(500).json({
      ok: false,
      error: "Could not save game."
    });
  }
});

app.get("/api/save", authMiddleware, async (req, res) => {
  try {
    const character = String(req.query.character || req.query.char || "default")
      .slice(0, 50);

    res.json({
      ok: true,
      character,
      data: req.user.saves?.[character] ?? null
    });
  } catch (error) {
    console.error("Load save error:", error);
    res.status(500).json({
      ok: false,
      error: "Could not load game."
    });
  }
});

app.get("/api/save/:char", authMiddleware, async (req, res) => {
  try {
    const character = String(req.params.char).slice(0, 50);

    res.json({
      ok: true,
      character,
      data: req.user.saves?.[character] ?? null
    });
  } catch (error) {
    console.error("Load character save error:", error);
    res.status(500).json({
      ok: false,
      error: "Could not load character save."
    });
  }
});

app.delete("/api/save/:char", authMiddleware, async (req, res) => {
  try {
    const character = String(req.params.char).slice(0, 50);

    if (req.user.saves) {
      delete req.user.saves[character];
    }

    req.user.markModified("saves");
    await req.user.save();

    res.json({ ok: true, character });
  } catch (error) {
    console.error("Delete save error:", error);
    res.status(500).json({
      ok: false,
      error: "Could not delete save."
    });
  }
});

// ==================== MULTIPLAYER ====================

const players = new Map();

function safeNumber(value, fallback = 0) {
  const number = Number(value);
  return Number.isFinite(number) ? number : fallback;
}

io.on("connection", socket => {
  socket.on("join", async payload => {
    try {
      payload = payload || {};

      const roomId = String(payload.roomId || payload.room || "konoha")
        .slice(0, 50);

      const character = String(payload.char || "default").slice(0, 50);
      const token = String(payload.token || "");
      const session = sessions.get(token);

      let username = "Guest";
      let userId = null;

      if (session && session.expiresAt > Date.now()) {
        const user = await User.findById(session.userId);

        if (user) {
          username = user.username;
          userId = String(user._id);
        }
      }

      socket.join(roomId);

      const playerState = {
        id: socket.id,
        username,
        userId,
        character,
        roomId,
        x: 0,
        y: 0,
        hp: 100,
        maxHp: 100,
        lvl: 1,
        score: 0,
        face: 1,
        dead: false,
        gameData: userId && payload.gameData &&
          typeof payload.gameData === "object"
          ? payload.gameData
          : null
      };

      players.set(socket.id, playerState);

      socket.emit("joined", {
        ok: true,
        id: socket.id,
        username,
        roomId
      });

      socket.emit("players", Array.from(players.values())
        .filter(player => player.roomId === roomId && player.id !== socket.id));

      socket.to(roomId).emit("playerJoined", playerState);
    } catch (error) {
      console.error("Socket join error:", error);
      socket.emit("errorMessage", "Could not join multiplayer.");
    }
  });

  socket.on("state", data => {
    const player = players.get(socket.id);
    if (!player || !data || typeof data !== "object") return;

    player.x = safeNumber(data.x, player.x);
    player.y = safeNumber(data.y, player.y);
    player.hp = safeNumber(data.hp, player.hp);
    player.maxHp = safeNumber(data.maxHp, player.maxHp);
    player.lvl = safeNumber(data.lvl, player.lvl);
    player.score = safeNumber(data.score, player.score);
    player.face = safeNumber(data.face, player.face);
    player.dead = Boolean(data.dead);

    if (player.userId && data.gameData &&
        typeof data.gameData === "object" &&
        !Array.isArray(data.gameData)) {
      player.gameData = data.gameData;
    }

    socket.to(player.roomId).emit("playerState", player);
  });

  socket.on("fire", data => {
    const player = players.get(socket.id);
    if (!player) return;

    socket.to(player.roomId).emit("fire", {
      id: socket.id,
      data: data || {}
    });
  });

  socket.on("died", data => {
    const player = players.get(socket.id);
    if (!player) return;

    player.dead = true;

    socket.to(player.roomId).emit("playerDied", {
      id: socket.id,
      data: data || {}
    });
  });

  socket.on("disconnect", async () => {
    const player = players.get(socket.id);
    if (!player) return;

    players.delete(socket.id);

    socket.to(player.roomId).emit("playerLeft", {
      id: socket.id
    });

    // Save only when the socket belongs to an authenticated account.
    if (player.userId && player.gameData &&
        typeof player.gameData === "object") {
      try {
        const user = await User.findById(player.userId);

        if (user) {
          user.set(`saves.${player.character}`, player.gameData);
          user.markModified("saves");
          await user.save();
        }
      } catch (error) {
        console.error("Disconnect auto-save error:", error.message);
      }
    }
  });
});

// ==================== START SERVER ====================

async function startServer() {
  try {
    await mongoose.connect(DATABASE_URL, {
      serverSelectionTimeoutMS: 15000
    });

    console.log("✅ MongoDB Atlas connected");

    server.listen(PORT, () => {
      console.log(`✅ Naruto RPG API running on port ${PORT}`);
    });
  } catch (error) {
    console.error("❌ MongoDB connection failed:", error.message);
    process.exit(1);
  }
}

mongoose.connection.on("disconnected", () => {
  console.warn("⚠️ MongoDB disconnected");
});

startServer();
