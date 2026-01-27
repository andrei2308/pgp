const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const http = require('http');
const { Server } = require("socket.io");

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
    cors: { origin: "http://localhost:5173", methods: ["GET", "POST"] }
});

const PORT = 3000;
const JWT_SECRET = "super-secret-key-change-in-prod";

// Middleware
app.use(cors());
app.use(express.json());

// --- DATABASE CONNECTION ---
const pool = new Pool({
  user: 'postgres',
  host: 'localhost',      
  database: 'postgres',   
  password: 'secret',    
  port: 5432,
});

// --- REST API: AUTHENTICATION ---

// 1. REGISTER
app.post('/register', async (req, res) => {
    try {
        const { username, password, publicKey, encryptedPrivKey } = req.body;
        
        const salt = await bcrypt.genSalt(10);
        const passwordHash = await bcrypt.hash(password, salt);

        const newUser = await pool.query(
            "INSERT INTO users (username, password_hash, public_key, encrypted_priv_key) VALUES ($1, $2, $3, $4) RETURNING id, username",
            [username, passwordHash, publicKey, encryptedPrivKey]
        );

        res.json(newUser.rows[0]);
    } catch (err) {
        console.error(err.message);
        res.status(500).send("Server Error");
    }
});

// 2. LOGIN
app.post('/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const user = await pool.query("SELECT * FROM users WHERE username = $1", [username]);

        if (user.rows.length === 0) return res.status(401).json("Invalid Creds");

        const validPass = await bcrypt.compare(password, user.rows[0].password_hash);
        if (!validPass) return res.status(401).json("Invalid Creds");

        const token = jwt.sign({ id: user.rows[0].id }, JWT_SECRET, { expiresIn: "1h" });

        res.json({
            token,
            username: user.rows[0].username,
            encryptedPrivKey: user.rows[0].encrypted_priv_key, 
            publicKey: user.rows[0].public_key
        });

    } catch (err) {
        console.error(err.message);
        res.status(500).send("Server Error");
    }
});

app.get('/lookup/:username', async (req, res) => {
    try {
        const { username } = req.params;
        const user = await pool.query("SELECT public_key FROM users WHERE username = $1", [username]);
        
        if (user.rows.length === 0) return res.status(404).json("User not found");
        
        res.json({ publicKey: user.rows[0].public_key });
    } catch (err) {
        res.status(500).send("Server Error");
    }
});

// --- SOCKET.IO: SIGNALING SERVER ---
const onlineUsers = new Map();

io.on('connection', (socket) => {
    console.log('User Connected:', socket.id);

    socket.on('join', (username) => {
        onlineUsers.set(username, socket.id);
        console.log(`${username} is online`);
    });

    socket.on('send_message', ({ to, packet }) => {
        const recipientSocketId = onlineUsers.get(to);
        
        if (recipientSocketId) {
            io.to(recipientSocketId).emit('receive_message', {
                from: socket.id,
                packet: packet   
            });
        } else {
            console.log(`User ${to} is offline. Saving to DB...`);
        }
    });

    socket.on('disconnect', () => {
        for (let [user, id] of onlineUsers.entries()) {
            if (id === socket.id) onlineUsers.delete(user);
        }
        console.log('User Disconnected');
    });
});

server.listen(PORT, () => {
    console.log(`Blind Courier Server running on port ${PORT}`);
});