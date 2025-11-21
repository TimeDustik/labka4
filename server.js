require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// КЛЮЧИ (В реальном проекте они должны быть разными и сложными)
const ACCESS_SECRET = 'access_secret_key_123';
const REFRESH_SECRET = 'refresh_secret_key_789';

app.use(cors());
app.use(bodyParser.json());
app.use(express.static(__dirname));

// --- 1. БАЗА ДАННЫХ ---
const db = new sqlite3.Database('./database.db', (err) => {
    if (err) console.error('Ошибка БД:', err.message);
    else console.log('✅ Підключено до SQLite.');
});

db.serialize(() => {
    // Таблица пользователей
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT
    )`);
    // Таблица для Refresh токенов (Белый список)
    db.run(`CREATE TABLE IF NOT EXISTS refresh_tokens (
        token TEXT PRIMARY KEY
    )`);
});

// --- 2. ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ---
function generateAccessToken(user) {
    // ВАЖНО: Ставим короткое время жизни (30 сек), чтобы ты мог быстро проверить Refresh
    return jwt.sign({ id: user.id, username: user.username }, ACCESS_SECRET, { expiresIn: '30s' });
}

function generateRefreshToken(user) {
    return jwt.sign({ id: user.id, username: user.username }, REFRESH_SECRET, { expiresIn: '7d' });
}

// Middleware проверки Access токена
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.status(401).json({ message: 'Нет токена' });

    jwt.verify(token, ACCESS_SECRET, (err, user) => {
        if (err) {
            // 403 означает, что токен есть, но он просрочен или неверен
            return res.status(403).json({ message: 'Токен недействителен' });
        }
        req.user = user;
        next();
    });
};

// --- 3. МАРШРУТЫ ---

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

// РЕГИСТРАЦИЯ
app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ message: 'Заполните поля' });

    const hashedPassword = await bcrypt.hash(password, 10);
    db.run(`INSERT INTO users (username, password) VALUES (?, ?)`, [username, hashedPassword], function(err) {
        if (err) return res.status(400).json({ message: 'Логин занят' });
        res.status(201).json({ message: 'OK' });
    });
});

// ВХОД (Создает Access + Refresh)
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    db.get(`SELECT * FROM users WHERE username = ?`, [username], async (err, user) => {
        if (err || !user) return res.status(400).json({ message: 'Пользователь не найден' });
        if (!await bcrypt.compare(password, user.password)) return res.status(400).json({ message: 'Неверный пароль' });

        const accessToken = generateAccessToken(user);
        const refreshToken = generateRefreshToken(user);

        // Сохраняем Refresh токен в БД
        db.run(`INSERT INTO refresh_tokens (token) VALUES (?)`, [refreshToken]);

        res.json({ accessToken, refreshToken, username: user.username });
    });
});

// ОБНОВЛЕНИЕ ТОКЕНА (REFRESH)
app.post('/refresh', (req, res) => {
    const { token } = req.body; // Клиент присылает Refresh токен
    if (!token) return res.sendStatus(401);

    // 1. Проверяем, есть ли этот токен в БД
    db.get(`SELECT token FROM refresh_tokens WHERE token = ?`, [token], (err, row) => {
        if (!row) return res.status(403).json({ message: 'Refresh токен отозван или не существует' });

        // 2. Проверяем валидность подписи
        jwt.verify(token, REFRESH_SECRET, (err, user) => {
            if (err) return res.sendStatus(403);

            // 3. Выдаем НОВЫЙ Access токен
            const newAccessToken = generateAccessToken({ id: user.id, username: user.username });
            
            console.log(`🔄 Токен обновлен для: ${user.username}`);
            res.json({ accessToken: newAccessToken });
        });
    });
});

// ВЫХОД (Удаляем Refresh токен)
app.post('/logout', (req, res) => {
    const { token } = req.body;
    db.run(`DELETE FROM refresh_tokens WHERE token = ?`, [token], () => {
        res.sendStatus(204);
    });
});

// ЗАЩИЩЕННЫЙ ПРОФИЛЬ
app.get('/profile', authenticateToken, (req, res) => {
    res.json({ 
        userData: { 
            id: req.user.id, 
            role: 'Admin', 
            secretCode: '777-XXX' 
        } 
    });
});

// ПРОВЕРКА
app.get('/auth-check', authenticateToken, (req, res) => {
    res.json({ message: 'Access токен жив!', user: req.user.username });
});

app.listen(PORT, () => console.log(`Сервер: http://localhost:${PORT}`));