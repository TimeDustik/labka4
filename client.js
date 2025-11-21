const API_URL = 'http://localhost:3000';

// --- УМНЫЙ FETCH (С авто-обновлением токена) ---
async function authFetch(url, options = {}) {
    // 1. Добавляем текущий Access токен в заголовки
    let accessToken = localStorage.getItem('accessToken');
    
    if (!options.headers) options.headers = {};
    options.headers['Authorization'] = `Bearer ${accessToken}`;

    // 2. Делаем запрос
    let response = await fetch(url, options);

    // 3. Если сервер ответил 403 (Токен протух)
    if (response.status === 403) {
        console.log('⚠️ Access токен протух. Пробуем обновить...');
        
        // 4. Пытаемся получить новый токен
        const newAccessToken = await refreshMyToken();

        if (newAccessToken) {
            // 5. Если удалось - повторяем оригинальный запрос с новым токеном
            console.log('✅ Токен обновлен. Повторяем запрос.');
            options.headers['Authorization'] = `Bearer ${newAccessToken}`;
            response = await fetch(url, options); // Рекурсия (повтор)
        } else {
            // Если обновить не удалось (Refresh тоже протух) - выход
            handleLogout();
        }
    }

    return response;
}

// Функция запроса нового Access токена
async function refreshMyToken() {
    const refreshToken = localStorage.getItem('refreshToken');
    if (!refreshToken) return null;

    try {
        const res = await fetch(`${API_URL}/refresh`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ token: refreshToken })
        });

        if (res.ok) {
            const data = await res.json();
            localStorage.setItem('accessToken', data.accessToken); // Сохраняем новый
            return data.accessToken;
        }
    } catch (e) {
        console.error('Ошибка обновления:', e);
    }
    return null;
}

// --- НАВИГАЦИЯ ---
function switchView(viewName) {
    ['view-login', 'view-register', 'view-profile'].forEach(id => 
        document.getElementById(id).classList.add('hidden')
    );
    document.getElementById(viewName).classList.remove('hidden');
    document.querySelectorAll('.msg-box').forEach(m => m.innerText = '');
}

// --- ОСНОВНЫЕ ФУНКЦИИ ---

async function handleLogin() {
    const u = document.getElementById('login-user').value;
    const p = document.getElementById('login-pass').value;

    try {
        const res = await fetch(`${API_URL}/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username: u, password: p })
        });
        const data = await res.json();

        if (res.ok) {
            // СОХРАНЯЕМ ОБА ТОКЕНА
            localStorage.setItem('accessToken', data.accessToken);
            localStorage.setItem('refreshToken', data.refreshToken);
            localStorage.setItem('username', data.username);
            openProfile(data.username);
        } else {
            document.getElementById('login-msg').innerText = data.message;
        }
    } catch (e) { console.error(e); }
}

async function handleRegister() {
    const u = document.getElementById('reg-user').value;
    const p = document.getElementById('reg-pass').value;

    try {
        const res = await fetch(`${API_URL}/register`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username: u, password: p })
        });
        if (res.ok) {
            alert('OK! Входите.');
            switchView('view-login');
        } else {
            document.getElementById('reg-msg').innerText = (await res.json()).message;
        }
    } catch (e) { console.error(e); }
}

async function openProfile(username) {
    switchView('view-profile');
    document.getElementById('display-username').innerText = username;
    
    // ИСПОЛЬЗУЕМ НАШУ УМНУЮ ФУНКЦИЮ authFetch
    try {
        const res = await authFetch(`${API_URL}/profile`);
        
        if (res.ok) {
            const data = await res.json();
            document.getElementById('secret-container').innerHTML = 
                `ID: ${data.userData.id}<br>Role: ${data.userData.role}<br>Code: ${data.userData.secretCode}`;
        }
    } catch (e) { console.error(e); }
}

async function handleTokenCheck() {
    // Тоже используем authFetch, чтобы проверка сработала даже через 30 сек
    try {
        const res = await authFetch(`${API_URL}/auth-check`);
        const data = await res.json();

        if (res.ok) {
            alert(`✅ ВСЁ ОК!\nСервер: ${data.message}`);
        } else {
            alert(`⛔ ОШИБКА!`);
        }
    } catch (e) { alert('Ошибка сети'); }
}

async function handleLogout() {
    const refreshToken = localStorage.getItem('refreshToken');
    // Сообщаем серверу, чтобы удалил refresh токен из базы
    await fetch(`${API_URL}/logout`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token: refreshToken })
    });

    localStorage.clear();
    switchView('view-login');
}

window.onload = () => {
    const u = localStorage.getItem('username');
    if (u) openProfile(u);
};