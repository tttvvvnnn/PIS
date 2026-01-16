const API_URL = 'http://localhost:8000/api/v1'; // Адрес бэкенда

// === ROUTER ===
const routes = {
    '/': 'view-login',
    '/login': 'view-login',
    '/register': 'view-register',
    '/profile': 'view-profile',
    '/verify-email': 'view-verify',
    '/forgot-password': 'view-forgot',
    '/reset-password': 'view-reset'
};

function navigateTo(url) {
    history.pushState(null, null, url);
    router();
}

/*
 * смотрит на текущий адрес (window.location.pathname),
 * находит нужный view-id и убирает у него класс hidden, а всем остальным добавляет
 */
async function router() {
    // Скрываем все views
    document.querySelectorAll('.view').forEach(div => div.classList.add('hidden'));

    // Определяем текущий путь
    let path = window.location.pathname;

    // Если мы на главной и есть токен -> в профиль
    if (path === '/' && localStorage.getItem('access_token')) {
        navigateTo('/profile');
        return;
    }

    // 3. Показываем нужный view
    const viewId = routes[path] || 'view-login';
    const viewElement = document.getElementById(viewId);
    if (viewElement) {
        viewElement.classList.remove('hidden');
    }

    // 4. Логика для конкретных страниц
    updateNav();

    if (path === '/profile') {
        if (!localStorage.getItem('access_token')) {
            navigateTo('/login');
            return;
        }
        loadProfile();
    }

    if (path === '/verify-email') {
        handleVerification();
    }
}

// Перехват кликов по ссылкам (SPA режим)
document.addEventListener("DOMContentLoaded", () => {
    document.body.addEventListener("click", e => {
        if (e.target.matches("[data-link]")) {
            e.preventDefault();
            navigateTo(e.target.href);
        }
    });
    router();
});

window.addEventListener("popstate", router);

// === API HELPER ===
async function apiRequest(endpoint, method = 'GET', body = null, auth = false) {
    const headers = { 'Content-Type': 'application/json' };

    if (auth) {
        const token = localStorage.getItem('access_token');
        headers['Authorization'] = `Bearer ${token}`;
    }

    // FastAPI для логина требует form-data, а не JSON
    let fetchConfig = { method, headers };

    if (endpoint.includes('/auth/login')) {
        delete headers['Content-Type']; // fetch сам поставит boundary
        fetchConfig.body = body; // body это FormData
    } else if (body) {
        fetchConfig.body = JSON.stringify(body);
    }

    try {
        const response = await fetch(`${API_URL}${endpoint}`, fetchConfig);
        const data = await response.json();

        if (!response.ok) {
            // Пытаемся достать сообщение об ошибке красиво
            let errorMsg = data.detail;
            if (typeof errorMsg === 'object') {
                errorMsg = JSON.stringify(errorMsg);
            }
            throw new Error(errorMsg || "Ошибка сервера");
        }
        return data;
    } catch (error) {
        showToast(error.message, true);
        throw error;
    }
}

// === LOGIC ===

// Вход
document.getElementById('login-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const formData = new FormData(e.target);

    try {
        const data = await apiRequest('/auth/login', 'POST', formData);
        localStorage.setItem('access_token', data.access_token);
        localStorage.setItem('refresh_token', data.refresh_token);
        showToast("Успешный вход!");
        navigateTo('/profile');
    } catch (e) {}
});

// Регистрация
document.getElementById('register-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const data = Object.fromEntries(new FormData(e.target));
    // data.role_name = 'user'; // Уберите хардкод, если роль не нужна при регистрации или задается на бэке по умолчанию

    try {
        await apiRequest('/auth/signup', 'POST', data);
        showToast("Аккаунт создан! Проверьте почту.");
        navigateTo('/login');
    } catch (e) {}
});

// Загрузка профиля
async function loadProfile() {
    try {
        const user = await apiRequest('/user/me', 'GET', null, true);

        document.getElementById('p-id').innerText = user.id;
        document.getElementById('p-email').innerText = user.email;
        document.getElementById('p-username').innerText = user.username;
        // Проверка на наличие поля role_name
        document.getElementById('p-role').innerText = user.role_name || user.role_id || "User";
    } catch (e) {
        logout();
    }
}

// Смена имени (username)
document.getElementById('change-username-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const data = Object.fromEntries(new FormData(e.target));
    try {
        await apiRequest('/user/update-username', 'PATCH', data, true);
        showToast("Имя обновлено");
        loadProfile(); // Обновляем данные на экране
    } catch (e) {}
});

// Смена пароля (из профиля)
document.getElementById('change-password-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const data = Object.fromEntries(new FormData(e.target));

    // Проверка совпадения нового пароля
    if (data.password !== data.confirm_password) {
        showToast("Новые пароли не совпадают", true);
        return;
    }

    try {
        // ИСПРАВЛЕНО: путь /user/update-password
        await apiRequest('/user/update-password', 'PATCH', data, true);
        showToast("Пароль успешно обновлен");
        e.target.reset();
    } catch (e) {}
});

// Забыл пароль
document.getElementById('forgot-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const data = Object.fromEntries(new FormData(e.target));

    try {
        await apiRequest('/auth/forgot-password', 'POST', { email: data.email });
        showToast("Ссылка для сброса отправлена на почту!");
    } catch (e) {}
});

// Сброс пароля (по ссылке из почты)
document.getElementById('reset-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const data = Object.fromEntries(new FormData(e.target));

    if (data.password !== data.confirm_password) {
        showToast("Пароли не совпадают!", true);
        return;
    }

    const params = new URLSearchParams(window.location.search);
    // Берем 't' из ссылки (как в Mailpit)
    const token = params.get('t') || params.get('token');

    if (!token) {
        showToast("Ошибка: Неверная ссылка (нет токена)", true);
        return;
    }

    try {
        // Отправляем JSON. Важно передать token, password и confirm_password
        await apiRequest('/auth/reset-password', 'POST', {
            token: token,
            password: data.password,
            confirm_password: data.confirm_password
        });

        showToast("Пароль успешно изменен! Теперь войдите.");
        navigateTo('/login');
    } catch (e) {}
});

// Верификация email
async function handleVerification() {
    const params = new URLSearchParams(window.location.search);
    const token = params.get('t') || params.get('token');
    const messageElement = document.getElementById('verify-message');

    if (!token) {
        messageElement.innerText = "Ошибка: Некорректная ссылка (нет токена).";
        messageElement.style.color = "red";
        return;
    }

    try {
        messageElement.innerText = "Проверяем токен...";
        // Отправляем как JSON { token: "..." }
        await apiRequest('/auth/verify', 'POST', { token: token });

        messageElement.innerText = "Почта успешно подтверждена!";
        messageElement.style.color = "green";
        showToast("Аккаунт активирован! Перенаправляем на вход...");

        setTimeout(() => {
            navigateTo('/login');
        }, 2000);

    } catch (e) {
        console.error(e);
        messageElement.innerText = "Ошибка: " + e.message;
        messageElement.style.color = "red";
    }
}

// Выход
async function logout() {
    try {
        const refresh = localStorage.getItem('refresh_token');
        if (refresh) {
             // Пытаемся сделать "чистый" выход на бэкенде
             await apiRequest('/auth/logout', 'POST', { refresh_token: refresh }, true);
        }
    } catch(e) {
        console.log("Logout error/already logged out");
    } finally {
        localStorage.removeItem('access_token');
        localStorage.removeItem('refresh_token');
        navigateTo('/login');
    }
}

// Навигация (меню)
function updateNav() {
    const nav = document.getElementById('nav-links');
    if (localStorage.getItem('access_token')) {
        nav.innerHTML = `
            <a href="/profile" data-link>Профиль</a>
            <a href="#" onclick="logout(); return false;">Выход</a>
        `;
    } else {
        nav.innerHTML = `
            <a href="/login" data-link>Вход</a>
            <a href="/register" data-link>Регистрация</a>
        `;
    }
}

function showToast(msg, isError = false) {
    const toast = document.getElementById('toast');
    if (!toast) return;
  
    toast.innerText = msg;
  
    // сброс классов состояния
    toast.classList.remove('hidden', 'success', 'error', 'show');
  
    // выставляем состояние + показываем
    toast.classList.add('show', isError ? 'error' : 'success');
  
    // авто-скрытие
    setTimeout(() => toast.classList.remove('show'), 3000);
  }