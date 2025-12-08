// ============================================
// КОНФИГУРАЦИЯ CLOUDFLARE WORKER
// ============================================
const WORKER_URL = 'https://monitoring-widget.evgenstrizh.workers.dev'; // URL воркера

// ============================================
// СИСТЕМА ПРОВЕРКИ ЛИЦЕНЗИИ + ТОКЕНЫ
// ============================================
(async function() {
    const scriptTag = document.currentScript || document.querySelector('script[data-license]');
    const LICENSE_KEY = scriptTag ? scriptTag.getAttribute('data-license') : null;

    if (!LICENSE_KEY) {
        console.error('❌ License key not provided');
        showLicenseError('License key is required', 'Add data-license attribute to script tag');
        throw new Error('License key not provided');
    }

    console.log('🔐 Checking license...');

    // Показываем overlay во время проверки
    const overlay = document.createElement('div');
    overlay.id = 'license-loading-overlay';
    overlay.style.cssText = `
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        z-index: 999999;
        display: flex;
        align-items: center;
        justify-content: center;
        flex-direction: column;
        color: white;
        font-family: system-ui, -apple-system, sans-serif;
    `;
    overlay.innerHTML = `
        <div style="text-align: center;">
            <div style="font-size: 48px; margin-bottom: 20px;">🔐</div>
            <h2 style="margin: 0 0 10px 0; font-size: 24px;">Verifying License...</h2>
            <p style="margin: 0; opacity: 0.8; font-size: 16px;">Please wait</p>
            <div style="margin-top: 30px;">
                <div class="spinner" style="
                    width: 40px;
                    height: 40px;
                    border: 4px solid rgba(255,255,255,0.3);
                    border-top-color: white;
                    border-radius: 50%;
                    animation: spin 1s linear infinite;
                    margin: 0 auto;
                "></div>
            </div>
        </div>
    `;
    document.body.appendChild(overlay);

    // Добавляем анимацию спиннера
    const style = document.createElement('style');
    style.textContent = `
        @keyframes spin {
            to { transform: rotate(360deg); }
        }
    `;
    document.head.appendChild(style);

    try {
        const response = await fetch(`${WORKER_URL}/api/verify-license`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                license_key: LICENSE_KEY,
                domain: window.location.hostname
            })
        });

        const result = await response.json();

        if (!result.valid) {
            console.error('❌ License validation failed:', result.error);
            overlay.remove();
            showLicenseError(result.error || 'Invalid or expired license', 'Contact support for assistance');
            throw new Error('License verification failed');
        }

        console.log('✅ License verified successfully');
        console.log('📦 Client:', result.client_id);

        // Сохраняем токен и информацию о лицензии
        window.LICENSE_INFO = {
            valid: true,
            client_id: result.client_id,
            features: result.features,
            expires_at: result.expires_at,
            token: result.token,
            token_expires_at: Date.now() + (result.expires_in * 1000)
        };

        // Убираем overlay после успешной проверки
        setTimeout(() => {
            overlay.style.opacity = '0';
            overlay.style.transition = 'opacity 0.3s ease';
            setTimeout(() => overlay.remove(), 300);
        }, 500);

        // Запускаем периодическую проверку лицензии (каждые 30 минут)
        startLicenseRevalidation(LICENSE_KEY);

    } catch (error) {
        overlay.remove();

        if (!window.LICENSE_INFO || !window.LICENSE_INFO.valid) {
            console.error('💥 License check error:', error);
            showLicenseError('Connection Error', 'Unable to verify license');
            throw error;
        }
    }
})();

// Показ ошибки лицензии
function showLicenseError(title, message) {
    document.body.innerHTML = `
        <div style="display:flex;align-items:center;justify-content:center;height:100vh;background:#1a1a1a;color:#fff;font-family:Arial,sans-serif;text-align:center;padding:20px;">
            <div>
                <h1 style="font-size:48px;margin:0;color:#ff4444;">⚠️ ${title}</h1>
                <p style="font-size:20px;margin:20px 0;color:#aaa;">${message}</p>
            </div>
        </div>
    `;
}

// Периодическая ре-валидация лицензии
function startLicenseRevalidation(licenseKey) {
    // Проверяем каждые 30 минут
    setInterval(async () => {
        console.log('🔄 Revalidating license...');

        try {
            const response = await fetch(`${WORKER_URL}/api/verify-license`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    license_key: licenseKey,
                    domain: window.location.hostname
                })
            });

            const result = await response.json();

            if (!result.valid) {
                console.error('❌ License no longer valid');
                showLicenseError('License Expired', 'Your license has expired or been revoked');
                return;
            }

            // Обновляем токен
            window.LICENSE_INFO.token = result.token;
            window.LICENSE_INFO.token_expires_at = Date.now() + (result.expires_in * 1000);

            console.log('✅ License revalidated successfully');
        } catch (error) {
            console.error('⚠️ License revalidation failed:', error);
        }
    }, 30 * 60 * 1000); // 30 минут
}

// Получение токена для запросов к воркеру
function getAuthHeaders() {
    // Проверяем готовность лицензии
    if (!window.LICENSE_INFO || !window.LICENSE_INFO.token) {
        console.warn('⏳ License not ready yet, waiting...');
        return null;
    }

    // Проверяем срок действия токена
    if (Date.now() > window.LICENSE_INFO.token_expires_at) {
        console.warn('⚠️ Token expired, please refresh the page');
        return null;
    }

    return {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${window.LICENSE_INFO.token}`
    };
}

// =====================================================
// СИСТЕМА АУТЕНТИФИКАЦИИ
// =====================================================

// Получаем API ключ из конфига для защиты вебхуков
const API_KEY = MonitoringConfigManager.getTechnicalSettings().apiKey;

/**
 * Проверка наличия действительного токена при загрузке страницы
 */
async function checkAuthentication() {
    const token = getAuthToken();

    if (!token) {
        showAuthModal();
        return false;
    }

    // Валидация токена на сервере
    const isValid = await validateToken(token);

    if (!isValid) {
        clearAuthToken();
        showAuthModal();
        return false;
    }

    // Токен валидный - скрываем модальное окно и показываем контент
    hideAuthModal();
    return true;
}

/**
 * Получить токен из localStorage или sessionStorage
 */
function getAuthToken() {
    return localStorage.getItem('authToken') || sessionStorage.getItem('authToken');
}

/**
 * Сохранить токен
 */
function saveAuthToken(token, remember = false) {
    if (remember) {
        localStorage.setItem('authToken', token);
        sessionStorage.removeItem('authToken');
    } else {
        sessionStorage.setItem('authToken', token);
        localStorage.removeItem('authToken');
    }
}

/**
 * Сохранить данные пользователя
 */
function saveUserData(userData, remember = false) {
    const userDataStr = JSON.stringify(userData);
    if (remember) {
        localStorage.setItem('userData', userDataStr);
        sessionStorage.removeItem('userData');
    } else {
        sessionStorage.setItem('userData', userDataStr);
        localStorage.removeItem('userData');
    }
}

/**
 * Удалить токен
 */
function clearAuthToken() {
    localStorage.removeItem('authToken');
    sessionStorage.removeItem('authToken');
    localStorage.removeItem('userData');
    sessionStorage.removeItem('userData');
}

/**
 * Валидация токена на сервере
 */
async function validateToken(token) {
    try {
        const config = MonitoringConfigManager.getTechnicalSettings();
        const url = config.authValidateEndpoint;

        // Проверяем, принадлежит ли URL к webhook доменам из конфига
        const webhookOrigins = getWebhookOrigins();
        const isWebhookUrl = [...webhookOrigins].some(origin => url.startsWith(origin));

        const response = await fetch(url, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`,
                ...(isWebhookUrl && config.apiKey && { 'X-API-Key': config.apiKey })
            }
        });

        const data = await response.json();

       if (data.valid) {
    // Сохраняем данные пользователя (в том же storage, где токен)
    const token = getAuthToken();
    const remember = localStorage.getItem('authToken') === token;
    saveUserData(data.user, remember);
    return true;
}

        return false;
    } catch (error) {
        console.error('Token validation error:', error);
        return false;
    }
}

/**
 * Показать модальное окно логина
 */
function showAuthModal() {
    const authModal = document.getElementById('authModal');
    authModal.classList.remove('hidden');

    // Блокируем контент за модальным окном
    document.body.style.overflow = 'hidden';
    
    // ВАЖНО: Обновляем переводы формы при показе
    updateAuthModalLanguage();

    // Фокус на поле username
    setTimeout(() => {
        document.getElementById('authUsername')?.focus();
    }, 300);
}

/**
 * Обновить язык модального окна авторизации
 */
function updateAuthModalLanguage() {
    // Обновляем все текстовые элементы с data-translate
    document.querySelectorAll('#authModal [data-translate]').forEach(element => {
        const key = element.getAttribute('data-translate');
        const translation = MonitoringConfigManager.getTranslation(key);
        if (translation) {
            element.textContent = translation;
        }
    });
    
    // Обновляем placeholder'ы
    document.querySelectorAll('#authModal [data-translate-placeholder]').forEach(element => {
        const key = element.getAttribute('data-translate-placeholder');
        const translation = MonitoringConfigManager.getTranslation(key);
        if (translation) {
            element.placeholder = translation;
        }
    });
}

/**
 * Скрыть модальное окно логина
 */
function hideAuthModal() {
    const authModal = document.getElementById('authModal');
    authModal.classList.add('hidden');

    // Разблокируем контент
    document.body.style.overflow = '';
}

/**
 * Обработка формы логина
 */
async function handleLogin(event) {
    event.preventDefault();

    const username = document.getElementById('authUsername').value.trim();
    const password = document.getElementById('authPassword').value;
    const rememberMe = document.getElementById('authRememberMe').checked;

    const submitBtn = document.getElementById('authSubmitBtn');
    const submitText = document.getElementById('authSubmitText');
    const submitSpinner = document.getElementById('authSubmitSpinner');
    const errorMessage = document.getElementById('authErrorMessage');
    const errorText = document.getElementById('authErrorText');

    // Показываем загрузку
    submitBtn.disabled = true;
    submitText.style.display = 'none';
    submitSpinner.style.display = 'inline-block';
    errorMessage.style.display = 'none';

    try {
        const config = MonitoringConfigManager.getTechnicalSettings();
        const url = config.authLoginEndpoint;

        // Проверяем, принадлежит ли URL к webhook доменам из конфига
        const webhookOrigins = getWebhookOrigins();
        const isWebhookUrl = [...webhookOrigins].some(origin => url.startsWith(origin));

        const response = await fetch(url, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                ...(isWebhookUrl && config.apiKey && { 'X-API-Key': config.apiKey })
            },
            body: JSON.stringify({ username, password })
        });

        const data = await response.json();

        if (data.success && data.token) {
            // Успешный вход - сохраняем токен
saveAuthToken(data.token, rememberMe);

// Сохраняем данные пользователя
saveUserData(data.user, rememberMe);

            // Показываем успешное уведомление
           showNotification(`✅ ${MonitoringConfigManager.getTranslation('auth.loginSuccess')}`, 'success');

            // Скрываем модальное окно
            hideAuthModal();
            // Добавляем кнопку выхода и имя пользователя
            addLogoutButton();
            showUserInfo();

           // Инициализируем интерфейс
await initializeInterface();

// Загружаем данные дашборда
await loadData();

        } else {
           throw new Error(data.message || MonitoringConfigManager.getTranslation('auth.invalidCredentials'));
        }
    } catch (error) {
        console.error('Login error:', error);

        errorText.textContent = error.message || MonitoringConfigManager.getTranslation('auth.loginError');
        errorMessage.style.display = 'flex';
    } finally {
        // Возвращаем кнопку в исходное состояние
        submitBtn.disabled = false;
        submitText.style.display = 'inline';
        submitSpinner.style.display = 'none';
    }
}

/**
 * Переключение видимости пароля
 */
function togglePasswordVisibility() {
    const passwordInput = document.getElementById('authPassword');
    const toggleIcon = document.getElementById('authPasswordToggleIcon');

    if (passwordInput.type === 'password') {
        passwordInput.type = 'text';
        toggleIcon.textContent = '🙈';
    } else {
        passwordInput.type = 'password';
        toggleIcon.textContent = '👁️';
    }
}

/**
 * Получает уникальные домены (origins) из всех endpoint'ов в конфиге
 */
function getWebhookOrigins() {
    const config = MonitoringConfigManager.getTechnicalSettings();
    const origins = new Set();

    // Собираем все URL из конфига (все поля заканчивающиеся на Endpoint)
    Object.keys(config).forEach(key => {
        if (key.endsWith('Endpoint') && typeof config[key] === 'string') {
            try {
                origins.add(new URL(config[key]).origin);
            } catch (e) { /* игнорируем невалидные URL */ }
        }
    });

    return origins;
}

/**
 * Защищенный fetch с автоматической передачей JWT токена и API ключа
 */
async function authFetch(url, options = {}) {
    const token = getAuthToken();

    if (!token) {
        showAuthModal();
        throw new Error('No authentication token');
    }

    // Проверяем, принадлежит ли URL к одному из наших webhook доменов
    const webhookOrigins = getWebhookOrigins();
    const isWebhookUrl = [...webhookOrigins].some(origin => url.startsWith(origin));

    // Добавляем токен и API ключ в заголовки (API ключ только для webhook'ов из конфига)
    const authOptions = {
        ...options,
        headers: {
            ...(options.headers || {}),
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json',
            ...(isWebhookUrl && API_KEY && { 'X-API-Key': API_KEY })
        }
    };

    try {
        const response = await fetch(url, authOptions);

        // Если 401 Unauthorized - токен истек
        if (response.status === 401) {
            clearAuthToken();
            showAuthModal();
            throw new Error('Session expired');
        }

        return response;
    } catch (error) {
        console.error('Auth fetch error:', error);
        throw error;
    }
}

/**
 * Выход из системы
 */
function logout() {
    if (confirm(MonitoringConfigManager.getTranslation('auth.logoutConfirm'))) {
        // Останавливаем автообновление
        stopAutoRefresh();
        
        // Очищаем токен
        clearAuthToken();
        
        // Показываем уведомление
       showNotification(`👋 ${MonitoringConfigManager.getTranslation('auth.logoutSuccess')}`, 'info');

        // Перезагружаем страницу (покажется модальное окно логина)
        setTimeout(() => {
            window.location.reload();
        }, 500);
    }
}

// =====================================================
// ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
// =====================================================

/**
 * Экранирование HTML для безопасного отображения в атрибутах
 */
function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML.replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

// =====================================================
// УПРАВЛЕНИЕ РОЛЯМИ И ДОСТУПОМ
// =====================================================

/**
 * Получить данные текущего пользователя
 */
function getCurrentUser() {
    const userDataStr = localStorage.getItem('userData') || sessionStorage.getItem('userData');
    if (!userDataStr) return null;
    
    try {
        return JSON.parse(userDataStr);
    } catch (error) {
        console.error('Error parsing user data:', error);
        return null;
    }
}

/**
 * Проверить роль пользователя (иерархическая проверка)
 */
function hasRole(requiredRole) {
    const user = getCurrentUser();
    if (!user || !user.role) return false;
    
    const roles = {
        'viewer': 1,
        'manager': 2,
        'admin': 3
    };
    
    const userLevel = roles[user.role] || 0;
    const requiredLevel = roles[requiredRole] || 0;
    
    return userLevel >= requiredLevel;
}

/**
 * Проверить точное совпадение роли
 */
function hasExactRole(role) {
    const user = getCurrentUser();
    return user && user.role === role;
}

/**
 * Применить ограничения по ролям к интерфейсу
 */
function applyRoleBasedRestrictions() {
    const user = getCurrentUser();
    
    if (!user || !user.role) {
        console.warn('⚠️ User role not found');
        return;
    }
    
    console.log(`👤 Применение ограничений для роли: ${user.role}`);
    
    // ===== ОГРАНИЧЕНИЯ ДЛЯ VIEWER =====
    if (user.role === 'viewer') {
        // Скрываем кнопки AI анализа
        const analysisButtons = document.querySelectorAll('[data-role-required="manager"]');
        analysisButtons.forEach(btn => {
            btn.style.display = 'none';
        });
        
        // Скрываем кнопки отправки в CRM
        const crmButtons = document.querySelectorAll('.crm-send-btn');
        crmButtons.forEach(btn => {
            btn.style.display = 'none';
        });
        
        // Скрываем кнопку экспорта
        const exportBtn = document.getElementById('exportButton');
        if (exportBtn) exportBtn.style.display = 'none';
        
        // Скрываем кнопки действий в таблице
        hideTableActionButtons(['analyze', 'crm', 'delete']);
        
        console.log('✅ Ограничения для Viewer применены');
    }
    
    // ===== ОГРАНИЧЕНИЯ ДЛЯ MANAGER =====
    if (user.role === 'manager') {
        // Скрываем только кнопки удаления
        hideTableActionButtons(['delete']);
        
        // Скрываем настройки
        const settingsBtn = document.getElementById('settingsButton');
        if (settingsBtn) settingsBtn.style.display = 'none';
        
        console.log('✅ Ограничения для Manager применены');
    }
    
    // ===== ADMIN - БЕЗ ОГРАНИЧЕНИЙ =====
    if (user.role === 'admin') {
        console.log('✅ Admin - полный доступ');
    }
}

/**
 * Скрыть кнопки действий в таблице пользователей
 */
function hideTableActionButtons(actionsToHide) {
    // Эта функция будет вызываться после рендеринга таблицы
    // Скрываем кнопки с определенными data-action атрибутами
    actionsToHide.forEach(action => {
        const buttons = document.querySelectorAll(`[data-action="${action}"]`);
        buttons.forEach(btn => {
            btn.style.display = 'none';
        });
    });
}

/**
 * Проверка доступа перед выполнением действия
 */
function checkActionPermission(action) {
    const user = getCurrentUser();
    
    if (!user) {
        const message = `❌ ${MonitoringConfigManager.getTranslation('auth.notAuthorized')}`;
        showNotification(message, 'error');
        return false;
    }
    
    const permissions = {
        'view': ['viewer', 'manager', 'admin'],
        'export': ['manager', 'admin'],
        'analyze': ['manager', 'admin'],
        'crm_send': ['manager', 'admin'],
        'delete': ['admin'],
        'settings': ['admin']
    };
    
    if (!permissions[action] || !permissions[action].includes(user.role)) {
        const orTranslation = MonitoringConfigManager.getTranslation('auth.or');
        const accessDenied = MonitoringConfigManager.getTranslation('auth.accessDenied');
        const requiredRoles = permissions[action].join(orTranslation);
        const message = `❌ ${accessDenied}${requiredRoles}`;
        showNotification(message, 'error');
        return false;
    }
    
    return true;
}

/**
 * Добавить кнопку выхода в header
 */
function addLogoutButton() {
    const headerControls = document.querySelector('.header-controls');

    if (!headerControls) return;

    // Проверяем, что кнопки еще нет
    if (document.querySelector('.logout-btn')) return;

    const logoutBtn = document.createElement('button');
    logoutBtn.className = 'logout-btn';
    logoutBtn.onclick = logout;
    logoutBtn.innerHTML = `
    <span style="font-size: 20px;">🚪</span>
    <span class="logout-text" data-translate="auth.logoutButton">Выход</span>
`;

    headerControls.appendChild(logoutBtn);
}

/**
 * Показать имя пользователя в header
 */
function showUserInfo() {
    const userData = localStorage.getItem('userData') || sessionStorage.getItem('userData');

    if (!userData) return;

    try {
        const user = JSON.parse(userData);
        const headerControls = document.querySelector('.header-controls');

        if (!headerControls || document.querySelector('.user-info')) return;

        const userInfo = document.createElement('div');
        userInfo.className = 'user-info';
        userInfo.style.cssText = `
            display: flex;
            align-items: center;
            gap: 8px;
            background: rgba(255,255,255,0.2);
            padding: 8px 16px;
            border-radius: 30px;
            color: white;
            font-size: 14px;
            font-weight: 500;
        `;
        userInfo.innerHTML = `
            <span style="font-size: 20px;">👤</span>
            <span>${user.username}</span>
        `;

        // Вставляем перед кнопкой выхода
        headerControls.insertBefore(userInfo, headerControls.firstChild);
    } catch (error) {
        console.error('Error showing user info:', error);
    }
}

/**
 * Инициализировать систему аутентификации при загрузке страницы
 */
async function initializeAuthentication() {
    // Добавляем обработчик формы логина
    const loginForm = document.getElementById('authLoginForm');
    if (loginForm) {
        loginForm.addEventListener('submit', handleLogin);
    }

    // Проверяем аутентификацию
    const isAuthenticated = await checkAuthentication();

    if (isAuthenticated) {
        // Добавляем кнопку выхода
        addLogoutButton();

        // Показываем имя пользователя
        showUserInfo();
    }

    return isAuthenticated;
}

/**
 * Улучшенная функция уведомлений
 */
function showNotification(message, type = 'info') {
    // Удаляем предыдущее уведомление если есть
    const existing = document.querySelector('.auth-notification');
    if (existing) {
        existing.remove();
    }

    const notification = document.createElement('div');
    notification.className = 'auth-notification';

    const colors = {
        success: '#10b981',
        error: '#ef4444',
        warning: '#f59e0b',
        info: '#3b82f6'
    };

    const icons = {
        success: '✅',
        error: '❌',
        warning: '⚠️',
        info: 'ℹ️'
    };

    notification.style.cssText = `
        position: fixed;
        top: 80px;
        right: 20px;
        background: white;
        padding: 16px 20px;
        border-radius: 12px;
        box-shadow: 0 10px 30px rgba(0, 0, 0, 0.2);
        z-index: 10002;
        display: flex;
        align-items: center;
        gap: 12px;
        font-weight: 500;
        border-left: 4px solid ${colors[type]};
        animation: slideInRight 0.3s ease-out;
    `;

    notification.innerHTML = `
        <span style="font-size: 20px;">${icons[type]}</span>
        <span style="color: var(--text-primary);">${message}</span>
    `;

    document.body.appendChild(notification);

    // Автоматически удаляем через 3 секунды
    setTimeout(() => {
        notification.style.animation = 'slideOutRight 0.3s ease-in';
        setTimeout(() => notification.remove(), 300);
    }, 3000);
}

// =====================================================
// ОСНОВНОЙ КОД МОНИТОРИНГА
// =====================================================

// Инициализация системы переводов
function initializeTranslations() {
    const lang = MonitoringConfigManager.getLanguage();
    
    // Переводим все элементы с атрибутом data-translate
    document.querySelectorAll('[data-translate]').forEach(element => {
        const key = element.getAttribute('data-translate');
        const translation = MonitoringConfigManager.getTranslation(key);
        if (translation) {
            element.textContent = translation;
        }
    });
    
    // Переводим placeholder'ы
    document.querySelectorAll('[data-translate-placeholder]').forEach(element => {
        const key = element.getAttribute('data-translate-placeholder');
        const translation = MonitoringConfigManager.getTranslation(key);
        if (translation) {
            element.placeholder = translation;
        }
    });
    
    // Переводим tooltips
    document.querySelectorAll('[data-tooltip-translate]').forEach(element => {
        const key = element.getAttribute('data-tooltip-translate');
        const translation = MonitoringConfigManager.getTranslation(key);
        if (translation) {
            element.setAttribute('data-tooltip', translation);
        }
    });
    
    //console.log('✅ Переводы применены для языка:', lang);
}

// Проверка наличия включенных языков
function hasEnabledAnalysisLanguages() {
    const languages = MonitoringConfig.availableAnalysisLanguages;
    if (!languages) return false;
    return Object.values(languages).some(lang => lang.enabled);
}

function hasEnabledResultLanguages() {
    const languages = MonitoringConfig.availableResultLanguages;
    if (!languages) return false;
    return Object.values(languages).some(lang => lang.enabled);
}

// Применение настроек видимости из конфигурации
function applyVisibilitySettings() {
    const displaySettings = MonitoringConfigManager.getDisplaySettings();

    // Фильтры
    Object.keys(displaySettings.filters).forEach(filterName => {
        const elements = document.querySelectorAll(`[data-filter="${filterName}"]`);
        elements.forEach(el => {
            el.style.display = displaySettings.filters[filterName] ? '' : 'none';
        });
    });

    // Управление видимостью кнопок анализа
    const hasResultLangs = hasEnabledResultLanguages();
    const hasAnalysisLangs = hasEnabledAnalysisLanguages();

    // Кнопка выбора языка результата анализа
    const resultLangWrapper = document.getElementById('resultLanguageButtonWrapper');
    if (resultLangWrapper) {
        if (hasResultLangs) {
            resultLangWrapper.style.display = 'flex';
            resultLangWrapper.style.flexDirection = 'column';
        } else {
            resultLangWrapper.style.display = 'none';
        }
    }

    // Кнопка анализа по языку
    const analyzeLangWrapper = document.getElementById('analyzeByLanguageButtonWrapper');
    if (analyzeLangWrapper) {
        if (hasAnalysisLangs) {
            analyzeLangWrapper.style.display = 'flex';
            analyzeLangWrapper.style.flexDirection = 'column';
        } else {
            analyzeLangWrapper.style.display = 'none';
        }
    }

    // Проверяем видимость кнопки refresh
    const refreshBtnVisible = displaySettings.filters.refreshButton;

    // Контейнер всех кнопок - показывать только если хотя бы одна кнопка видима
    const allButtonsContainer = document.getElementById('allButtonsContainer');
    if (allButtonsContainer) {
        const anyButtonVisible = refreshBtnVisible || hasResultLangs || hasAnalysisLangs;
        allButtonsContainer.style.display = anyButtonVisible ? 'flex' : 'none';
    }

    // Карточки статистики
    Object.keys(displaySettings.statsCards).forEach(cardName => {
        const element = document.querySelector(`[data-stat="${cardName}"]`);
        if (element) {
            element.style.display = displaySettings.statsCards[cardName] ? '' : 'none';
        }
    });

    // Графики
    Object.keys(displaySettings.charts).forEach(chartName => {
        const element = document.querySelector(`[data-chart="${chartName}"]`);
        if (element) {
            element.style.display = displaySettings.charts[chartName] ? '' : 'none';
        }
    });

    //console.log('✅ Настройки видимости применены');
}

// Заполнение фильтров конфигураций
function populateConfigurationFilter() {
    const select = document.getElementById('configFilter');
    const configs = MonitoringConfigManager.getEnabledConfigurations();
    const lang = MonitoringConfigManager.getLanguage();
    
    // Очищаем существующие опции (кроме "Все")
    while (select.options.length > 1) {
        select.remove(1);
    }
    
    // Сортируем по order
    const sortedConfigs = Object.entries(configs).sort((a, b) => {
        return a[1].order - b[1].order;
    });
    
    // Добавляем опции
    sortedConfigs.forEach(([key, config]) => {
        const option = document.createElement('option');
        option.value = key;
        option.textContent = `${config.icon} ${config.labels[lang] || config.labels.ru}`;
        select.appendChild(option);
    });
}

// Заполнение фильтров платформ
function populatePlatformFilter() {
    const select = document.getElementById('platformFilter');
    const platforms = MonitoringConfigManager.getEnabledPlatforms();
    const lang = MonitoringConfigManager.getLanguage();
    
    // Очищаем существующие опции (кроме "Все")
    while (select.options.length > 1) {
        select.remove(1);
    }
    
    // Сортируем по order
    const sortedPlatforms = Object.entries(platforms).sort((a, b) => {
        return a[1].order - b[1].order;
    });
    
    // Добавляем опции
    sortedPlatforms.forEach(([key, platform]) => {
        const option = document.createElement('option');
        option.value = key;
        option.textContent = `${platform.icon} ${platform.labels[lang] || platform.labels.ru}`;
        select.appendChild(option);
    });
}

// Заполнение кнопок выбора языка для анализа
function populateLanguageButtons() {
    const container = document.getElementById('languageOptionsContainer');
    const languages = MonitoringConfig.availableAnalysisLanguages;
    const currentLang = MonitoringConfigManager.getLanguage();
    
    // Очищаем контейнер
    container.innerHTML = '';
    
    // Сортируем по order
    const sortedLanguages = Object.entries(languages)
        .filter(([key, lang]) => lang.enabled)
        .sort((a, b) => a[1].order - b[1].order);
    
    // Создаем кнопки
    sortedLanguages.forEach(([langCode, langConfig]) => {
        const button = document.createElement('button');
        button.className = 'language-btn';
        button.onclick = () => analyzeLanguageDialogs(langCode);
        button.innerHTML = `${langConfig.flag} <span>${langConfig.labels[currentLang] || langConfig.labels.en}</span>`;
        container.appendChild(button);
    });
}

// Обновление заголовков таблицы
function updateTableHeaders() {
    const headerRow = document.getElementById('tableHeaderRow');
    const displaySettings = MonitoringConfigManager.getDisplaySettings();
    const translations = MonitoringConfigManager.getTranslation('table.columns');
    
    headerRow.innerHTML = '';
    
    // Список колонок в правильном порядке
    const columns = [
    { key: 'leadScore', sortable: true },
    { key: 'contactName', sortable: true },
    { key: 'contactPhone', sortable: true },
    { key: 'contactEmail', sortable: true },
    { key: 'contactMessengers', sortable: true },
    { key: 'contactCompany', sortable: true },
    { key: 'sessionId', sortable: true },
    { key: 'ipAddress', sortable: true },
    { key: 'country', sortable: true },
    { key: 'city', sortable: true },
    { key: 'platform', sortable: true },
    { key: 'configuration', sortable: true },
    { key: 'startTime', sortable: true },
    { key: 'duration', sortable: true },
    { key: 'messages', sortable: true },
    { key: 'satisfaction', sortable: true },
    { key: 'crmStatus', sortable: true },  // <-- ДОБАВИТЬ ЭТУ СТРОКУ
    { key: 'status', sortable: true },
    { key: 'actions', sortable: false }
];
    
    columns.forEach(column => {
        if (displaySettings.tableColumns[column.key]) {
            const th = document.createElement('th');
            th.textContent = translations[column.key];
            if (column.sortable) {
                th.onclick = () => sortTable(column.key);
                th.style.cursor = 'pointer';
            }
            headerRow.appendChild(th);
        }
    });
}

// Инициализация темы
        const savedTheme = localStorage.getItem('theme') || 'light';
        document.documentElement.setAttribute('data-theme', savedTheme);
        updateThemeIcon(savedTheme);

        // Переключение темы
        function toggleTheme() {
            const currentTheme = document.documentElement.getAttribute('data-theme');
            const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
            
            document.documentElement.setAttribute('data-theme', newTheme);
            localStorage.setItem('theme', newTheme);
            updateThemeIcon(newTheme);
            
            // Перерисовка графиков при смене темы
            setTimeout(() => {
                updateCharts();
            }, 300);
        }

        function updateThemeIcon(theme) {
            const icon = document.getElementById('themeIcon');
            icon.textContent = theme === 'dark' ? '🌙' : '☀️';
        }

// Функция для установки правильных размеров canvas
function setCanvasSize(canvas) {
    const container = canvas.parentElement;
    const containerWidth = container.offsetWidth;
    const canvasWidth = Math.min(containerWidth - 40, 400);
    const canvasHeight = 300;
    
    canvas.style.width = canvasWidth + 'px';
    canvas.style.height = canvasHeight + 'px';
}

        // Фильтруем ошибки от расширений
        window.addEventListener('error', function(e) {
            if (e.message && (
                e.message.includes('Receiving end does not exist') ||
                e.message.includes('Failed to get initial state') ||
                e.message.includes('sender_getProviderState')
            )) {
                e.preventDefault();
                return false;
            }
        });

        window.addEventListener('unhandledrejection', function(e) {
            if (e.reason && e.reason.message && (
                e.reason.message.includes('Receiving end does not exist') ||
                e.reason.message.includes('Failed to get initial state')
            )) {
                e.preventDefault();
                return false;
            }
        });

        // Конфигурация
        const config = MonitoringConfigManager.getTechnicalSettings();
        
// =====================================================
// ФУНКЦИИ ДЛЯ ИНТЕГРАЦИИ С CRM
// =====================================================

// Глобальная переменная для хранения статусов отправки в CRM
let crmSentLeads = {};

// Функция отправки в CRM из карточки клиента
async function sendToCRM(sessionId, webhookUrl = null) {
    // ДОБАВЬ ПРОВЕРКУ:
    if (!checkActionPermission('crm_send')) {
        return;
    }
    
    try {
        // Получаем endpoint из конфигурации
        const config = MonitoringConfigManager.getTechnicalSettings();
        
        // Показываем уведомление о начале процесса
        showNotification(`⏳ ${MonitoringConfigManager.getTranslation('leadScoring.sending')}`, 'info');

        const response = await authFetch(config.sendToCRMEndpoint, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                sessionId: sessionId,
                webhookUrl: webhookUrl || null,
                autoSend: false // ручная отправка
            })
        });
        
        const result = await response.json();
        
        if (result.success) {
            // Сохраняем статус отправки
            crmSentLeads[sessionId] = {
                leadScore: result.leadScore,
                leadTemperature: result.leadTemperature,
                crmLeadId: result.crmLeadId,
                sentAt: new Date()
            };
            
            // Обновляем UI
            updateCRMStatus(sessionId);
            
            // Показываем успешное уведомление
            const tempTranslation = MonitoringConfigManager.getTranslation(`leadScoring.temperature.${result.leadTemperature}`);
const message = MonitoringConfigManager.getTranslation('leadScoring.successMessage')
    .replace('{score}', result.leadScore)
    .replace('{temperature}', tempTranslation);
showNotification(`✅ ${message}`, 'success');
            
            // Если это из карточки клиента, обновляем кнопку
            const sendBtn = document.querySelector('.send-to-crm-btn');
            if (sendBtn) {
                sendBtn.textContent = `✅ ${MonitoringConfigManager.getTranslation('leadScoring.sentToCRM')}`;
                sendBtn.disabled = true;
            }
        } else {
            const errorText = result.error || MonitoringConfigManager.getTranslation('leadScoring.unknownError');
const message = MonitoringConfigManager.getTranslation('leadScoring.errorMessage').replace('{error}', errorText);
showNotification(`❌ ${message}`, 'error');
        }
        
        return result;
    } catch (error) {
        console.error('Ошибка отправки в CRM:', error);
        showNotification('❌ Ошибка отправки в CRM', 'error');
        return { success: false, error: error.message };
    }
}

// Функция для загрузки статусов отправленных в CRM лидов
async function loadCRMStatuses() {
    try {
        const config = MonitoringConfigManager.getTechnicalSettings();
        const response = await authFetch(config.getCRMStatusEndpoint);
        
        // Проверяем статус ответа
        if (!response.ok) {
            console.warn('Не удалось загрузить статусы CRM: HTTP', response.status);
            crmSentLeads = {};
            return;
        }
        
        // Получаем текст ответа
        const text = await response.text();
        
        // Проверяем, что ответ не пустой
        if (!text || text.trim() === '') {
            // Если таблица пуста - это нормально, не пишем ошибку
            crmSentLeads = {};
            return;
        }
        
        // Парсим JSON
        const data = JSON.parse(text);
        
        if (data.statuses && Object.keys(data.statuses).length > 0) {
            crmSentLeads = data.statuses;
            const message = MonitoringConfigManager.getTranslation('crmStatuses.loading').replace('{count}', Object.keys(crmSentLeads).length);
            //console.log('✅', message);
        } else {
            // Таблица пуста - это нормальная ситуация
            crmSentLeads = {};
        }
    } catch (error) {
        console.error('Ошибка загрузки статусов CRM:', error);
        // Устанавливаем пустой объект в случае ошибки
        crmSentLeads = {};
    }
}

// Функция обновления отображения статуса CRM
function updateCRMStatus(sessionId) {
    // Проверяем, что crmSentLeads инициализирован
    if (!crmSentLeads) {
        crmSentLeads = {};
    }
    
    const crmStatus = crmSentLeads[sessionId];
    
    // Обновляем в таблице
    const crmCell = document.querySelector(`[data-session="${sessionId}"] .crm-status`);
    if (crmCell) {
        if (crmStatus) {
            crmCell.innerHTML = `
                <span class="crm-sent-badge ${crmStatus.leadTemperature}">
                    ✅ CRM
                </span>
            `;
        }
    }
}

// Функция отправки с подтверждением
// Функция отправки с подтверждением через модальное окно
window.sendToCRMWithConfirm = async function(sessionId, leadScore, leadTemperature) {
    // Сохраняем данные для последующей отправки
    window.pendingCRMSend = {
        sessionId: sessionId,
        leadScore: leadScore,
        leadTemperature: leadTemperature
    };
    
    // Открываем модальное окно подтверждения
    openCRMConfirm(leadScore, leadTemperature);
};

// Открытие модального окна CRM
function openCRMConfirm(leadScore, leadTemperature) {
    const modal = document.getElementById('crmConfirmModal');
    const title = document.getElementById('crmConfirmTitle');
    const info = document.getElementById('crmConfirmInfo');
    const cancelBtn = document.getElementById('crmCancelBtn');
    const sendBtn = document.getElementById('crmSendBtn');
    
    // Получаем переводы
    const translations = MonitoringConfigManager.getTranslation('crmConfirm');
    const tempTranslation = MonitoringConfigManager.getTranslation(`leadScoring.temperature.${leadTemperature}`);
    
    // Устанавливаем тексты
    title.textContent = translations.title;
    
    const infoText = translations.confirmMessage
        .replace('{temperature}', tempTranslation)
        .replace('{score}', leadScore);
    info.textContent = infoText;
    
    cancelBtn.textContent = translations.cancelButton;
    sendBtn.textContent = translations.sendButton;
    
    // Показываем модальное окно
    modal.style.display = 'flex';
    
    // Добавляем обработчик для закрытия по клику вне окна
    modal.onclick = function(event) {
        if (event.target === modal) {
            closeCRMConfirm(false);
        }
    };
}

// Закрытие модального окна CRM
function closeCRMConfirm(confirmed) {
    const modal = document.getElementById('crmConfirmModal');
    modal.style.display = 'none';
    
    if (!confirmed) {
        // Очищаем данные если отменили
        window.pendingCRMSend = null;
    }
}

// Подтверждение отправки в CRM
async function confirmCRMSend() {
    if (!window.pendingCRMSend) return;
    
    const { sessionId } = window.pendingCRMSend;
    
    // Закрываем модальное окно
    closeCRMConfirm(true);
    
    // Отправляем в CRM
    const result = await sendToCRM(sessionId);
    
    if (result.success) {
        // Обновляем карточку
        closeClientCard();
        setTimeout(() => openClientCard(sessionId), 500);
    }
    
    // Очищаем данные
    window.pendingCRMSend = null;
}

// Функция расчета Lead Score
function getLeadScore(sessionId, contactData, analysisData) {
    // Используем сохраненный score из анализа
    if (analysisData && analysisData.leadScoring && analysisData.leadScoring.score !== undefined) {
        return analysisData.leadScoring.score;
    }
    
    // Fallback на старый расчет если нет данных
    if (!analysisData || !analysisData.emotionalTone) return 0;
    
    // Простой расчет для обратной совместимости
    const satisfaction = analysisData.emotionalTone.satisfaction || 0;
    const hasContacts = (contactData.phone ? 20 : 0) + (contactData.email ? 10 : 0);
    
    return Math.min(100, Math.round((satisfaction * 0.6) + hasContacts));
}

// Функция определения температуры лида
function getLeadTemperature(leadScore, sessionId, analysisData) {
    // Используем сохраненную температуру из анализа
    if (analysisData && analysisData.leadScoring && analysisData.leadScoring.temperature) {
        return analysisData.leadScoring.temperature;
    }
    
    // Определяем по score
    if (leadScore >= 80) return 'hot';
    if (leadScore >= 50) return 'warm';
    return 'cold';
}

// Функция загрузки настроек CRM
async function loadCRMSettings() {
    try {
        const config = MonitoringConfigManager.getTechnicalSettings();
        const response = await authFetch(config.crmSettingsEndpoint);

        if (response.ok) {
            const settings = await response.json();
            //console.log('✅ Настройки CRM загружены:', settings);
            return settings;
        }
    } catch (error) {
        console.error('Ошибка загрузки настроек CRM:', error);
    }
    return null;
}

// Функция обновления настроек CRM
async function updateCRMSettings(settings) {
    try {
        const config = MonitoringConfigManager.getTechnicalSettings();
        const response = await authFetch(config.updateCRMSettingsEndpoint, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(settings)
        });
        
        if (response.ok) {
            showNotification('✅ Настройки CRM сохранены', 'success');
            return true;
        }
    } catch (error) {
        console.error('Ошибка сохранения настроек CRM:', error);
        showNotification('❌ Ошибка сохранения настроек CRM', 'error');
    }
    return false;
}

// =====================================================
// ФУНКЦИИ УПРАВЛЕНИЯ НАСТРОЙКАМИ CRM
// =====================================================

// Глобальная переменная для хранения настроек CRM
let crmSettings = {
    webhookUrl: '',
    autoSendEnabled: false,
    minLeadScore: 80
};

// Загрузка настроек CRM в модальное окно
async function loadCRMSettingsToModal() {
    try {
        const config = MonitoringConfigManager.getTechnicalSettings();
        const response = await authFetch(config.crmSettingsEndpoint);
        
        if (response.ok) {
            const settings = await response.json();
            
            if (settings && settings.length > 0) {
                const crmData = settings[0]; // Первая запись для CRM
                
                // Обновляем глобальную переменную
                crmSettings.webhookUrl = crmData.webhook_url || '';
                crmSettings.autoSendEnabled = crmData.auto_send_enabled || false;
                crmSettings.minLeadScore = crmData.min_lead_score || 80;
                
                // Обновляем UI
                document.getElementById('crmWebhookUrl').value = crmSettings.webhookUrl;
                document.getElementById('crmMinLeadScore').value = crmSettings.minLeadScore;
                document.getElementById('crmAutoSendToggle').classList.toggle('active', crmSettings.autoSendEnabled);
                // Устанавливаем правильное положение переключателя
                const toggle = document.getElementById('crmAutoSendToggle');
                const slider = toggle.querySelector('.toggle-slider');
                if (crmSettings.autoSendEnabled) {
                    slider.style.transform = 'translateX(26px)';
                    toggle.style.background = 'var(--success)';
                } else {
                    slider.style.transform = 'translateX(0)';
                    toggle.style.background = 'var(--border-color)';
                }
                
                //console.log('✅ Настройки CRM загружены:', crmSettings);
            }
        }
    } catch (error) {
        console.error('Ошибка загрузки настроек CRM:', error);
    }
}

// Переключение автоматической отправки
function toggleCRMAutoSend() {
    const toggle = document.getElementById('crmAutoSendToggle');
    const slider = toggle.querySelector('.toggle-slider');
    
    crmSettings.autoSendEnabled = !crmSettings.autoSendEnabled;
    toggle.classList.toggle('active', crmSettings.autoSendEnabled);
    
    // Анимация переключателя
    if (crmSettings.autoSendEnabled) {
        slider.style.transform = 'translateX(26px)';
        toggle.style.background = '#667eea';
    } else {
        slider.style.transform = 'translateX(0)';
        toggle.style.background = 'var(--border-color)';
    }
}

// Сохранение настроек CRM
async function saveCRMSettings() {
    try {
        const config = MonitoringConfigManager.getTechnicalSettings();
        
        // Получаем значения из формы
        crmSettings.webhookUrl = document.getElementById('crmWebhookUrl').value.trim();
        crmSettings.minLeadScore = parseInt(document.getElementById('crmMinLeadScore').value);
        
        // Валидация только если URL не пустой
        if (crmSettings.webhookUrl && crmSettings.webhookUrl.trim() !== '') {
            // Проверяем, что URL выглядит как валидный webhook
            if (!crmSettings.webhookUrl.startsWith('http://') && !crmSettings.webhookUrl.startsWith('https://')) {
                showNotification(`⚠️ ${MonitoringConfigManager.getTranslation('crmSettings.urlMustContain')}`, 'warning');
                return false;
            }
        }

        // Отправляем на сервер
        const response = await authFetch(config.updateCRMSettingsEndpoint, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                webhookUrl: crmSettings.webhookUrl,
                autoSendEnabled: crmSettings.autoSendEnabled,
                minLeadScore: crmSettings.minLeadScore,
                settings: {
                    lastUpdated: new Date().toISOString()
                }
            })
        });
        
        if (response.ok) {
            //console.log('✅ Настройки CRM сохранены');
            return true;
        } else {
            throw new Error('Ошибка сохранения');
        }
    } catch (error) {
        console.error('Ошибка сохранения настроек CRM:', error);
        showNotification(`❌ ${MonitoringConfigManager.getTranslation('crm.sendError')}`, 'error');
        return false;
    }
}

// Тест подключения к CRM
async function testCRMConnection() {
    const resultSpan = document.getElementById('crmTestResult');
    const webhookUrl = document.getElementById('crmWebhookUrl').value.trim();
    
    if (!webhookUrl) {
        resultSpan.innerHTML = `<span style="color: var(--danger);">❌ ${MonitoringConfigManager.getTranslation('crmSettings.specifyUrl')}</span>`;
        return;
    }
    
   resultSpan.innerHTML = `<span style="color: var(--warning);">⏳ ${MonitoringConfigManager.getTranslation('testLead.testing')}</span>`;
    
    try {
        // Создаем тестовый лид
        const testData = {
            fields: {
                TITLE: MonitoringConfigManager.getTranslation('testLead.title'),
NAME: MonitoringConfigManager.getTranslation('testLead.name'),
COMMENTS: MonitoringConfigManager.getTranslation('testLead.comments').replace('{date}', new Date().toLocaleString('ru-RU')),
                SOURCE_ID: "WEB"
            }
        };

        const response = await authFetch(webhookUrl, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(testData)
        });
        
        const result = await response.json();
        
        if (result.result) {
           const successMessage = MonitoringConfigManager.getTranslation('crmSettings.testResultSuccess').replace('{id}', result.result);
resultSpan.innerHTML = `<span style="color: var(--success);">✅ ${successMessage}</span>`;
showNotification(`✅ ${MonitoringConfigManager.getTranslation('testLead.testSuccess')}`, 'success');
        } else {
            throw new Error(result.error_description || 'Неизвестная ошибка');
        }
    } catch (error) {
        console.error('Ошибка тестирования CRM:', error);
        const errorMessage = MonitoringConfigManager.getTranslation('crmSettings.testResultError').replace('{error}', error.message);
resultSpan.innerHTML = `<span style="color: var(--danger);">❌ ${errorMessage}</span>`;
showNotification(`❌ ${MonitoringConfigManager.getTranslation('testLead.connectionError')}`, 'error');
    }
}

// Обновляем функцию openSettingsModal
const originalOpenSettingsModal = window.openSettingsModal;
window.openSettingsModal = function() {
    originalOpenSettingsModal();
    // Загружаем настройки CRM при открытии модального окна
    loadCRMSettingsToModal();
};

// Обновляем функцию saveAllSettings
const originalSaveAllSettings = window.saveAllSettings;
window.saveAllSettings = async function() {
    // Сохраняем настройки CRM только если интеграция включена
    if (MonitoringConfig.crmIntegration.enabled) {
        const crmSaved = await saveCRMSettings();
        
        if (!crmSaved) {
            return; // Если CRM настройки не сохранились, прерываем
        }
    }
    
    // Вызываем оригинальную функцию для сохранения остальных настроек
    await originalSaveAllSettings();
};

      // Глобальные переменные
let allData = [];
let filteredData = [];
let currentPage = 1;
let sortField = 'startTime';
let sortDirection = 'desc';
let serverTimeOffset = 0; // Смещение между временем сервера и клиента
// ДОБАВЬ ЭТУ КОНСТАНТУ СРАЗУ ПОСЛЕ:
const ACTIVE_SESSION_TIMEOUT = 5 * 60 * 1000; // 5 минут в миллисекундах

        // Синхронизация времени с сервером
async function syncServerTime() {
    try {
        const response = await authFetch(config.serverTimeEndpoint);
        const data = await response.json();
        
        const serverTime = new Date(data.serverTime);
        const clientTime = new Date();
        serverTimeOffset = serverTime.getTime() - clientTime.getTime();
        
        /*console.log('Time sync:', {
            serverTime: data.serverTime,
            clientTime: clientTime.toISOString(),
            offsetMs: serverTimeOffset,
            offsetMinutes: (serverTimeOffset / 1000 / 60).toFixed(2)
        });
        */
    } catch (error) {
        console.error('Failed to sync server time:', error);
        serverTimeOffset = 0;
    }
}

// Получить синхронизированное время
function getSyncedTime() {
    return new Date(Date.now() + serverTimeOffset);
}

// =====================================================
// ИНИЦИАЛИЗАЦИЯ ИНТЕРФЕЙСА (вызывается после входа)
// =====================================================
async function initializeInterface() {
    // Применяем переводы
    initializeTranslations();
    
    // Применяем настройки видимости
    applyVisibilitySettings();
    
    // Заполняем фильтры
    populateConfigurationFilter();
    populatePlatformFilter();
    populateLanguageButtons();
    
    // Обновляем заголовки таблицы
    updateTableHeaders();
    
    // Инициализация вкладок если email мониторинг включен
    if (MonitoringConfig.emailMonitoring && MonitoringConfig.emailMonitoring.enabled) {
        document.getElementById('tableTabs').style.display = 'flex';
        initializeEmailTable();
    }
    
    // Применяем тему из конфигурации
    const theme = MonitoringConfig.theme.mode || 'light';
    document.documentElement.setAttribute('data-theme', theme);
    updateThemeIcon(theme);
    
    // Синхронизируем время при загрузке
    await syncServerTime();
    
    // Инициализация savedAnalyses
    if (typeof savedAnalyses === 'undefined') {
        window.savedAnalyses = {};
    }

    // Настройка обработчиков (только если еще не установлены)
    const periodFilter = document.getElementById('periodFilter');
    if (periodFilter && !periodFilter._handlersAttached) {
        periodFilter.addEventListener('change', handlePeriodChange);
        document.getElementById('configFilter').addEventListener('change', applyFilters);
        document.getElementById('platformFilter').addEventListener('change', applyFilters);
        document.getElementById('searchBox').addEventListener('input', applyFilters);
        periodFilter._handlersAttached = true;
    }
    
    // Загружаем дополнительные настройки
    await loadAutoAnalysisSettings();
    await loadSavedAnalyses();
    await loadContactData();
    
    if (MonitoringConfig.crmIntegration.enabled) {
        await loadCRMStatuses();
    }
    
    await loadAnalysisResultLanguage();
  // Запускаем автообновление
    startAutoRefresh();
    // Применяем ограничения по ролям
    applyRoleBasedRestrictions();
}

// =====================================================
// УПРАВЛЕНИЕ АВТООБНОВЛЕНИЕМ
// =====================================================

/**
 * Запуск автообновления данных
 */
function startAutoRefresh() {
    // Проверяем что автообновление еще не запущено
    if (window.autoRefreshInterval) {
        console.log('⚠️ Автообновление уже запущено');
        return;
    }
    
    // Запускаем интервал
    window.autoRefreshInterval = setInterval(async () => {
        try {
            await loadData();
            await loadSavedAnalyses();
            await loadContactData();
            updateTable();
        } catch (error) {
            console.error('❌ Ошибка автообновления:', error);
        }
    }, config.refreshInterval);
    
    console.log('✅ Автообновление запущено (интервал: ' + (config.refreshInterval / 1000) + ' сек)');
}

/**
 * Остановка автообновления
 */
function stopAutoRefresh() {
    if (window.autoRefreshInterval) {
        clearInterval(window.autoRefreshInterval);
        window.autoRefreshInterval = null;
        console.log('🛑 Автообновление остановлено');
    }
}

// =====================================================
// ИНИЦИАЛИЗАЦИЯ
// =====================================================

// Инициализация
document.addEventListener('DOMContentLoaded', async function() {
    // ===== ШАГ 1: ЖДЁМ ПРОВЕРКИ ЛИЦЕНЗИИ =====
    console.log('⏳ Waiting for license verification...');

    let licenseReady = false;
    let attempts = 0;
    const maxAttempts = 50; // 5 секунд (50 * 100ms)

    while (!licenseReady && attempts < maxAttempts) {
        if (window.LICENSE_INFO && window.LICENSE_INFO.valid) {
            licenseReady = true;
            console.log('✅ License ready, continuing initialization...');
            break;
        }
        await new Promise(resolve => setTimeout(resolve, 100));
        attempts++;
    }

    if (!licenseReady) {
        console.error('❌ License verification timeout');
        showLicenseError('Initialization Error', 'License verification took too long. Please refresh the page.');
        return;
    }

    // ===== ШАГ 2: ПРОВЕРЯЕМ JWT АУТЕНТИФИКАЦИЮ =====
    const isAuthenticated = await initializeAuthentication();

    if (!isAuthenticated) {
        // Не авторизованы - останавливаем загрузку данных
        return;
    }

    // ===== ПРОДОЛЖЕНИЕ СУЩЕСТВУЮЩЕГО КОДА =====
    // Применяем переводы
    initializeTranslations();
    
    // Применяем настройки видимости
    applyVisibilitySettings();
    
    // Заполняем фильтры
    populateConfigurationFilter();
    populatePlatformFilter();
    populateLanguageButtons();
    
    // Обновляем заголовки таблицы
    updateTableHeaders();
    // Инициализация вкладок если email мониторинг включен
    if (MonitoringConfig.emailMonitoring && MonitoringConfig.emailMonitoring.enabled) {
        document.getElementById('tableTabs').style.display = 'flex';
        initializeEmailTable();
    }
    
    // Применяем тему из конфигурации
    const theme = MonitoringConfig.theme.mode || 'light';
    document.documentElement.setAttribute('data-theme', theme);
    updateThemeIcon(theme);

    // Создаем элемент брендирования
    createBrandingElement();

    // Синхронизируем время при загрузке
    await syncServerTime();
    
            // Инициализация savedAnalyses
    if (typeof savedAnalyses === 'undefined') {
        window.savedAnalyses = {};
    }

            // Настройка обработчиков
            document.getElementById('periodFilter').addEventListener('change', handlePeriodChange);
            document.getElementById('configFilter').addEventListener('change', applyFilters);
            document.getElementById('platformFilter').addEventListener('change', applyFilters);
            document.getElementById('searchBox').addEventListener('input', applyFilters);

            // Загрузка данных (ждём полной загрузки и отрисовки)
            await loadData();

// Автообновление
startAutoRefresh();
// Перерисовка графиков при изменении размера окна
let resizeTimeout;
window.addEventListener('resize', () => {
    clearTimeout(resizeTimeout);
    resizeTimeout = setTimeout(() => {
        updateCharts();
    }, 250);
});
// Добавляем новую инициализацию
await loadAutoAnalysisSettings();
// Загружаем настройки очистки БД  
await loadSavedAnalyses();
// Загружаем контактные данные
await loadContactData();
// Загружаем статусы CRM только если интеграция включена
if (MonitoringConfig.crmIntegration.enabled) {
    await loadCRMStatuses();
}
// Загружаем язык результатов анализа (добавляем после CRM)
await loadAnalysisResultLanguage();
});

        // Обработка изменения периода
        function handlePeriodChange() {
            const period = document.getElementById('periodFilter').value;
            const customRange = document.getElementById('customDateRange');
            const customRangeEnd = document.getElementById('customDateRangeEnd');
            
            if (period === 'custom') {
                customRange.style.display = 'block';
                customRangeEnd.style.display = 'block';
            } else {
                customRange.style.display = 'none';
                customRangeEnd.style.display = 'none';
            }
            
            applyFilters();
            // Применяем фильтр и к email таблице если она активна
            if (document.getElementById('emailTableContainer') && 
                document.getElementById('emailTableContainer').style.display !== 'none') {
                applyEmailFilters();
            }
        }

        // Загрузка данных
     async function loadData() {
    try {
        const response = await authFetch(config.dataEndpoint);
        if (!response.ok) throw new Error('Ошибка загрузки данных');
        
        const result = await response.json();
        
        //console.log('Loaded data:', result);
        
        // Обработка различных форматов ответа
        if (Array.isArray(result)) {
            allData = result;
        } else if (result.data && Array.isArray(result.data)) {
            allData = result.data;
        } else if (result.sessions && Array.isArray(result.sessions)) {
            allData = result.sessions;
        } else {
            console.warn('Неожиданный формат данных:', result);
            allData = [];
        }
        
        //console.log('All data count:', allData.length);
        
        // ВОТ СЮДА ВСТАВЬТЕ КОД ДЛЯ ОТЛАДКИ:
        const configsInData = [...new Set(allData.map(item => item.configName))];
        //console.log('Available configs in data:', configsInData);

        await applyFilters();  // Ждём фильтрации через воркер
        await updateStats();   // Ждём расчёта статистики через воркер
        updateCharts();        // Теперь данные готовы!
        
    } catch (error) {
        console.error('Ошибка:', error);
        showError('Не удалось загрузить данные. Проверьте подключение.');
    }
}

// Функция для получения актуальной конфигурации сессии
function getSessionCurrentConfig(sessionId) {
    // Находим все записи для этой сессии
    const sessionRecords = allData.filter(item => item.sessionId === sessionId);
    
    if (sessionRecords.length === 0) return 'unknown';
    
    // Сортируем по времени и берем последнюю
    sessionRecords.sort((a, b) => {
        const timeA = new Date(a.timestamp || a.lastActivityTime || a.sessionStartTime);
        const timeB = new Date(b.timestamp || b.lastActivityTime || b.sessionStartTime);
        return timeB - timeA;
    });
    
    return sessionRecords[0].configName || 'unknown';
}

       async function applyFilters() {
    // Быстрая проверка лицензии без ожидания
    if (!window.LICENSE_INFO || !window.LICENSE_INFO.token) {
        console.warn('⏳ License not ready yet, skipping filters');
        return;
    }

    const period = document.getElementById('periodFilter').value;
    const configFilter = document.getElementById('configFilter').value;
    const platformFilter = document.getElementById('platformFilter').value;
    const searchText = document.getElementById('searchBox').value.toLowerCase();

    let startDate = new Date();
    let endDate = new Date();

    if (period === '1h') {
        startDate.setHours(startDate.getHours() - 1);
    } else if (period === '24h') {
        startDate.setHours(startDate.getHours() - 24);
    } else if (period === '7d') {
        startDate.setDate(startDate.getDate() - 7);
    } else if (period === '30d') {
        startDate.setDate(startDate.getDate() - 30);
    } else if (period === 'custom') {
        const customStart = document.getElementById('startDate').value;
        const customEnd = document.getElementById('endDate').value;
        if (customStart) startDate = new Date(customStart);
        if (customEnd) endDate = new Date(customEnd);
    }

    try {
        const headers = getAuthHeaders();
        if (!headers) {
            console.error('❌ Cannot get auth headers');
            showError('Authentication error. Please refresh the page.');
            return;
        }

        const response = await fetch(`${WORKER_URL}/api/process-filters`, {
            method: 'POST',
            headers: headers,
            body: JSON.stringify({
                data: allData,
                filters: {
                    period: period,
                    configFilter: configFilter,
                    platformFilter: platformFilter,
                    searchText: searchText,
                    startDate: startDate.toISOString(),
                    endDate: endDate.toISOString()
                },
                sortConfig: {
                    field: sortField,
                    direction: sortDirection
                },
                returnAll: true
            })
        });

        const result = await response.json();

        if (result.success) {
            filteredData = result.data;
            currentPage = 1;
            updateTable();
            await updateStats();
            updateCharts();  // Обновляем графики после фильтрации
        } else {
            throw new Error(result.error || 'Failed to apply filters');
        }
    } catch (error) {
        console.error('Filter error:', error);
        showError('Failed to apply filters');
    }
}

        // Обновление статистики через воркер
        async function updateStats() {
    try {
        const headers = getAuthHeaders();
        if (!headers) {
            console.warn('⏳ Waiting for license before updating stats...');
            return;
        }

        const response = await fetch(`${WORKER_URL}/api/calculate-stats`, {
            method: 'POST',
            headers: headers,
            body: JSON.stringify({
                data: filteredData,
                currentTime: getSyncedTime().getTime()
            })
        });

        const stats = await response.json();

        if (stats.totalUsers !== undefined) {
            animateValue('totalUsers', 0, stats.totalUsers, 1000);
            animateValue('activeSessions', 0, stats.activeSessions, 1000);
            document.getElementById('totalMessages').textContent = stats.totalMessages;
            document.getElementById('avgSessionTime').textContent = formatDuration(stats.avgSessionTime);
        } else {
            throw new Error(stats.error || 'Stats calculation failed');
        }
    } catch (error) {
        console.error('Stats calculation error:', error);
        showError('Failed to calculate statistics');
    }
}

        // Анимация чисел
        function animateValue(id, start, end, duration) {
            const element = document.getElementById(id);
            if (!element) return;
            
            const range = end - start;
            if (range === 0) {
                element.textContent = end;
                return;
            }
            
            const minTimer = 50;
            let stepTime = Math.abs(Math.floor(duration / range));
            stepTime = Math.max(stepTime, minTimer);
            const startTime = new Date().getTime();
            const endTime = startTime + duration;
            let timer;
            
            function run() {
                const now = new Date().getTime();
                const remaining = Math.max((endTime - now) / duration, 0);
                const value = Math.round(end - (remaining * range));
                element.textContent = value;
                if (value == end) {
                    clearInterval(timer);
                }
            }
            
            timer = setInterval(run, stepTime);
            run();
        }

// Получение иконки платформы
function getPlatformIcon(platform) {
    if (!platform) return '❓';
    
    const normalizedPlatform = platform.toLowerCase();
    const platformConfig = MonitoringConfig.availablePlatforms[normalizedPlatform];
    
    if (platformConfig && platformConfig.icon) {
        return platformConfig.icon;
    }
    
    // Fallback на старые иконки
    const icons = {
        'webchat': '💬',
        'web': '💻',
        'telegram': '✈️',
        'whatsapp': '💚',
        'facebook': '👤',
        'instagram': '📷',
        'viber': '💜',
        'vk': '🔵',
        'slack': '🔷',
        'discord': '🎮',
        'email': '📧',
        'sms': '📨',
        'mobile': '📱',
        'desktop': '💻',
        'pc': '💻',
        'api': '🔌'
    };
    
    return icons[normalizedPlatform] || '❓';
}

// Функция генерации HTML для одной строки таблицы
function generateTableRowHTML(session, displaySettings, statusTranslations, actionTranslations) {
    const isActive = (getSyncedTime() - new Date(session.lastActivity)) < ACTIVE_SESSION_TIMEOUT;
    const status = isActive ? 'active' : 'inactive';
    const statusText = statusTranslations[status];
    
    let cells = '';

    if (displaySettings.tableColumns.leadScore) {
        const contact = userContactsData[session.sessionId];
        const analysisData = savedAnalyses[session.sessionId];
        const leadScore = getLeadScore(session.sessionId, contact || {}, analysisData);
        
        cells += `<td data-field="leadScore" data-session="${session.sessionId}">
            <div class="lead-score-cell">
                <div class="lead-score-indicator ${getLeadTemperature(leadScore)}">
                    ${leadScore}
                </div>
            </div>
        </td>`;
    }
    
    if (displaySettings.tableColumns.contactName) {
        const contact = userContactsData[session.sessionId];
        cells += `<td data-field="contactName">
            <a href="#" onclick="openClientCard('${session.sessionId}'); return false;" 
               style="color: var(--accent-primary); text-decoration: none; font-weight: 600; cursor: pointer; transition: all 0.3s ease;"
               onmouseover="this.style.textDecoration='underline'" 
               onmouseout="this.style.textDecoration='none'">
                ${contact?.name || '<span style="color: var(--text-secondary); font-weight: normal;">—</span>'}
            </a>
        </td>`;
    }

    if (displaySettings.tableColumns.contactPhone) {
        const contact = userContactsData[session.sessionId];
        cells += `<td data-field="contactPhone" class="data-indicator-cell">${contact?.phone ? '<span class="data-check-indicator" title="' + escapeHtml(contact.phone) + '">✓</span>' : '<span class="data-empty-indicator">—</span>'}</td>`;
    }

    if (displaySettings.tableColumns.contactEmail) {
        const contact = userContactsData[session.sessionId];
        cells += `<td data-field="contactEmail" class="data-indicator-cell">${contact?.email ? '<span class="data-check-indicator" title="' + escapeHtml(contact.email) + '">✓</span>' : '<span class="data-empty-indicator">—</span>'}</td>`;
    }

    if (displaySettings.tableColumns.contactMessengers) {
        const contact = userContactsData[session.sessionId];
        cells += `<td data-field="contactMessengers" class="data-indicator-cell">${contact?.messengers ? '<span class="data-check-indicator" title="' + escapeHtml(contact.messengers) + '">✓</span>' : '<span class="data-empty-indicator">—</span>'}</td>`;
    }

    if (displaySettings.tableColumns.contactCompany) {
        const contact = userContactsData[session.sessionId];
        cells += `<td data-field="contactCompany" class="data-indicator-cell">${contact?.company ? '<span class="data-check-indicator" title="' + escapeHtml(contact.company) + '">✓</span>' : '<span class="data-empty-indicator">—</span>'}</td>`;
    }
    
    if (displaySettings.tableColumns.sessionId) {
        cells += `<td data-field="sessionId">${session.sessionId.substring(0, 16)}...</td>`;
    }
    
    if (displaySettings.tableColumns.ipAddress) {
        cells += `<td data-field="ipAddress">${session.ip}</td>`;
    }
    
    if (displaySettings.tableColumns.country) {
        cells += `<td data-field="country">${session.country}</td>`;
    }
    
    if (displaySettings.tableColumns.city) {
        cells += `<td data-field="city">${session.city}</td>`;
    }
    
    if (displaySettings.tableColumns.platform) {
        cells += `<td data-field="platform">
            <span style="font-size: 20px;" title="${session.platform}">
                ${getPlatformIcon(session.platform)}
            </span>
        </td>`;
    }
    
    if (displaySettings.tableColumns.configuration) {
        cells += `<td data-field="configuration" style="font-size: 12px; color: var(--text-secondary);">
            ${session.configName}
        </td>`;
    }
    
    if (displaySettings.tableColumns.startTime) {
        cells += `<td data-field="startTime">${formatDate(session.startTime)}</td>`;
    }
    
    if (displaySettings.tableColumns.duration) {
        cells += `<td data-field="duration">${formatDuration(session.duration)}</td>`;
    }
    
    if (displaySettings.tableColumns.messages) {
        cells += `<td data-field="messages">${session.messages}</td>`;
    }
    
    if (displaySettings.tableColumns.satisfaction) {
        cells += `<td data-field="satisfaction" class="satisfaction-cell" data-session="${session.sessionId}">
            ${savedAnalyses[session.sessionId] ? 
                `<span class="satisfaction-indicator ${
                    savedAnalyses[session.sessionId].satisfactionPercentage >= 70 ? 'satisfaction-high' : 
                    savedAnalyses[session.sessionId].satisfactionPercentage >= 50 ? 'satisfaction-medium' : 
                    'satisfaction-low'
                }">${savedAnalyses[session.sessionId].satisfactionPercentage}%</span>` : 
                '<span style="color: var(--text-secondary);">—</span>'
            }
        </td>`;
    }
    
    if (displaySettings.tableColumns.crmStatus !== false) {
        cells += `<td data-field="crmStatus">
            ${crmSentLeads[session.sessionId] ? 
                `<span class="satisfaction-indicator ${
                    crmSentLeads[session.sessionId].leadScore >= 80 ? 'satisfaction-high' : 
                    crmSentLeads[session.sessionId].leadScore >= 50 ? 'satisfaction-medium' : 
                    'satisfaction-low'
                }" title="Lead Score: ${crmSentLeads[session.sessionId].leadScore}">
                    ✅ CRM
                </span>` : 
                '<span style="color: var(--text-secondary);">—</span>'
            }
        </td>`;
    }
    
    if (displaySettings.tableColumns.status) {
        cells += `<td data-field="status">
            <span class="status-badge status-${status}">
                ${isActive ? '<span class="status-dot"></span>' : ''}
                ${statusText}
            </span>
        </td>`;
    }
    
    if (displaySettings.tableColumns.actions) {
        const actionButtons = displaySettings.tableColumns.actionButtons || {
            viewDialog: true,
            analyze: true,
            viewAnalysis: true,
            extractContacts: true,
            deleteRecord: true  
        };
        
       cells += `<td data-field="actions">
    <div class="action-buttons">
        ${actionButtons.viewDialog ? `
            <button class="view-dialog-btn" onclick="viewDialog('${session.sessionId}')"
                    title="${actionTranslations.viewDialog}">
                📋
            </button>
        ` : ''}
        ${actionButtons.analyze ? `
            <button class="analyze-btn" onclick="analyzeUserDialog('${session.sessionId}', '${session.userName}')"
                    title="${actionTranslations.analyze}">
                🔍
            </button>
        ` : ''}
        ${actionButtons.viewAnalysis ? `
            <button class="view-analysis-btn" id="viewAnalysis_${session.sessionId}" 
                    onclick="viewSavedAnalysis('${session.sessionId}', '${session.userName}')" 
                    style="display: ${savedAnalyses[session.sessionId] ? 'inline-flex' : 'none'};"
                    title="${actionTranslations.viewAnalysis}">
                📊
            </button>
        ` : ''}
        ${actionButtons.extractContacts ? `
            <button class="extract-contacts-btn" onclick="extractContactsForSession('${session.sessionId}')"
                    title="${userContactsData[session.sessionId] && (userContactsData[session.sessionId].name || userContactsData[session.sessionId].phone || userContactsData[session.sessionId].email) ?
                        actionTranslations.updateContacts || actionTranslations.extractContacts :
                        actionTranslations.extractContacts}">
                ${userContactsData[session.sessionId] && (userContactsData[session.sessionId].name || userContactsData[session.sessionId].phone || userContactsData[session.sessionId].email) ?
                    '🔄' : '📇'}
            </button>
        ` : ''}
        ${actionButtons.deleteRecord ? `
            <button class="delete-btn action-btn" onclick="deleteSessionRecord('${session.sessionId}')"
                    title="${actionTranslations.deleteRecord}">
                🗑️
            </button>
        ` : ''}
    </div>
</td>`;
    }
    
    return cells;
}

    function updateTable() {
    const sessions = {};
    const SESSION_TIMEOUT = 30 * 60 * 1000; // 30 минут между визитами
    
    const sessionLastConfigs = {};
    filteredData.forEach(item => {
        const sessionId = item.sessionId;
        if (!sessionId) return;
        
        const itemTime = new Date(item.timestamp || item.sessionStartTime || item.lastActivityTime);
        
        if (!sessionLastConfigs[sessionId] || itemTime > new Date(sessionLastConfigs[sessionId].timestamp)) {
            sessionLastConfigs[sessionId] = {
                configName: item.configName,
                timestamp: item.timestamp || item.sessionStartTime || item.lastActivityTime
            };
        }
    });
    
    filteredData.forEach(item => {
        const sessionId = item.sessionId;
        if (!sessionId) return;
        
        if (!sessions[sessionId]) {
            sessions[sessionId] = {
                sessionId: sessionId,
                ip: item.geo?.ip || item.ip || 'unknown',
                country: item.geo?.country || item.country || 'unknown',
                city: item.geo?.city || item.city || 'unknown',
                startTime: item.sessionStartTime || item.timestamp,
                lastActivity: item.timestamp || item.lastActivityTime,
                messages: 0,
                duration: 0,
                messageTimestamps: [],
                userName: item.userName || MonitoringConfigManager.getTranslation('formatting.guest'),
                platform: item.platform || 'webchat',
                configName: getSessionCurrentConfig(sessionId)
            };
        }
        
        sessions[sessionId].messages = Math.max(
            sessions[sessionId].messages, 
            item.messageCount || item.messages || 0
        );
        sessions[sessionId].lastActivity = item.timestamp || item.lastActivityTime;
        
        // Собираем messageTimestamps
        if (item.messageTimestamps && item.messageTimestamps.length > 0) {
            sessions[sessionId].messageTimestamps = item.messageTimestamps;
        }
        
        sessions[sessionId].configName = sessionLastConfigs[sessionId]?.configName || item.configName || sessions[sessionId].configName;
    });
    
    // Рассчитываем правильную длительность для каждой сессии
    Object.values(sessions).forEach(session => {
        if (session.messageTimestamps && session.messageTimestamps.length > 0) {
            // Преобразуем timestamps в Date объекты
            const timestamps = session.messageTimestamps.map(ts => new Date(ts)).filter(d => !isNaN(d.getTime()));
            
            if (timestamps.length > 0) {
                timestamps.sort((a, b) => a - b);
                
                let totalDuration = 0;
                let currentVisitStart = timestamps[0];
                let lastMessage = timestamps[0];
                
                for (let i = 1; i < timestamps.length; i++) {
                    const currentMessage = timestamps[i];
                    const timeSinceLastMsg = currentMessage - lastMessage;
                    
                    if (timeSinceLastMsg > SESSION_TIMEOUT) {
                        // Закрываем визит
                        const visitDuration = (lastMessage - currentVisitStart) / 1000;
                        totalDuration += Math.max(visitDuration, 60);
                        currentVisitStart = currentMessage;
                    }
                    
                    lastMessage = currentMessage;
                }
                
                // Добавляем последний визит
                const lastVisitDuration = (lastMessage - currentVisitStart) / 1000;
                totalDuration += Math.max(lastVisitDuration, 60);
                
                session.duration = Math.round(totalDuration);
            }
        } else {
            // Fallback: если нет messageTimestamps
            session.duration = 0;
        }
    });
    
    let tableData = Object.values(sessions);
            
    // Сортировка
    tableData.sort((a, b) => {
        // Сначала проверяем активность - активные всегда вверху
        const now = getSyncedTime();
        const aIsActive = (now - new Date(a.lastActivity)) < ACTIVE_SESSION_TIMEOUT;
        const bIsActive = (now - new Date(b.lastActivity)) < ACTIVE_SESSION_TIMEOUT;

        // Если один активный а другой нет - активный выше
        if (aIsActive && !bIsActive) return -1;
        if (!aIsActive && bIsActive) return 1;

        // Если оба в одном статусе - применяем обычную сортировку
        let aVal = a[sortField];
        let bVal = b[sortField];

        if (sortField === 'startTime' || sortField === 'lastActivity') {
            aVal = new Date(aVal).getTime();
            bVal = new Date(bVal).getTime();
        }
        
        if (sortField === 'status') {
          const now = getSyncedTime();
          aVal = (now - new Date(a.lastActivity)) < ACTIVE_SESSION_TIMEOUT ? 1 : 0;
          bVal = (now - new Date(b.lastActivity)) < ACTIVE_SESSION_TIMEOUT ? 1 : 0;
        }
        
        if (sortField === 'satisfaction') {
            aVal = savedAnalyses[a.sessionId] ? savedAnalyses[a.sessionId].satisfactionPercentage : 0;
            bVal = savedAnalyses[b.sessionId] ? savedAnalyses[b.sessionId].satisfactionPercentage : 0;
        }
        
        if (sortField === 'leadScore') {
            const contactA = userContactsData[a.sessionId] || {};
            const contactB = userContactsData[b.sessionId] || {};
            const analysisA = savedAnalyses[a.sessionId];
            const analysisB = savedAnalyses[b.sessionId];
            aVal = getLeadScore(a.sessionId, contactA, analysisA);
            bVal = getLeadScore(b.sessionId, contactB, analysisB);
        }
    
        if (sortField === 'contactName') {
            const contactA = userContactsData[a.sessionId] || {};
            const contactB = userContactsData[b.sessionId] || {};
            aVal = contactA.name || '';
            bVal = contactB.name || '';
        }

        if (sortField === 'contactPhone') {
            const contactA = userContactsData[a.sessionId] || {};
            const contactB = userContactsData[b.sessionId] || {};
            aVal = contactA.phone || '';
            bVal = contactB.phone || '';
        }

        if (sortField === 'contactEmail') {
            const contactA = userContactsData[a.sessionId] || {};
            const contactB = userContactsData[b.sessionId] || {};
            aVal = contactA.email || '';
            bVal = contactB.email || '';
        }

        if (sortField === 'contactMessengers') {
            const contactA = userContactsData[a.sessionId] || {};
            const contactB = userContactsData[b.sessionId] || {};
            aVal = contactA.messengers || '';
            bVal = contactB.messengers || '';
        }

        if (sortField === 'contactCompany') {
            const contactA = userContactsData[a.sessionId] || {};
            const contactB = userContactsData[b.sessionId] || {};
            aVal = contactA.company || '';
            bVal = contactB.company || '';
        }

        if (sortField === 'crmStatus') {
            aVal = crmSentLeads[a.sessionId] ? crmSentLeads[a.sessionId].leadScore : 0;
            bVal = crmSentLeads[b.sessionId] ? crmSentLeads[b.sessionId].leadScore : 0;
        }

        if (sortField === 'country') {
            aVal = a.country || '';
            bVal = b.country || '';
        }

        if (sortField === 'city') {
            aVal = a.city || '';
            bVal = b.city || '';
        }

        if (sortField === 'platform') {
            aVal = a.platform || '';
            bVal = b.platform || '';
        }

        if (sortField === 'configuration') {
            aVal = a.configName || '';
            bVal = b.configName || '';
        }

        if (sortField === 'ipAddress') {
            aVal = a.ip || '';
            bVal = b.ip || '';
        }

        if (sortField === 'messages') {
            aVal = a.messages;
            bVal = b.messages;
        }

        if (sortField === 'duration') {
            aVal = a.duration;
            bVal = b.duration;
        }
        
        if (sortDirection === 'asc') {
            return aVal > bVal ? 1 : -1;
        } else {
            return aVal < bVal ? 1 : -1;
        }
    });
    
    document.querySelectorAll('th').forEach(th => {
        th.classList.remove('sorted-asc', 'sorted-desc');
    });
    const sortedTh = document.querySelector(`th[onclick*="${sortField}"]`);
    if (sortedTh) {
        sortedTh.classList.add(`sorted-${sortDirection}`);
    }
    
   // Пагинация
const startIndex = (currentPage - 1) * config.itemsPerPage;
const endIndex = startIndex + config.itemsPerPage;
const pageData = tableData.slice(startIndex, endIndex);

// AJAX ОБНОВЛЕНИЕ ДЕСКТОПНОЙ ТАБЛИЦЫ
const tbody = document.getElementById('usersTableBody');
const mobileCards = document.getElementById('mobileCards');
const noDataTranslation = MonitoringConfigManager.getTranslation('table.noData');

if (pageData.length === 0) {
    tbody.innerHTML = `
        <tr>
            <td colspan="20" style="text-align: center; padding: 40px; color: var(--text-secondary);">
                ${noDataTranslation}
            </td>
        </tr>
    `;
    mobileCards.innerHTML = `
        <div style="text-align: center; padding: 40px; color: var(--text-secondary);">
            ${noDataTranslation}
        </div>
    `;
    previousTableData = {};
    updatePagination(0);
    return;
}

// Удаляем сообщение "Нет данных" если есть
const noDataRow = tbody.querySelector('tr td[colspan="20"]');
if (noDataRow) {
    noDataRow.parentElement.remove();
}

const displaySettings = MonitoringConfigManager.getDisplaySettings();
const statusTranslations = MonitoringConfigManager.getTranslation('table.status');
const actionTranslations = MonitoringConfigManager.getTranslation('table.actions');

        // Создаем карту текущих данных
        const currentDataMap = {};
        pageData.forEach(session => {
            currentDataMap[session.sessionId] = session;
        });

        // Находим существующие строки
        const existingRows = {};
        tbody.querySelectorAll('tr[data-session-row]').forEach(row => {
            const sessionId = row.getAttribute('data-session-row');
            existingRows[sessionId] = row;
        });

        // 1. Удаляем строки, которых больше нет в данных
        Object.keys(existingRows).forEach(sessionId => {
            if (!currentDataMap[sessionId]) {
                const row = existingRows[sessionId];
                row.classList.add('table-row-removed');
                setTimeout(() => row.remove(), 300);
            }
        });

        // 2. Добавляем новые строки и обновляем существующие
        pageData.forEach((session, index) => {
            const sessionId = session.sessionId;
            const existingRow = existingRows[sessionId];

            if (!existingRow) {
                // Новая строка - создаем и вставляем
                const newRow = document.createElement('tr');
                newRow.setAttribute('data-session-row', sessionId);
                newRow.className = 'table-row-new';
                newRow.innerHTML = generateTableRowHTML(session, displaySettings, statusTranslations, actionTranslations);
                
                // Вставляем в правильную позицию
                const rows = tbody.querySelectorAll('tr[data-session-row]');
                if (index < rows.length) {
                    tbody.insertBefore(newRow, rows[index]);
                } else {
                    tbody.appendChild(newRow);
                }
            } else {
                
                // Существующая строка - проверяем изменения
                const previousData = previousTableData[sessionId];
            
                if (previousData) {
                    // Проверяем каждое поле на изменения
                    const fields = ['leadScore', 'contactName', 'contactPhone', 'contactEmail', 
                                  'contactMessengers', 'contactCompany', 'sessionId', 'ipAddress', 
                                  'country', 'city', 'platform', 'configuration', 'startTime', 
                                  'duration', 'messages', 'satisfaction', 'crmStatus', 'status', 'actions'];
                    
                    fields.forEach(field => {
                        let oldValue, newValue;
                        let forceUpdate = false; // ← ДОБАВЛЕНА ЭТА СТРОКА!
                        
                        if (field === 'leadScore') {
                            const oldContact = previousData.contact || {};
                            const oldAnalysis = previousData.analysis;
                            oldValue = getLeadScore(sessionId, oldContact, oldAnalysis);
                            
                            const newContact = userContactsData[sessionId] || {};
                            const newAnalysis = savedAnalyses[sessionId];
                            newValue = getLeadScore(sessionId, newContact, newAnalysis);
                        } else if (field.startsWith('contact')) {
                            const contactField = field.replace('contact', '').toLowerCase();
                            oldValue = previousData.contact?.[contactField === 'name' ? 'name' : contactField] || '';
                            newValue = userContactsData[sessionId]?.[contactField === 'name' ? 'name' : contactField] || '';
                        } else if (field === 'satisfaction') {
                            oldValue = previousData.analysis?.satisfactionPercentage || 0;
                            newValue = savedAnalyses[sessionId]?.satisfactionPercentage || 0;
                        } else if (field === 'crmStatus') {
                            oldValue = previousData.crmSent ? 'sent' : 'not_sent';
                            newValue = crmSentLeads[sessionId] ? 'sent' : 'not_sent';
                        } else if (field === 'status') {
                            const newActive = (getSyncedTime() - new Date(session.lastActivity)) < ACTIVE_SESSION_TIMEOUT;
                            newValue = newActive ? 'active' : 'inactive';
                            forceUpdate = true;
                            oldValue = 'force_check';
                        } else if (field === 'actions') {
                            // Проверяем изменение контактных данных для обновления кнопки
                            const oldHasContact = previousData.contact && 
                                                 (previousData.contact.name || 
                                                  previousData.contact.phone || 
                                                  previousData.contact.email);
                            const newContact = userContactsData[sessionId];
                            const newHasContact = newContact && 
                                                 (newContact.name || 
                                                  newContact.phone || 
                                                  newContact.email);
                            
                            oldValue = oldHasContact ? 'has_contact' : 'no_contact';
                            newValue = newHasContact ? 'has_contact' : 'no_contact';
                        } else {
                            oldValue = previousData[field];
                            newValue = session[field];
                        }
                        
                        if (forceUpdate || oldValue !== newValue) {
                            const cell = existingRow.querySelector(`td[data-field="${field}"]`);
                            if (cell) {
                                cell.classList.add('cell-updated');
                                setTimeout(() => cell.classList.remove('cell-updated'), 600);
                                
                                // Обновляем содержимое ячейки
                                const tempRow = document.createElement('tr');
                                tempRow.innerHTML = generateTableRowHTML(session, displaySettings, statusTranslations, actionTranslations);
                                const newCell = tempRow.querySelector(`td[data-field="${field}"]`);
                                if (newCell) {
                                    cell.innerHTML = newCell.innerHTML;
                                }
                            }
                        }
                    });
                }
                
                // Проверяем позицию
                const rows = Array.from(tbody.querySelectorAll('tr[data-session-row]'));
                const currentIndex = rows.indexOf(existingRow);
                if (currentIndex !== index && index < rows.length) {
                    tbody.insertBefore(existingRow, rows[index]);
                }
            }
        });

       // Сохраняем текущие данные для следующего сравнения
previousTableData = {};
pageData.forEach(session => {
    previousTableData[session.sessionId] = {
        ...session,
        contact: userContactsData[session.sessionId],
        analysis: savedAnalyses[session.sessionId],
        crmSent: !!crmSentLeads[session.sessionId]
    };
});

// МОБИЛЬНЫЕ КАРТОЧКИ - полная перегенерация
if (pageData.length === 0) {
    mobileCards.innerHTML = `
        <div style="text-align: center; padding: 40px; color: var(--text-secondary);">
            ${noDataTranslation}
        </div>
    `;
} else {
    // Генерируем весь HTML сразу
    const cardsHTML = pageData.map(session => {
        const isActive = (getSyncedTime() - new Date(session.lastActivity)) < ACTIVE_SESSION_TIMEOUT;
        const status = isActive ? 'active' : 'inactive';
        const statusText = statusTranslations[status];
        
        const contactData = userContactsData[session.sessionId] || {};
        const hasContacts = contactData.name || contactData.phone || contactData.email;
        const displayName = contactData.name || session.userName || MonitoringConfigManager.getTranslation('formatting.guest');
        const leadScore = getLeadScore(session.sessionId, contactData, savedAnalyses[session.sessionId]);
        const leadTemp = getLeadTemperature(leadScore);
        const satisfaction = savedAnalyses[session.sessionId]?.satisfactionPercentage || 0;
        const satisfactionClass = satisfaction >= 70 ? 'satisfaction-high' : 
                                 satisfaction >= 50 ? 'satisfaction-medium' : 'satisfaction-low';
        
        const actionButtons = displaySettings.tableColumns.actionButtons || {
            viewDialog: true,
            analyze: true,
            viewAnalysis: true,
            extractContacts: true,
            deleteRecord: true
        };
        
        return `
            <div class="user-card" data-session-card="${session.sessionId}">
                <div class="user-card-header">
                    <div style="display: flex; align-items: center; gap: 15px;">
                        ${displaySettings.tableColumns.leadScore ? `
                            <div class="lead-score-indicator ${leadTemp}">${leadScore}</div>
                        ` : ''}
                        <div>
                            <strong>
                                <a href="#" onclick="openClientCard('${session.sessionId}'); return false;" 
                                   style="color: var(--text-primary); text-decoration: none; cursor: pointer;"
                                   onmouseover="this.style.textDecoration='underline'" 
                                   onmouseout="this.style.textDecoration='none'">
                                    ${displayName}
                                </a>
                            </strong>
                            <div style="font-size: 11px; color: var(--text-secondary); margin-top: 2px;">
                                ID: ${session.sessionId.substring(0, 12)}...
                            </div>
                            ${displaySettings.tableColumns.status ? `
                                <div style="margin-top: 5px;">
                                    <span class="status-badge status-${status}">
                                        ${isActive ? '<span class="status-dot"></span>' : ''}
                                        ${statusText}
                                    </span>
                                </div>
                            ` : ''}
                        </div>
                    </div>
                </div>
                <div class="user-card-info">
                    ${hasContacts ? `
                        <div style="margin-bottom: 10px; padding-bottom: 10px; border-bottom: 1px solid var(--border-color);">
                            ${contactData.phone ? `
                                <div class="info-row">
                                    <span class="info-label">📱</span>
                                    <span class="info-value">${contactData.phone}</span>
                                </div>
                            ` : ''}
                            ${contactData.email ? `
                                <div class="info-row">
                                    <span class="info-label">📧</span>
                                    <span class="info-value">${contactData.email}</span>
                                </div>
                            ` : ''}
                        </div>
                    ` : ''}
                    <div class="info-row">
                        <span class="info-label">🌍</span>
                        <span class="info-value">${session.country}, ${session.city}</span>
                    </div>
                    <div class="info-row">
                        <span class="info-label">${getPlatformIcon(session.platform)}</span>
                        <span class="info-value">${session.platform}</span>
                    </div>
                    <div class="info-row">
                        <span class="info-label">⏱️</span>
                        <span class="info-value">${formatDuration(session.duration)}</span>
                    </div>
                    <div class="info-row">
                        <span class="info-label">💬</span>
                        <span class="info-value">${session.messages} сообщ.</span>
                    </div>
                    ${savedAnalyses[session.sessionId] ? `
                        <div class="info-row">
                            <span class="info-label">😊</span>
                            <span class="info-value">
                                <span class="satisfaction-indicator ${satisfactionClass}">${satisfaction}%</span>
                            </span>
                        </div>
                    ` : ''}
                </div>
                ${displaySettings.tableColumns.actions ? `
                    <div class="user-card-actions">
                        ${actionButtons.viewDialog !== false ? `
                            <button class="view-dialog-btn" onclick="viewDialog('${session.sessionId}')">
                                📋 ${actionTranslations.viewDialog}
                            </button>
                        ` : ''}
                        ${actionButtons.analyze !== false && !savedAnalyses[session.sessionId] ? `
                            <button class="analyze-btn" onclick="analyzeUserDialog('${session.sessionId}', '${displayName}')">
                                🔍 ${actionTranslations.analyze}
                            </button>
                        ` : ''}
                        ${actionButtons.viewAnalysis !== false && savedAnalyses[session.sessionId] ? `
                            <button class="view-analysis-btn" onclick="viewSavedAnalysis('${session.sessionId}', '${displayName}')">
                                📊 ${actionTranslations.viewAnalysis}
                            </button>
                        ` : ''}
                        ${actionButtons.extractContacts !== false ? `
                            <button class="extract-contacts-btn" onclick="extractContactsForSession('${session.sessionId}')">
                                ${hasContacts ? '🔄' : '📇'} ${hasContacts ? (actionTranslations.updateContacts || actionTranslations.extractContacts) : actionTranslations.extractContacts}
                            </button>
                        ` : ''}
                        ${actionButtons.deleteRecord !== false ? `
                            <button class="delete-btn action-btn" onclick="deleteSessionRecord('${session.sessionId}')">
                                🗑️ ${actionTranslations.deleteRecord}
                            </button>
                        ` : ''}
                    </div>
                ` : ''}
            </div>
        `;
    }).join('');
    
    mobileCards.innerHTML = cardsHTML;
}

updatePagination(tableData.length);
}

        // Обновление пагинации
        function updatePagination(totalItems) {
            const totalPages = Math.ceil(totalItems / config.itemsPerPage);
            const pageNumbers = document.getElementById('pageNumbers');
            
            let paginationHTML = '';
            const maxVisiblePages = 5;
            let startPage = Math.max(1, currentPage - Math.floor(maxVisiblePages / 2));
            let endPage = Math.min(totalPages, startPage + maxVisiblePages - 1);
            
            if (endPage - startPage < maxVisiblePages - 1) {
                startPage = Math.max(1, endPage - maxVisiblePages + 1);
            }
            
            for (let i = startPage; i <= endPage; i++) {
                paginationHTML += `
                    <div class="page-number ${i === currentPage ? 'active' : ''}" onclick="goToPage(${i})">
                        ${i}
                    </div>
                `;
            }
            
            pageNumbers.innerHTML = paginationHTML;
            
            document.getElementById('prevPage').disabled = currentPage === 1;
            document.getElementById('nextPage').disabled = currentPage === totalPages || totalPages === 0;
        }

        function goToPage(page) {
            currentPage = page;
            updateTable();
        }

        function changePage(direction) {
            currentPage += direction;
            updateTable();
        }

        // Обновление графиков
        function updateCharts() {
    // Устанавливаем размеры перед рисованием
    setCanvasSize(document.getElementById('activityCanvas'));
    setCanvasSize(document.getElementById('geoCanvas'));
    setCanvasSize(document.getElementById('platformCanvas'));
    
    // Рисуем графики
    drawActivityChart();
    drawGeoChart();
    drawPlatformChart();
}

        // График активности
        function drawActivityChart() {
    const canvas = document.getElementById('activityCanvas');
    const container = canvas.parentElement;
    const ctx = canvas.getContext('2d');
    
    const containerWidth = container.offsetWidth;
    const canvasWidth = Math.min(containerWidth - 40, 400);
    const canvasHeight = 300;
    
    const scale = window.devicePixelRatio;
    canvas.style.width = canvasWidth + 'px';
    canvas.style.height = canvasHeight + 'px';
    canvas.width = canvasWidth * scale;
    canvas.height = canvasHeight * scale;
    ctx.scale(scale, scale);
    
    ctx.clearRect(0, 0, canvasWidth, canvasHeight);
    
    const styles = getComputedStyle(document.documentElement);
    const textColor = styles.getPropertyValue('--text-secondary');
    const borderColor = styles.getPropertyValue('--border-color');
    const accentPrimary = styles.getPropertyValue('--accent-primary');
    const accentSecondary = styles.getPropertyValue('--accent-secondary');
    const cardBg = styles.getPropertyValue('--card-bg');
    
    const hourlyData = {};
    for (let i = 0; i < 24; i++) {
        hourlyData[i] = 0;
    }
    
    filteredData.forEach(item => {
        const timestamp = new Date(item.timestamp || item.sessionStartTime || item.lastActivityTime);
        if (!isNaN(timestamp)) {
            const hour = timestamp.getHours();
            hourlyData[hour] = (hourlyData[hour] || 0) + 1;
        }
    });
    
    const hours = Object.keys(hourlyData).map(h => parseInt(h));
    const values = hours.map(h => hourlyData[h]);
    const maxValue = Math.max(...values, 1);
    
    const padding = 50;
    const chartWidth = canvasWidth - padding * 2;
    const chartHeight = canvasHeight - padding * 2;
    const barWidth = chartWidth / 24;
    
    const bgGradient = ctx.createLinearGradient(0, padding, 0, canvasHeight - padding);
    bgGradient.addColorStop(0, 'rgba(102, 126, 234, 0.03)');
    bgGradient.addColorStop(1, 'rgba(118, 75, 162, 0.03)');
    ctx.fillStyle = bgGradient;
    ctx.fillRect(padding, padding, chartWidth, chartHeight);
    
    ctx.strokeStyle = borderColor;
    ctx.lineWidth = 0.5;
    ctx.setLineDash([5, 5]);
    
    const ySteps = 5;
    for (let i = 0; i <= ySteps; i++) {
        const y = padding + (chartHeight / ySteps) * i;
        const alpha = 1 - (i / ySteps) * 0.5;
        ctx.globalAlpha = alpha;
        ctx.beginPath();
        ctx.moveTo(padding, y);
        ctx.lineTo(canvasWidth - padding, y);
        ctx.stroke();
    }
    ctx.globalAlpha = 1;
    
    ctx.setLineDash([]);
    
    ctx.beginPath();
    ctx.moveTo(padding, canvasHeight - padding);
    
    const points = [];
    hours.forEach((hour) => {
        const value = values[hour];
        const x = padding + (hour * barWidth) + barWidth / 2;
        const y = canvasHeight - padding - (value / maxValue) * chartHeight;
        points.push({x, y, value});
    });
    
    if (points.length > 0) {
        ctx.moveTo(points[0].x, points[0].y);
        
        for (let i = 0; i < points.length - 1; i++) {
            const currentPoint = points[i];
            const nextPoint = points[i + 1];
            const xMid = (currentPoint.x + nextPoint.x) / 2;
            const yMid = (currentPoint.y + nextPoint.y) / 2;
            const cpX1 = (xMid + currentPoint.x) / 2;
            const cpX2 = (xMid + nextPoint.x) / 2;
            
            ctx.quadraticCurveTo(cpX1, currentPoint.y, xMid, yMid);
            ctx.quadraticCurveTo(cpX2, nextPoint.y, nextPoint.x, nextPoint.y);
        }
    }
    
    ctx.lineTo(canvasWidth - padding, canvasHeight - padding);
    ctx.closePath();
    
    const gradient = ctx.createLinearGradient(0, padding, 0, canvasHeight - padding);
    gradient.addColorStop(0, accentPrimary + '50');
    gradient.addColorStop(0.5, accentPrimary + '30');
    gradient.addColorStop(1, accentPrimary + '05');
    ctx.fillStyle = gradient;
    ctx.fill();
    
    ctx.save();
    ctx.shadowColor = accentPrimary;
    ctx.shadowBlur = 15;
    ctx.shadowOffsetY = 0;
    
    ctx.beginPath();
    if (points.length > 0) {
        ctx.moveTo(points[0].x, points[0].y);
        
        for (let i = 0; i < points.length - 1; i++) {
            const currentPoint = points[i];
            const nextPoint = points[i + 1];
            const xMid = (currentPoint.x + nextPoint.x) / 2;
            const yMid = (currentPoint.y + nextPoint.y) / 2;
            const cpX1 = (xMid + currentPoint.x) / 2;
            const cpX2 = (xMid + nextPoint.x) / 2;
            
            ctx.quadraticCurveTo(cpX1, currentPoint.y, xMid, yMid);
            ctx.quadraticCurveTo(cpX2, nextPoint.y, nextPoint.x, nextPoint.y);
        }
    }
    
    ctx.strokeStyle = accentPrimary;
    ctx.lineWidth = 3;
    ctx.lineCap = 'round';
    ctx.lineJoin = 'round';
    ctx.stroke();
    ctx.restore();
    
    points.forEach((point, index) => {
        if (point.value > 0) {
            ctx.save();
            ctx.shadowColor = accentPrimary;
            ctx.shadowBlur = 20;
            
            const pulseSize = 8 + Math.sin(Date.now() / 500 + index) * 2;
            
            ctx.beginPath();
            ctx.arc(point.x, point.y, pulseSize, 0, Math.PI * 2);
            ctx.fillStyle = accentPrimary + '40';
            ctx.fill();
            
            ctx.beginPath();
            ctx.arc(point.x, point.y, 6, 0, Math.PI * 2);
            ctx.fillStyle = cardBg;
            ctx.fill();
            ctx.strokeStyle = accentPrimary;
            ctx.lineWidth = 3;
            ctx.stroke();
            
            ctx.beginPath();
            ctx.arc(point.x, point.y, 3, 0, Math.PI * 2);
            ctx.fillStyle = accentPrimary;
            ctx.fill();
            
            ctx.restore();
        }
    });
    
    ctx.strokeStyle = textColor;
    ctx.lineWidth = 2;
    
    ctx.beginPath();
    ctx.moveTo(padding, canvasHeight - padding);
    ctx.lineTo(canvasWidth - padding, canvasHeight - padding);
    ctx.stroke();
    
    ctx.beginPath();
    ctx.moveTo(padding, padding);
    ctx.lineTo(padding, canvasHeight - padding);
    ctx.stroke();
    
    ctx.fillStyle = textColor;
    ctx.font = '12px system-ui';
    ctx.textAlign = 'center';
    
    for (let hour = 0; hour < 24; hour += 3) {
        const x = padding + (hour * barWidth) + barWidth / 2;
        const y = canvasHeight - padding + 20;
        ctx.fillText(`${hour}:00`, x, y);
    }
    
    ctx.textAlign = 'right';
    ctx.textBaseline = 'middle';
    for (let i = 0; i <= ySteps; i++) {
        const value = Math.round((maxValue / ySteps) * (ySteps - i));
        const y = padding + (chartHeight / ySteps) * i;
        ctx.fillText(value.toString(), padding - 10, y);
    }
    
    ctx.save();
    ctx.translate(15, canvasHeight / 2);
    ctx.rotate(-Math.PI / 2);
    ctx.textAlign = 'center';
    ctx.fillStyle = textColor;
    ctx.font = '14px system-ui';
    ctx.fillText(MonitoringConfigManager.getTranslation('charts.activity.yAxis'), 0, 0);
    ctx.restore();
    
    const currentHour = new Date().getHours();
    const currentValue = hourlyData[currentHour] || 0;
    
    // Компактная горизонтальная легенда справа вверху
    const legendWidth = 150;
    const legendHeight = 45;
    const legendX = canvasWidth - legendWidth - 10;
    const legendY = 5;
    
    const legendGradient = ctx.createLinearGradient(legendX, legendY, legendX + legendWidth, legendY + legendHeight);
    legendGradient.addColorStop(0, 'rgba(102, 126, 234, 0.1)');
    legendGradient.addColorStop(1, 'rgba(118, 75, 162, 0.1)');
    ctx.fillStyle = legendGradient;
    ctx.fillRect(legendX, legendY, legendWidth, legendHeight);
    
    ctx.strokeStyle = accentPrimary + '50';
    ctx.lineWidth = 2;
    ctx.strokeRect(legendX, legendY, legendWidth, legendHeight);
    
    ctx.fillStyle = textColor;
    ctx.font = '10px system-ui';
    ctx.textAlign = 'left';
    ctx.fillText(MonitoringConfigManager.getTranslation('charts.activity.currentHour') + ':', legendX + 10, legendY + 15);
    
    ctx.font = '14px system-ui';
    ctx.fillStyle = accentPrimary;
    ctx.fillText(`${currentHour}:00`, legendX + 10, legendY + 30);
    
    ctx.font = '10px system-ui';
    ctx.fillStyle = textColor;
    ctx.fillText(`${MonitoringConfigManager.getTranslation('charts.activity.events')}: ${currentValue}`, legendX + 70, legendY + 30);
}

        // График географии
       function drawGeoChart() {
    const canvas = document.getElementById('geoCanvas');
    const ctx = canvas.getContext('2d');
    const container = canvas.parentElement;
    
    const containerWidth = container.offsetWidth;
    const canvasWidth = Math.min(containerWidth - 40, 400);
    const canvasHeight = 300;
    
    const scale = window.devicePixelRatio;
    canvas.style.width = canvasWidth + 'px';
    canvas.style.height = canvasHeight + 'px';
    canvas.width = canvasWidth * scale;
    canvas.height = canvasHeight * scale;
    ctx.scale(scale, scale);
    
    const countryData = {};
    filteredData.forEach(item => {
        const country = item.geo?.country || item.country || 'Unknown';
        countryData[country] = (countryData[country] || 0) + 1;
    });
    
    const sortedCountries = Object.entries(countryData)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 5);
    
    ctx.clearRect(0, 0, canvasWidth, canvasHeight);
    
    const styles = getComputedStyle(document.documentElement);
    const textColor = styles.getPropertyValue('--text-primary');
    
    if (sortedCountries.length === 0) {
        ctx.fillStyle = textColor;
        ctx.font = '16px system-ui';
        ctx.textAlign = 'center';
        ctx.fillText(MonitoringConfigManager.getTranslation('charts.geography.noData'), canvasWidth/2, canvasHeight/2);
        return;
    }
    
    const total = sortedCountries.reduce((sum, [_, count]) => sum + count, 0);
    let currentAngle = -Math.PI / 2;
    
    const colors = [
        ['#667eea', '#764ba2'],
        ['#f093fb', '#f5576c'],
        ['#4facfe', '#00f2fe'],
        ['#43e97b', '#38f9d7'],
        ['#fa709a', '#fee140']
    ];
    
    const centerX = canvasWidth / 2;
    const centerY = canvasHeight / 2;
    const radius = 80;
    
    sortedCountries.forEach(([country, count], index) => {
        const angle = (count / total) * 2 * Math.PI;
        
        ctx.save();
        ctx.shadowColor = 'rgba(0, 0, 0, 0.3)';
        ctx.shadowBlur = 15;
        ctx.shadowOffsetX = 3;
        ctx.shadowOffsetY = 3;
        
        ctx.beginPath();
        ctx.moveTo(centerX, centerY);
        ctx.arc(centerX, centerY, radius, currentAngle, currentAngle + angle);
        ctx.closePath();
        
        const gradient = ctx.createLinearGradient(
            centerX - radius, centerY - radius,
            centerX + radius, centerY + radius
        );
        gradient.addColorStop(0, colors[index % colors.length][0]);
        gradient.addColorStop(1, colors[index % colors.length][1]);
        
        ctx.fillStyle = gradient;
        ctx.fill();
        ctx.restore();
        
        ctx.save();
        ctx.strokeStyle = 'rgba(255, 255, 255, 0.3)';
        ctx.lineWidth = 2;
        ctx.shadowColor = 'rgba(255, 255, 255, 0.5)';
        ctx.shadowBlur = 5;
        ctx.stroke();
        ctx.restore();
        
        const labelAngle = currentAngle + angle / 2;
const labelDistance = radius + 45;
const labelX = centerX + Math.cos(labelAngle) * labelDistance;
const labelY = centerY + Math.sin(labelAngle) * labelDistance;

// Убираем фон, оставляем только тень
ctx.save();
ctx.shadowColor = 'rgba(0, 0, 0, 0.9)';
ctx.shadowBlur = 8;
ctx.shadowOffsetX = 0;
ctx.shadowOffsetY = 0;

// Определяем цвет текста в зависимости от темы
const labelColor = styles.getPropertyValue('--text-primary').trim() || '#ffffff';

ctx.fillStyle = labelColor;
ctx.font = 'bold 12px system-ui';
ctx.textAlign = 'center';
ctx.fillText(country, labelX, labelY);

ctx.font = 'bold 11px system-ui';
ctx.fillStyle = labelColor;
ctx.fillText(`${Math.round(count / total * 100)}%`, labelX, labelY + 15);

ctx.restore();

currentAngle += angle;
    });
    
    const centerGradient = ctx.createRadialGradient(centerX, centerY, 0, centerX, centerY, 25);
    centerGradient.addColorStop(0, 'rgba(255, 255, 255, 0.2)');
    centerGradient.addColorStop(1, 'rgba(0, 0, 0, 0.3)');
    
    ctx.beginPath();
    ctx.arc(centerX, centerY, 25, 0, Math.PI * 2);
    ctx.fillStyle = centerGradient;
    ctx.fill();
    
    let legendY = 30;
    sortedCountries.forEach(([country, count], index) => {
        const legendGradient = ctx.createLinearGradient(canvasWidth - 80, legendY, canvasWidth - 68, legendY + 12);
        legendGradient.addColorStop(0, colors[index % colors.length][0]);
        legendGradient.addColorStop(1, colors[index % colors.length][1]);
        
        ctx.fillStyle = legendGradient;
        ctx.fillRect(canvasWidth - 80, legendY, 12, 12);
        
        ctx.strokeStyle = 'rgba(255, 255, 255, 0.3)';
        ctx.lineWidth = 1;
        ctx.strokeRect(canvasWidth - 80, legendY, 12, 12);
        
        ctx.fillStyle = textColor;
        ctx.font = '11px system-ui';
        ctx.textAlign = 'left';
        ctx.fillText(country, canvasWidth - 60, legendY + 10);
        
        legendY += 20;
    });
}

// График распределения по платформам
function drawPlatformChart() {
    const canvas = document.getElementById('platformCanvas');
    const ctx = canvas.getContext('2d');
    const container = canvas.parentElement;
    
    const containerWidth = container.offsetWidth;
    const canvasWidth = Math.min(containerWidth - 40, 400);
    const canvasHeight = 300;
    
    const scale = window.devicePixelRatio;
    canvas.style.width = canvasWidth + 'px';
    canvas.style.height = canvasHeight + 'px';
    canvas.width = canvasWidth * scale;
    canvas.height = canvasHeight * scale;
    ctx.scale(scale, scale);
    
    const platformData = {};
    filteredData.forEach(item => {
        const platform = item.platform || 'webchat';
        platformData[platform] = (platformData[platform] || 0) + 1;
    });
    
    const sortedPlatforms = Object.entries(platformData)
        .sort((a, b) => b[1] - a[1]);
    
    ctx.clearRect(0, 0, canvasWidth, canvasHeight);
    
    const styles = getComputedStyle(document.documentElement);
    const textColor = styles.getPropertyValue('--text-primary');
    
    if (sortedPlatforms.length === 0) {
        ctx.fillStyle = textColor;
        ctx.font = '16px system-ui';
        ctx.textAlign = 'center';
        ctx.fillText(MonitoringConfigManager.getTranslation('charts.platforms.noData'), canvasWidth/2, canvasHeight/2);
        return;
    }
    
    const total = sortedPlatforms.reduce((sum, [_, count]) => sum + count, 0);
    let currentAngle = -Math.PI / 2;
    
    const colors = [
        ['#667eea', '#764ba2'],
        ['#f093fb', '#f5576c'],
        ['#4facfe', '#00f2fe'],
        ['#43e97b', '#38f9d7'],
        ['#fa709a', '#fee140'],
        ['#30cfd0', '#330867'],
        ['#a8edea', '#fed6e3'],
        ['#ff9a9e', '#fecfef']
    ];
    
    const centerX = canvasWidth / 2;
    const centerY = canvasHeight / 2;
    const radius = 80;
    
    sortedPlatforms.forEach(([platform, count], index) => {
        const angle = (count / total) * 2 * Math.PI;
        
        ctx.save();
        ctx.shadowColor = 'rgba(0, 0, 0, 0.3)';
        ctx.shadowBlur = 15;
        ctx.shadowOffsetX = 3;
        ctx.shadowOffsetY = 3;
        
        ctx.beginPath();
        ctx.moveTo(centerX, centerY);
        ctx.arc(centerX, centerY, radius, currentAngle, currentAngle + angle);
        ctx.closePath();
        
        const gradient = ctx.createLinearGradient(
            centerX - radius, centerY - radius,
            centerX + radius, centerY + radius
        );
        gradient.addColorStop(0, colors[index % colors.length][0]);
        gradient.addColorStop(1, colors[index % colors.length][1]);
        
        ctx.fillStyle = gradient;
        ctx.fill();
        ctx.restore();
        
        ctx.save();
        ctx.strokeStyle = 'rgba(255, 255, 255, 0.3)';
        ctx.lineWidth = 2;
        ctx.shadowColor = 'rgba(255, 255, 255, 0.5)';
        ctx.shadowBlur = 5;
        ctx.stroke();
        ctx.restore();
        
        const labelAngle = currentAngle + angle / 2;
const labelDistance = radius + 45;
const labelX = centerX + Math.cos(labelAngle) * labelDistance;
const labelY = centerY + Math.sin(labelAngle) * labelDistance;

const icon = getPlatformIcon(platform);

// Убираем фон, оставляем только тень под текстом
ctx.save();
ctx.shadowColor = 'rgba(0, 0, 0, 0.9)';
ctx.shadowBlur = 8;
ctx.shadowOffsetX = 0;
ctx.shadowOffsetY = 0;

// Определяем цвет текста в зависимости от темы
const labelColor = styles.getPropertyValue('--text-primary').trim() || '#ffffff';

ctx.font = '18px system-ui';
ctx.fillStyle = labelColor;
ctx.textAlign = 'center';
ctx.fillText(icon, labelX, labelY - 8);

ctx.font = 'bold 11px system-ui';
ctx.fillStyle = labelColor;
ctx.fillText(platform, labelX, labelY + 3);

ctx.font = 'bold 10px system-ui';
ctx.fillStyle = labelColor;
ctx.fillText(`${Math.round(count / total * 100)}%`, labelX, labelY + 15);

ctx.restore();

currentAngle += angle;
    });
    
    const centerGradient = ctx.createRadialGradient(centerX, centerY, 0, centerX, centerY, 25);
    centerGradient.addColorStop(0, 'rgba(255, 255, 255, 0.2)');
    centerGradient.addColorStop(1, 'rgba(0, 0, 0, 0.3)');
    
    ctx.beginPath();
    ctx.arc(centerX, centerY, 25, 0, Math.PI * 2);
    ctx.fillStyle = centerGradient;
    ctx.fill();
    
    let legendY = 30;
    sortedPlatforms.slice(0, 5).forEach(([platform, count], index) => {
        const legendGradient = ctx.createLinearGradient(canvasWidth - 80, legendY, canvasWidth - 68, legendY + 12);
        legendGradient.addColorStop(0, colors[index % colors.length][0]);
        legendGradient.addColorStop(1, colors[index % colors.length][1]);
        
        ctx.fillStyle = legendGradient;
        ctx.fillRect(canvasWidth - 80, legendY, 12, 12);
        
        ctx.strokeStyle = 'rgba(255, 255, 255, 0.3)';
        ctx.lineWidth = 1;
        ctx.strokeRect(canvasWidth - 80, legendY, 12, 12);
        
        const icon = getPlatformIcon(platform);
        ctx.fillStyle = textColor;
        ctx.font = '11px system-ui';
        ctx.textAlign = 'left';
        ctx.fillText(icon + ' ' + platform, canvasWidth - 60, legendY + 10);
        
        legendY += 20;
    });
}

        // Вспомогательные функции
        function formatDate(dateString) {
    const date = new Date(dateString);
    const formatting = MonitoringConfigManager.getTranslation('formatting');
    
    if (isNaN(date)) return formatting.unknown || 'Н/Д';
    
    const lang = MonitoringConfigManager.getLanguage();
    const localeMap = {
        'ru': 'ru-RU',
        'en': 'en-US',
        'es': 'es-ES',
        'fr': 'fr-FR',
        'de': 'de-DE',
        'it': 'it-IT',
        'pt': 'pt-PT',
        'zh': 'zh-CN',
        'ja': 'ja-JP',
        'ko': 'ko-KR',
        'ua': 'uk-UA'
    };
    
    return date.toLocaleString(localeMap[lang] || 'ru-RU', {
        day: '2-digit',
        month: '2-digit',
        year: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
    });
}

// 8. ДОБАВЬТЕ ФУНКЦИЮ ДЛЯ СМЕНЫ ЯЗЫКА:
function changeLanguage(newLang) {
    if (MonitoringConfigManager.setLanguage(newLang)) {
        // Обновляем кнопки языков без перезагрузки страницы
        populateLanguageButtons();
        // Перезагружаем страницу для применения нового языка
        location.reload();
    }
}
        function formatDuration(seconds) {
    const formatting = MonitoringConfigManager.getTranslation('formatting');
    
    if (!seconds || seconds < 0) return `0 ${formatting.seconds}`;
    if (seconds < 60) return `${Math.round(seconds)} ${formatting.seconds}`;
    if (seconds < 3600) return `${Math.floor(seconds / 60)} ${formatting.minutes}`;
    return `${Math.floor(seconds / 3600)} ${formatting.hours} ${Math.floor((seconds % 3600) / 60)} ${formatting.minutes}`;
}

        function showError(message) {
    console.error('Dashboard error:', message);
    const container = document.querySelector('.container');
    if (!container) return;
    
    const oldError = document.querySelector('.error');
    if (oldError) oldError.remove();
    
    const errorDiv = document.createElement('div');
    errorDiv.className = 'error';
    errorDiv.style.cssText = `
        background: rgba(239, 68, 68, 0.1);
        color: var(--danger);
        padding: 16px 20px;
        border-radius: 12px;
        margin-bottom: 20px;
        border: 1px solid rgba(239, 68, 68, 0.3);
        display: flex;
        align-items: center;
        gap: 10px;
        animation: slideIn 0.3s ease-out;
    `;
    
    // Используем переведенное сообщение если оно есть в errors
    const translatedMessage = MonitoringConfigManager.getTranslation(`errors.${message}`) || message;
    errorDiv.innerHTML = `<span style="font-size: 20px;">⚠️</span> ${translatedMessage}`;
    container.insertBefore(errorDiv, container.firstChild);
    
    setTimeout(() => errorDiv.remove(), 5000);
}

        // Сортировка таблицы
        function sortTable(field) {
            if (sortField === field) {
                sortDirection = sortDirection === 'asc' ? 'desc' : 'asc';
            } else {
                sortField = field;
                sortDirection = 'desc';
            }
            
            updateTable();
        }

        // Обновление данных
        function refreshData() {
            const btn = document.querySelector('.refresh-btn');
            btn.classList.add('loading');
            loadData().then(() => {
                btn.classList.remove('loading');
            });
        }

        // Экспорт данных
function exportData() {
    // ДОБАВЬ ПРОВЕРКУ:
    if (!checkActionPermission('export')) {
        return;
    }
    const sessions = {};
    
    // Группировка данных по сессиям
    filteredData.forEach(item => {
        const sessionId = item.sessionId;
        if (!sessionId) return;
        
        if (!sessions[sessionId]) {
            const contact = userContactsData[sessionId] || {};
            const analysisData = savedAnalyses[sessionId];
            const leadScore = getLeadScore(sessionId, contact, analysisData);
            const crmStatus = crmSentLeads[sessionId];
            
            sessions[sessionId] = {
                sessionId: sessionId,
                leadScore: leadScore,
                contactName: contact.name || '',
                contactPhone: contact.phone || '',
                contactEmail: contact.email || '',
                contactMessengers: contact.messengers || '',
                contactCompany: contact.company || '',
                ip: item.geo?.ip || item.ip || 'unknown',
                country: item.geo?.country || item.country || 'unknown',
                city: item.geo?.city || item.city || 'unknown',
                platform: item.platform || 'webchat',
                configuration: item.configName || 'default',
                startTime: item.sessionStartTime || item.timestamp,
                messages: 0,
                duration: 0,
                satisfaction: analysisData ? analysisData.satisfactionPercentage : '',
                crmStatus: crmStatus ? 'Sent' : '',
                crmLeadScore: crmStatus ? crmStatus.leadScore : ''
            };
        }
        
        // Обновляем данные сессии
        sessions[sessionId].messages = Math.max(
            sessions[sessionId].messages, 
            item.messageCount || item.messages || 0
        );
        sessions[sessionId].duration = Math.max(
            sessions[sessionId].duration, 
            item.sessionDuration || item.duration || 0
        );
    });
    
    // Формируем CSV
    const headers = [
        'Session ID',
        'Lead Score',
        'Contact Name',
        'Contact Phone',
        'Contact Email',
        'Contact Messengers',
        'Contact Company',
        'IP Address',
        'Country',
        'City',
        'Platform',
        'Configuration',
        'Start Time',
        'Messages',
        'Duration (sec)',
        'Satisfaction %',
        'CRM Status',
        'CRM Lead Score'
    ];
    
    const csvContent = "data:text/csv;charset=utf-8,"
        + headers.join(',') + "\n"
        + Object.values(sessions).map(s => [
            s.sessionId,
            s.leadScore,
            `"${s.contactName}"`,
            `"${s.contactPhone}"`,
            `"${s.contactEmail}"`,
            `"${s.contactMessengers}"`,
            `"${s.contactCompany}"`,
            s.ip,
            s.country,
            s.city,
            s.platform,
            s.configuration,
            s.startTime,
            s.messages,
            s.duration,
            s.satisfaction,
            s.crmStatus,
            s.crmLeadScore
        ].join(',')).join("\n");
    
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement("a");
    link.setAttribute("href", encodedUri);
    link.setAttribute("download", `chat_monitoring_${new Date().toISOString()}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
}

        // Просмотр диалога
async function viewDialog(sessionId) {
    activeFilter = null; 
    const modal = document.getElementById('dialogModal');
    const body = document.getElementById('dialogBody');
    const title = document.getElementById('dialogTitle');
    
    // Получаем данные пользователя и контактные данные
    const sessionData = allData.find(item => item.sessionId === sessionId);
    const contactData = userContactsData[sessionId] || {};
    
    // Определяем имя пользователя
const guestName = MonitoringConfigManager.getTranslation('formatting.guest');

// Список всех возможных переводов "Guest/User/Пользователь"
const userTranslations = ['Guest', 'Пользователь', 'Гість', 'User', 'Usuario', 'Utilisateur', 'Benutzer', 'Utente', 'Usuário', '用户', 'ユーザー', '사용자', 'Користувач', 'Invitado', 'Invité', 'Gast', 'Ospite', 'Convidado', '访客', 'ゲスト', '게스트'];

// Получаем имя с проверкой
let userName = contactData.name;
if (!userName && sessionData?.userName) {
    userName = userTranslations.includes(sessionData.userName) ? guestName : sessionData.userName;
}
if (!userName) {
    userName = guestName;
}
    
    // Блокируем прокрутку body
    window.scrollPosition = window.pageYOffset || document.documentElement.scrollTop;
    document.body.classList.add('modal-open');
    document.body.style.top = `-${window.scrollPosition}px`;
    
    modal.style.display = 'block';
    body.innerHTML = `
    <div class="loading-spinner">
        <div class="spinner"></div>
        <p>${MonitoringConfigManager.getTranslation('dialogs.dialog.loading')}</p>
    </div>
`;
    title.textContent = `${MonitoringConfigManager.getTranslation('dialogs.dialog.title')}: ${userName}`;

    try {
        const response = await authFetch(`${config.dialogsEndpoint}?session_id=${sessionId}`);
        const data = await response.json();

        let dialogs = [];
        if (data.dialogs) {
            dialogs = data.dialogs;
        } else if (Array.isArray(data)) {
            dialogs = data;
        }
        
        if (dialogs.length > 0) {
    // ✅ ПРОВЕРКА: Включены ли highlights
const highlightsConfig = MonitoringConfig.highlights || {};
const shouldLoadHighlights = highlightsConfig.enabled === true; 
// ✅ Если highlights выключены - скрываем UI
if (!shouldLoadHighlights) {
}
    
    // Загружаем highlights только если включено
    const highlightsData = shouldLoadHighlights 
        ? await loadHighlights(sessionId) 
        : { hasHighlights: false, highlights: [], total: 0 };
            
            // Создаем контейнер с боковой панелью
            const hasHighlights = highlightsData && highlightsData.hasHighlights;

// ✅ ИСПОЛЬЗУЕМ РАЗНЫЕ LAYOUTS в зависимости от shouldLoadHighlights
if (shouldLoadHighlights) {
    // Layout С поддержкой highlights (двухколоночный)
    body.innerHTML = `
        <div class="dialog-container-with-highlights">
            ${hasHighlights ? `
                <div class="dialog-highlights-sidebar">
                    ${renderHighlightsPanel(highlightsData)}
                </div>
            ` : ''}
            <div class="dialog-messages-content ${hasHighlights ? 'with-highlights' : ''}">
                ${dialogs.map(msg => `
                    <div class="dialog-message ${msg.message_type}" data-message-id="${msg.id}">
                        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                            <strong style="color: ${msg.message_type === 'user' ? 'var(--accent-primary)' : 'var(--success)'};font-size: 14px;">
                                ${msg.message_type === 'user' ? 
                                '👤 ' + userName : 
                                '🤖 ' + MonitoringConfigManager.getTranslation('dialogs.dialog.bot')}
                            </strong>
                            <div style="display: flex; gap: 8px; align-items: center;">
                                <span style="font-size: 18px;">${msg.platform_icon || '💬'}</span>
                                <span style="font-size: 18px;">${msg.language_flag || '🌐'}</span>
                            </div>
                        </div>
                        <div class="message-content">${msg.message_text || msg.response_text || msg.content || ''}</div>
                        <div style="font-size: 11px; color: var(--text-secondary); margin-top: 8px; display: flex; justify-content: space-between;">
                            <span>🕐 ${formatDate(msg.timestamp)}</span>
                            <span>${msg.platform || 'web'}</span>
                        </div>
                    </div>
                `).join('')}
            </div>
        </div>
    `;
} else {
    // Layout БЕЗ highlights (обычный одноколоночный)
    body.innerHTML = `
        <div class="dialog-messages-simple">
            ${dialogs.map(msg => `
                <div class="dialog-message ${msg.message_type}" data-message-id="${msg.id}">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                        <strong style="color: ${msg.message_type === 'user' ? 'var(--accent-primary)' : 'var(--success)'};font-size: 14px;">
                            ${msg.message_type === 'user' ? 
                            '👤 ' + userName : 
                            '🤖 ' + MonitoringConfigManager.getTranslation('dialogs.dialog.bot')}
                        </strong>
                        <div style="display: flex; gap: 8px; align-items: center;">
                            <span style="font-size: 18px;">${msg.platform_icon || '💬'}</span>
                            <span style="font-size: 18px;">${msg.language_flag || '🌐'}</span>
                        </div>
                    </div>
                    <div class="message-content">${msg.message_text || msg.response_text || msg.content || ''}</div>
                    <div style="font-size: 11px; color: var(--text-secondary); margin-top: 8px; display: flex; justify-content: space-between;">
                        <span>🕐 ${formatDate(msg.timestamp)}</span>
                        <span>${msg.platform || 'web'}</span>
                    </div>
                </div>
            `).join('')}
        </div>
    `;
}
            // Добавляем кнопку для анализа highlights если их нет
            if (!hasHighlights && shouldLoadHighlights) {  // ← ДОБАВИЛИ проверку && shouldLoadHighlights
    const analyzeBtn = document.createElement('button');
    analyzeBtn.className = 'analyze-highlights-button';
    analyzeBtn.innerHTML = '🔍 ' + MonitoringConfigManager.getTranslation('highlights.button');
    analyzeBtn.onclick = async () => {
        analyzeBtn.disabled = true;
        analyzeBtn.textContent = MonitoringConfigManager.getTranslation('highlights.analyzing');
        
        await analyzeHighlights(sessionId, userName);
        
        // Перезагружаем диалог
        setTimeout(() => {
            viewDialog(sessionId);
        }, 1500);
    };
    
    body.prepend(analyzeBtn);
}
        } else {
            body.innerHTML = `<p style="text-align: center; color: var(--text-secondary);">${MonitoringConfigManager.getTranslation('dialogs.dialog.notFound')}</p>`;
        }
    } catch (error) {
        console.error('Ошибка загрузки диалога:', error);
        body.innerHTML = '<p style="color: var(--danger); text-align: center;">Ошибка загрузки диалога</p>';
    }
}

        function closeDialog(event) {
    if (!event || event.target.id === 'dialogModal') {
        document.getElementById('dialogModal').style.display = 'none';
        document.body.classList.remove('modal-open');
        document.body.style.top = '';
        window.scrollTo(0, window.scrollPosition || 0);
    }
}

        // Анализ диалогов
        async function analyzeUserDialog(sessionId, userName) {
    const modal = document.getElementById('analysisModal');
    const body = document.getElementById('analysisBody');
    const title = document.getElementById('analysisTitle');
    
    // ✅ ИСПРАВЛЕНИЕ: Получаем реальное имя из контактных данных
    const contactData = userContactsData[sessionId] || {};
    const sessionData = allData.find(item => item.sessionId === sessionId);
    const guestTranslation = MonitoringConfigManager.getTranslation('formatting.guest');
   // Список всех возможных переводов "Guest/User/Пользователь"
const userTranslations = ['Guest', 'Пользователь', 'Гість', 'User', 'Usuario', 'Utilisateur', 'Benutzer', 'Utente', 'Usuário', '用户', 'ユーザー', '사용자', 'Користувач', 'Invitado', 'Invité', 'Gast', 'Ospite', 'Convidado', '访客', 'ゲスト', '게스트'];

// Получаем имя с проверкой
let displayName = contactData.name;

// Если нет имени в контактах, проверяем sessionData.userName
if (!displayName && sessionData?.userName) {
    displayName = userTranslations.includes(sessionData.userName) ? guestTranslation : sessionData.userName;
}

// Если всё ещё нет, проверяем переданный userName
if (!displayName && userName) {
    displayName = userTranslations.includes(userName) ? guestTranslation : userName;
}

// Если совсем нет имени, используем перевод "Гость"
if (!displayName) {
    displayName = guestTranslation;
}
    
    modal.style.display = 'block';
    // Блокируем прокрутку body
    window.scrollPosition = window.pageYOffset || document.documentElement.scrollTop;
    document.body.classList.add('modal-open');
    document.body.style.top = `-${window.scrollPosition}px`;
    
    body.innerHTML = `
        <div class="loading-spinner">
            <div class="spinner"></div>
            <p>${MonitoringConfigManager.getTranslation('dialogs.analysis.loading')} ${displayName}...</p>
        </div>
    `;

    title.textContent = `${MonitoringConfigManager.getTranslation('dialogs.analysis.title')}: ${displayName}`;

    try {
        const response = await authFetch(config.analyzeEndpoint, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                type: 'single',
                sessionId: sessionId,
                userName: displayName,  // ✅ Отправляем правильное имя в workflow
                resultLanguage: currentAnalysisResultLanguage
            })
        });
        
        if (!response.ok) throw new Error('Ошибка анализа');
        
        const analysis = await response.json();
        // Добавляем sessionId к данным анализа
        analysis.sessionId = sessionId;
        displayAnalysisResults(body, analysis);
        
        // Обновляем интерфейс после анализа
        setTimeout(() => {
            loadSavedAnalyses();
            updateTable();
        }, 2000);
        
    } catch (error) {
        console.error('Ошибка анализа:', error);
        body.innerHTML = `<p style="color: var(--danger); text-align: center;">${MonitoringConfigManager.getTranslation('dialogs.analysis.error')}</p>`;
    }
}

        async function analyzeAllDialogs() {
    const modal = document.getElementById('analysisModal');
    const body = document.getElementById('analysisBody');
    const title = document.getElementById('analysisTitle');
    
    modal.style.display = 'block';
    // Блокируем прокрутку body
    document.body.classList.add('modal-open');
    
    body.innerHTML = `
        <div class="loading-spinner">
            <div class="spinner"></div>
            <p>${MonitoringConfigManager.getTranslation('dialogs.analysis.analyzingAll')}</p>
            <p style="font-size: 12px; color: var(--text-secondary);">${MonitoringConfigManager.getTranslation('dialogs.analysis.timeNotice')}</p>
        </div>
    `;

    title.textContent = MonitoringConfigManager.getTranslation('dialogs.analysis.title');

    try {
        const response = await authFetch(config.analyzeEndpoint, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                type: 'all'
            })
        });
        
        if (!response.ok) throw new Error('Ошибка анализа');
        
        const analysis = await response.json();
        displayAnalysisResults(body, analysis);
        
        // Обновляем интерфейс после анализа
        setTimeout(() => {
            loadSavedAnalyses();
            updateTable();
        }, 2000);
        
    } catch (error) {
        console.error('Ошибка анализа:', error);
        body.innerHTML = `<p style="color: var(--danger); text-align: center;">${MonitoringConfigManager.getTranslation('dialogs.analysis.error')}</p>`;
    }
}

function analyzeByLanguage() {
    // Обновляем кнопки языков перед показом модального окна
    populateLanguageButtons();
    document.getElementById('languageModal').style.display = 'block';
    // Блокируем прокрутку body
    window.scrollPosition = window.pageYOffset || document.documentElement.scrollTop;
document.body.classList.add('modal-open');
document.body.style.top = `-${window.scrollPosition}px`;
}

async function analyzeLanguageDialogs(language) {
    
    closeLanguageModal();
    
    const modal = document.getElementById('analysisModal');
    const body = document.getElementById('analysisBody');
    const title = document.getElementById('analysisTitle');
    
    // Получаем конфигурацию выбранного языка
    const langConfig = MonitoringConfig.availableAnalysisLanguages[language];
    const currentLang = MonitoringConfigManager.getLanguage();
    const languageName = langConfig.labels[currentLang] || langConfig.labels.en;
    
    modal.style.display = 'block';
    document.body.classList.add('modal-open');
    
    body.innerHTML = `
        <div class="loading-spinner">
            <div class="spinner"></div>
            <p>${MonitoringConfigManager.getTranslation('dialogs.analysis.loading')} (${languageName})</p>
        </div>
    `;

    title.textContent = `${MonitoringConfigManager.getTranslation('dialogs.analysis.title')} (${languageName})`;

    try {
        const response = await authFetch(config.analyzeEndpoint, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
    type: 'language',
    language: language,
    resultLanguage: currentAnalysisResultLanguage
})
        });
        
        if (!response.ok) throw new Error('Ошибка анализа');
        
        const analysis = await response.json();
        displayAnalysisResults(body, analysis);
        
        setTimeout(() => {
            loadSavedAnalyses();
            updateTable();
        }, 2000);
        
    } catch (error) {
        console.error('Ошибка анализа:', error);
        body.innerHTML = `<p style="color: var(--danger); text-align: center;">${MonitoringConfigManager.getTranslation('dialogs.analysis.error')}</p>`;
    }
}

       function displayAnalysisResults(container, analysis) {
    // Добавляем проверку в начало функции
    if (!analysis) {
        container.innerHTML = `<p style="text-align: center; color: var(--text-secondary);">${MonitoringConfigManager.getTranslation('dialogs.analysis.error')}</p>`;
        return;
    }
    
    const translations = MonitoringConfigManager.getTranslation('analysis');
    
    let html = '<div class="analysis-result">';
    
    // Эмоциональный тон
    if (analysis.emotionalTone) {
        const toneIcons = {
            positive: '😊',
            negative: '😟',
            neutral: '😐'
        };
        
        const overall = analysis.emotionalTone.overall || 'neutral';
        const overallText = analysis.emotionalTone.overallText || translations.emotionalTone[overall] || overall;
        const satisfaction = analysis.emotionalTone.satisfaction !== undefined ? analysis.emotionalTone.satisfaction : (analysis.satisfactionPercentage || 0);
        const description = analysis.emotionalTone.description || '';
        
        html += `
            <div class="analysis-section">
                <h4>😊 ${translations.emotionalTone.title}</h4>
                <div class="analysis-metric">
                    <span class="metric-label">${translations.emotionalTone.overall}:</span>
                    <span class="metric-value">
                        <span class="${overall}" style="display: flex; align-items: center; gap: 8px;">
                            <span style="font-size: 24px;">${toneIcons[overall] || '😐'}</span>
                            <span style="font-size: 18px;">${overallText}</span>
                        </span>
                    </span>
                </div>
                <div class="analysis-metric">
                    <span class="metric-label">${translations.emotionalTone.satisfaction}:</span>
                    <span class="metric-value ${satisfaction >= 70 ? 'positive' : satisfaction >= 50 ? 'neutral' : 'negative'}">
                        <div style="display: flex; align-items: center; gap: 10px;">
                            <span style="font-size: 20px;">${satisfaction}%</span>
                            <div style="width: 100px; height: 8px; background: var(--border-color); border-radius: 4px; overflow: hidden;">
                                <div style="width: ${satisfaction}%; height: 100%; background: ${satisfaction >= 70 ? 'var(--success)' : satisfaction >= 50 ? 'var(--warning)' : 'var(--danger)'}; transition: width 1s ease;"></div>
                            </div>
                        </div>
                    </span>
                </div>
                ${description ? `
                    <p style="margin-top: 20px; padding: 15px; background: var(--primary-bg); border-radius: 8px; color: var(--text-secondary); line-height: 1.6;">
                        ${description}
                    </p>
                ` : ''}
            </div>
        `;
    }
    
    // Потребности клиента
if (analysis.customerNeeds && analysis.customerNeeds.length > 0) {
    html += `
        <div class="analysis-section collapsible">
            <div class="analysis-header" onclick="toggleAnalysisSection('needs')">
                <h4>🎯 ${translations.needs.title}</h4>
                <span class="analysis-toggle-icon" id="analysis-toggle-needs">▼</span>
            </div>
            <div class="analysis-content" id="analysis-content-needs">
                <div style="display: grid; gap: 10px;">
                    ${analysis.customerNeeds.map((need, index) => `
                        <div class="analysis-metric" style="animation-delay: ${index * 0.1}s;">
                            <span style="display: flex; align-items: center; gap: 10px;">
                                <span style="color: var(--accent-primary); font-size: 20px;">📍</span>
                                <span style="color: var(--text-primary);">${need}</span>
                            </span>
                        </div>
                    `).join('')}
                </div>
            </div>
        </div>
    `;
}
    
    // Упущенные возможности
if (analysis.missedOpportunities && analysis.missedOpportunities.length > 0) {
    html += `
        <div class="analysis-section collapsible">
            <div class="analysis-header" onclick="toggleAnalysisSection('opportunities')">
                <h4>💡 ${translations.missedOpportunities.title}</h4>
                <span class="analysis-toggle-icon" id="analysis-toggle-opportunities">▼</span>
            </div>
            <div class="analysis-content" id="analysis-content-opportunities">
                <div style="display: grid; gap: 10px;">
                    ${analysis.missedOpportunities.map((opp, index) => `
                        <div class="analysis-metric" style="background: rgba(245, 158, 11, 0.05); border-color: rgba(245, 158, 11, 0.3); animation-delay: ${index * 0.1}s;">
                            <span style="display: flex; align-items: center; gap: 10px;">
                                <span style="color: var(--warning); font-size: 20px;">⚠️</span>
                                <span style="color: var(--text-primary);">${opp}</span>
                            </span>
                        </div>
                    `).join('')}
                </div>
            </div>
        </div>
    `;
}
    
    // Рекомендации
if (analysis.recommendations && analysis.recommendations.length > 0) {
    html += `
        <div class="recommendations collapsible">
            <div class="analysis-header" onclick="toggleAnalysisSection('recommendations')">
                <h5 style="font-size: 18px; margin: 0;">📌 ${translations.recommendations.title}</h5>
                <span class="analysis-toggle-icon" id="analysis-toggle-recommendations">▼</span>
            </div>
            <div class="analysis-content" id="analysis-content-recommendations">
                <div style="display: grid; gap: 12px; margin-top: 15px;">
                    ${analysis.recommendations.map((rec, index) => `
                        <div style="padding: 15px; background: var(--card-bg); border-radius: 8px; border-left: 4px solid var(--warning); animation: slideIn 0.3s ease-out ${index * 0.1}s both;">
                            <span style="display: flex; align-items: start; gap: 10px;">
                                <span style="color: var(--warning); font-size: 18px; flex-shrink: 0;">💡</span>
                                <span style="color: var(--text-primary); line-height: 1.5;">${rec}</span>
                            </span>
                        </div>
                    `).join('')}
                </div>
            </div>
        </div>
    `;
}
    
    // Lead Scoring
if (analysis.leadScoring) {
    const leadScore = analysis.leadScoring.score || 0;
    const temperature = analysis.leadScoring.temperature || 'cold';
    const tempTranslation = MonitoringConfigManager.getTranslation(`leadScoring.temperature.${temperature}`) || temperature;
    
    html += `
        <div class="analysis-section" style="margin-top: 20px;">  <!-- ДОБАВЬТЕ margin-top: 20px -->
            <h4>🎯 ${MonitoringConfigManager.getTranslation('leadScoring.title')}</h4>
            <div class="lead-score-display">
                <div class="lead-score-indicator ${temperature}">
                    ${leadScore}
                </div>
                <div class="lead-score-details">
                    <div class="lead-temp-badge ${temperature}">
                        ${temperature === 'hot' ? '🔥' : temperature === 'warm' ? '🌡️' : '❄️'} 
                        ${tempTranslation}
                    </div>
                    ${analysis.leadScoring.recommendation ? `
                        <div style="margin-top: 15px; padding: 12px; background: var(--secondary-bg); border-radius: 8px; border-left: 3px solid var(--accent-primary);">
                            <div style="font-size: 14px; color: var(--text-primary); line-height: 1.5;">
                                ${analysis.leadScoring.recommendation}
                            </div>
                        </div>
                    ` : ''}
                </div>
            </div>
        </div>
    `;
}
    
    // Статистика
    if (analysis.statistics) {
        html += `
            <div class="analysis-section">
                <h4>📊 ${translations.statistics.title}</h4>
                ${analysis.statistics.totalDialogs !== undefined ? `
                    <div class="analysis-metric">
                        <span class="metric-label">${translations.statistics.totalDialogs}:</span>
                        <span class="metric-value" style="color: var(--accent-primary);">
                            <span style="font-size: 24px;">📝</span>
                            ${analysis.statistics.totalDialogs}
                        </span>
                    </div>
                ` : ''}
                ${analysis.statistics.avgSatisfaction !== undefined ? `
                    <div class="analysis-metric">
                        <span class="metric-label">${translations.statistics.avgSatisfaction}:</span>
                        <span class="metric-value ${analysis.statistics.avgSatisfaction >= 70 ? 'positive' : analysis.statistics.avgSatisfaction >= 50 ? 'neutral' : 'negative'}">
                            <div style="display: flex; align-items: center; gap: 10px;">
                                <span style="font-size: 20px;">${analysis.statistics.avgSatisfaction}%</span>
                                <div style="width: 120px; height: 10px; background: var(--border-color); border-radius: 5px; overflow: hidden;">
                                    <div style="width: ${analysis.statistics.avgSatisfaction}%; height: 100%; background: ${analysis.statistics.avgSatisfaction >= 70 ? 'var(--success)' : analysis.statistics.avgSatisfaction >= 50 ? 'var(--warning)' : 'var(--danger)'}; transition: width 1s ease;"></div>
                                </div>
                            </div>
                        </span>
                    </div>
                ` : ''}
                ${analysis.statistics.resolvedPercentage !== undefined ? `
                    <div class="analysis-metric">
                        <span class="metric-label">${translations.statistics.resolved}:</span>
                        <span class="metric-value ${analysis.statistics.resolvedPercentage >= 70 ? 'positive' : analysis.statistics.resolvedPercentage >= 50 ? 'neutral' : 'negative'}">
                            <div style="display: flex; align-items: center; gap: 10px;">
                                <span style="font-size: 20px;">✅ ${analysis.statistics.resolvedPercentage}%</span>
                                <div style="width: 120px; height: 10px; background: var(--border-color); border-radius: 5px; overflow: hidden;">
                                    <div style="width: ${analysis.statistics.resolvedPercentage}%; height: 100%; background: ${analysis.statistics.resolvedPercentage >= 70 ? 'var(--success)' : analysis.statistics.resolvedPercentage >= 50 ? 'var(--warning)' : 'var(--danger)'}; transition: width 1s ease;"></div>
                                </div>
                            </div>
                        </span>
                    </div>
                ` : ''}
            </div>
        `;
    }
    
    html += '</div>';
    container.innerHTML = html;
}

        function closeAnalysis(event) {
    if (!event || event.target.id === 'analysisModal') {
        document.getElementById('analysisModal').style.display = 'none';
        document.body.classList.remove('modal-open');
        document.body.style.top = '';
        window.scrollTo(0, window.scrollPosition || 0);
    }
}
function closeLanguageModal(event) {
    if (!event || event.target.id === 'languageModal') {
        document.getElementById('languageModal').style.display = 'none';
        document.body.classList.remove('modal-open');
        document.body.style.top = '';
        window.scrollTo(0, window.scrollPosition || 0);
    }
}
        
        // Глобальные переменные для автоанализа
let autoAnalysisEnabled = false;
let analysisDelayMinutes = 30;
let savedAnalyses = {};
let userContactsData = {};
// Глобальные переменные для email мониторинга
let emailData = [];
let filteredEmailData = [];
let currentEmailPage = 1;
let emailAnalyses = {};
let emailContactsData = {};
let currentAnalysisResultLanguage = null; // Язык результатов анализа по умолчанию
// Кэш для отслеживания предыдущего состояния таблиц
let previousTableData = {};
let previousEmailTableData = {};

// Открытие модального окна настроек
async function openSettingsModal() {
    document.getElementById('settingsModal').style.display = 'block';
    // Скрываем/показываем настройки CRM в зависимости от конфигурации
    const crmSection = document.getElementById('crmSettingsSection');
    if (crmSection) {
        crmSection.style.display = MonitoringConfig.crmIntegration.enabled ? 'block' : 'none';
    }
    // Блокируем прокрутку body
    document.body.classList.add('modal-open');
    
    // Синхронизация значений из основных элементов в модальное окно
    document.getElementById('autoAnalysisToggleModal').classList.toggle('active', autoAnalysisEnabled);
    document.getElementById('analysisDelayModal').value = analysisDelayMinutes;
    
    // Загружаем текущие значения периодов хранения
    await loadSettingsToModal();
    
    // Загружаем настройки CRM
    await loadCRMSettings();
}

// Закрытие модального окна настроек
function closeSettingsModal(event) {
    if (!event || event.target.id === 'settingsModal') {
        document.getElementById('settingsModal').style.display = 'none';
        document.body.classList.remove('modal-open');
        document.body.style.top = '';
        window.scrollTo(0, window.scrollPosition || 0);
    }
}

// Загрузка текущих настроек в модальное окно
async function loadSettingsToModal() {
    try {
        const response = await authFetch(config.cleanupSettingsEndpoint);
        
        if (response.ok) {
            const result = await response.json();
            if (result.settings) {
                document.getElementById('monitoringRetentionModal').value = result.settings.monitoring_retention_days || 30;
                document.getElementById('analysisRetentionModal').value = result.settings.analysis_retention_days || 90;
                document.getElementById('dialogsRetentionModal').value = result.settings.dialogs_retention_days || 60;
                document.getElementById('contactsRetentionModal').value = result.settings.contacts_retention_days || 180;
                
                //console.log('Настройки очистки БД загружены:', result.settings);
            }
        }
    } catch (error) {
        console.error('Ошибка загрузки настроек очистки:', error);
    }
}

// Загрузка настроек CRM
async function loadCRMSettings() {
    try {
        const config = MonitoringConfigManager.getTechnicalSettings();
        const response = await authFetch(config.crmSettingsEndpoint);

        if (response.ok) {
            const data = await response.json();

            if (data) {
                // Заполняем поля
                document.getElementById('crmWebhookUrl').value = data.webhook_url || '';
                document.getElementById('crmMinLeadScore').value = data.min_lead_score || 80;
                
                // Обновляем глобальную переменную
                crmSettings.autoSendEnabled = data.auto_send_enabled || false;
                
                // Устанавливаем toggle
                const toggle = document.getElementById('crmAutoSendToggle');
                const slider = toggle.querySelector('.toggle-slider');
                
                if (crmSettings.autoSendEnabled) {
                slider.style.transform = 'translateX(26px)';
                toggle.style.background = '#667eea';
                toggle.classList.add('active');
                } else {
                slider.style.transform = 'translateX(0)';
                toggle.style.background = 'var(--border-color)';
                toggle.classList.remove('active');
               }
                
                console.log('✅ Настройки CRM загружены');
            }
        }
    } catch (error) {
        console.error('❌ Ошибка загрузки настроек CRM:', error);
    }
}

// Сохранение всех настроек из модального окна
async function saveAllSettings() {
    // Получаем значения из модального окна
    analysisDelayMinutes = parseInt(document.getElementById('analysisDelayModal').value);
    const monitoringDays = parseInt(document.getElementById('monitoringRetentionModal').value);
    const analysisDays = parseInt(document.getElementById('analysisRetentionModal').value);
    const dialogsDays = parseInt(document.getElementById('dialogsRetentionModal').value);
    const contactsDays = parseInt(document.getElementById('contactsRetentionModal').value);
    
    // Валидация
    if (monitoringDays < 7 || monitoringDays > 365) {
        showNotification(`⚠️ ${MonitoringConfigManager.getTranslation('notifications.periodWarning')}`, 'warning');
        return;
    }
    
    if (analysisDays < 30 || analysisDays > 365) {
        showNotification(`⚠️ ${MonitoringConfigManager.getTranslation('notifications.analysisWarning')}`, 'warning');
        return;
    }
    if (dialogsDays < 7 || dialogsDays > 365) {
        showNotification(`⚠️ ${MonitoringConfigManager.getTranslation('notifications.dialogsWarning')}`, 'warning');
        return;
    }
    
    if (contactsDays < 30 || contactsDays > 365) {
        showNotification(`⚠️ ${MonitoringConfigManager.getTranslation('notifications.contactsWarning')}`, 'warning');
        return;
    }

    try {
        // Сохраняем настройки автоанализа
        const autoAnalysisResponse = await authFetch(config.autoAnalysisSettingsEndpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                monitoringRetention: monitoringDays,
                analysisRetention: analysisDays,
                dialogsRetention: dialogsDays,
                contactsRetention: contactsDays
            })
        });

        // Сохраняем настройки очистки БД
        const cleanupResponse = await authFetch(config.updateCleanupSettingsEndpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                monitoringRetention: monitoringDays,
                analysisRetention: analysisDays,
                dialogsRetention: dialogsDays,
                contactsRetention: contactsDays
            })
        });
        
        if (autoAnalysisResponse.ok && cleanupResponse.ok) {
            showNotification(`✅ ${MonitoringConfigManager.getTranslation('notifications.settingsSaved')}`, 'success');
            
            // Сохраняем локально
            const settings = {
                enabled: autoAnalysisEnabled,
                delay: analysisDelayMinutes
            };
            localStorage.setItem('autoAnalysisSettings', JSON.stringify(settings));
            
            // Закрываем модальное окно
            closeSettingsModal();
        } else {
            throw new Error('Ошибка сохранения');
        }
    } catch (error) {
        console.error('Ошибка:', error);
        showNotification(`❌ ${MonitoringConfigManager.getTranslation('notifications.settingsError')}`, 'error');
    }
}

// Загрузка настроек автоанализа с сервера
async function loadAutoAnalysisSettings() {
    //console.log('Пытаемся загрузить настройки...');
    try {
        const response = await authFetch(config.autoAnalysisSettingsEndpoint);
        //console.log('Ответ сервера:', response.status, response.ok);
        
        if (response.ok) {
            const result = await response.json();
            if (result.data && result.data[0]) {
                const data = result.data[0];
                autoAnalysisEnabled = data.enabled;
                analysisDelayMinutes = data.delay_minutes;
                
                /*console.log('Настройки автоанализа загружены с сервера:', {
                    enabled: autoAnalysisEnabled,
                    delay: analysisDelayMinutes
                });
                */
                return;
            }
        }
    } catch (error) {
        //console.error('Ошибка загрузки настроек с сервера:', error);
    }
    
    // Fallback на localStorage
    const saved = localStorage.getItem('autoAnalysisSettings');
    if (saved) {
        const settings = JSON.parse(saved);
        autoAnalysisEnabled = settings.enabled;
        analysisDelayMinutes = settings.delay;
        
        //console.log('Настройки загружены из localStorage');
    }
}

// Переключение автоанализа
function toggleAutoAnalysis() {
    const toggle = document.getElementById('autoAnalysisToggleModal');
    autoAnalysisEnabled = !autoAnalysisEnabled;
    toggle.classList.toggle('active', autoAnalysisEnabled);
    
    // Показываем уведомление о состоянии
    if (autoAnalysisEnabled) {
        showNotification(`🤖 ${MonitoringConfigManager.getTranslation('notifications.autoAnalysisEnabled')}`, 'success');
    } else {
        showNotification(`⏸️ ${MonitoringConfigManager.getTranslation('notifications.autoAnalysisDisabled')}`, 'info');
    }
}

// Функция для обновления отображения результатов автоанализа
async function checkForAutoAnalysis() {
    // Только загружаем и отображаем сохраненные анализы
    await loadSavedAnalyses();
    updateTable();
}

// Показ уведомлений
function showNotification(message, type = 'info') {
    const notification = document.createElement('div');
    notification.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        padding: 16px 24px;
        background: ${type === 'success' ? 'var(--success)' : type === 'error' ? 'var(--danger)' : 'var(--accent-primary)'};
        color: white;
        border-radius: 8px;
        box-shadow: 0 4px 12px rgba(0,0,0,0.2);
        z-index: 10000;
        animation: slideIn 0.3s ease-out;
    `;
    notification.textContent = message;
    document.body.appendChild(notification);
    
    setTimeout(() => {
        notification.style.animation = 'fadeOut 0.3s ease-out';
        setTimeout(() => notification.remove(), 300);
    }, 3000);
}
  // =====================================================
// ФУНКЦИИ ДЛЯ РАБОТЫ С КОНТАКТНЫМИ ДАННЫМИ
// =====================================================

// Функция загрузки контактных данных
async function loadContactData() {
    try {
        const response = await authFetch(config.getContactsEndpoint);
        const data = await response.json();
        
        if (data.contacts) {
            userContactsData = data.contacts;
            //console.log('✅ Контактные данные загружены:', Object.keys(userContactsData).length);
            
            // Обновляем таблицу после загрузки контактов
            updateTable();
        }
    } catch (error) {
        console.error('Ошибка загрузки контактных данных:', error);
        userContactsData = {}; // Важно инициализировать пустым объектом
    }
}

// Функция извлечения контактов для конкретной сессии
async function extractContactsForSession(sessionId) {
    try {
        showNotification(`⏳ ${MonitoringConfigManager.getTranslation('contacts.extracting')}`, 'info');

        const response = await authFetch(config.extractContactsEndpoint, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                type: 'single',
                sessionId: sessionId
            })
        });
        
        if (response.ok) {
            // Перезагружаем контактные данные
            await loadContactData();
            
            // ИСПРАВЛЕНИЕ: Обновляем таблицу после загрузки контактов
            updateTable();
            
            showNotification(`✅ ${MonitoringConfigManager.getTranslation('contacts.extracted')}`, 'success');
        } else {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
    } catch (error) {
        console.error('Ошибка извлечения контактов:', error);
        showNotification(`❌ ${MonitoringConfigManager.getTranslation('contacts.extractError')}`, 'error');
    }
}

// Добавьте кнопку извлечения контактов в действия таблицы
function getContactActionButton(sessionId) {
    const displaySettings = MonitoringConfigManager.getDisplaySettings();
    const actionButtons = displaySettings.tableColumns.actionButtons || {
        viewDialog: true,
        analyze: true,
        viewAnalysis: true,
        extractContacts: true
    };
    
    // Проверяем, включена ли кнопка извлечения контактов
    if (!actionButtons.extractContacts) {
        return '';
    }
    
    const actionTranslations = MonitoringConfigManager.getTranslation('table.actions');
    const hasContacts = userContactsData[sessionId] && 
                       (userContactsData[sessionId].name || 
                        userContactsData[sessionId].phone || 
                        userContactsData[sessionId].email);
    
    // Изменяем текст кнопки в зависимости от наличия контактов
    const buttonText = hasContacts ? 
        `🔄 ${actionTranslations.updateContacts || actionTranslations.extractContacts}` : 
        `📇 ${actionTranslations.extractContacts}`;
    
    return `<button class="extract-contacts-btn" onclick="extractContactsForSession('${sessionId}')" 
                    title="${hasContacts ? 'Обновить контактные данные' : 'Извлечь контактные данные'}">
                ${buttonText}
            </button>`;
}

// =====================================================
// ФУНКЦИИ ДЛЯ УДАЛЕНИЯ ЗАПИСЕЙ
// =====================================================

// Глобальные переменные для модального окна удаления
let pendingDeleteId = null;
let pendingDeleteType = null;

// Функция открытия модального окна подтверждения
function openDeleteConfirm(id, type, displayName) {
    const modal = document.getElementById('deleteConfirmModal');
    if (!modal) {
        console.error('Delete confirmation modal not found');
        return;
    }
    
    const title = document.getElementById('deleteModalTitle');
    const message = document.getElementById('deleteModalMessage');
    const idText = document.getElementById('deleteModalId');
    const cancelBtn = document.getElementById('deleteCancelBtn');
    const confirmBtn = document.getElementById('deleteConfirmBtn');
    
    // Получаем переводы
    const translations = MonitoringConfigManager.getTranslation('deleteModal');
    
    // Устанавливаем тексты
    if (title) title.textContent = translations.title;
    if (cancelBtn) cancelBtn.textContent = translations.cancel;
    if (confirmBtn) confirmBtn.textContent = translations.confirm;
    
    // Формируем сообщение в зависимости от типа
    if (type === 'session') {
        if (message) message.textContent = translations.messageSession;
        if (idText) {
            idText.textContent = `ID: ${id.substring(0, 16)}...`;
            idText.style.display = 'block';
        }
    } else if (type === 'email') {
        if (message) message.textContent = translations.messageEmail;
        if (idText) {
            idText.textContent = displayName || id;
            idText.style.display = 'block';
        }
    }
    
    // Сохраняем данные для удаления
    pendingDeleteId = id;
    pendingDeleteType = type;
    
    // Показываем модальное окно
    modal.style.display = 'block';
    window.scrollPosition = window.pageYOffset || document.documentElement.scrollTop;
document.body.classList.add('modal-open');
document.body.style.top = `-${window.scrollPosition}px`;
    
    // Устанавливаем обработчик для кнопки подтверждения
    const confirmButton = document.getElementById('confirmDeleteBtn');
    if (confirmButton) {
        // Удаляем старый обработчик если есть
        confirmButton.replaceWith(confirmButton.cloneNode(true));
        const newConfirmButton = document.getElementById('confirmDeleteBtn');
        newConfirmButton.onclick = confirmDelete;
    }
}

// Функция закрытия модального окна
function closeDeleteConfirm(event) {
    if (!event || event === true || event.target.id === 'deleteConfirmModal') {
        const modal = document.getElementById('deleteConfirmModal');
        if (modal) {
            modal.style.display = 'none';
            document.body.classList.remove('modal-open');
            document.body.style.top = '';
            window.scrollTo(0, window.scrollPosition || 0);
        }
        
        pendingDeleteId = null;
        pendingDeleteType = null;
    }
}

// Функция подтверждения удаления
async function confirmDelete() {
    if (!pendingDeleteId || !pendingDeleteType) {
        console.error('No delete data available');
        return;
    }
    
    // Сохраняем данные перед закрытием окна
    const deleteId = pendingDeleteId;
    const deleteType = pendingDeleteType;
    
    // Закрываем модальное окно
    closeDeleteConfirm(true);
    
    // Выполняем удаление с сохраненными данными
    if (deleteType === 'session') {
        await performDeleteSession(deleteId);
    } else if (deleteType === 'email') {
        await performDeleteEmail(deleteId);
    }
}

// Функция удаления сессии мессенджера
function deleteSessionRecord(sessionId) {
     // ДОБАВЬ ПРОВЕРКУ:
    if (!checkActionPermission('delete')) {
        return;
    }
    openDeleteConfirm(sessionId, 'session');
    return false; // Предотвращаем всплытие события
}

// Функция удаления email записи
function deleteEmailRecord(emailAddress) {
     // ДОБАВЬ ПРОВЕРКУ:
    if (!checkActionPermission('delete')) {
        return;
    }
    openDeleteConfirm(emailAddress, 'email', emailAddress);
    return false; // Предотвращаем всплытие события
}

// Выполнение удаления сессии
async function performDeleteSession(sessionId) {
    try {
        showNotification(`⏳ ${MonitoringConfigManager.getTranslation('notifications.deleting')}`, 'info');

        const config = MonitoringConfigManager.getTechnicalSettings();

        const response = await authFetch(config.deleteSessionEndpoint, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                sessionId: sessionId
            })
        });
        
        const result = await response.json();
        
        // Проверяем поле success в ответе
        if (!response.ok || !result.success) {
            throw new Error(result.message || 'Failed to delete record');
        }
        
        showNotification(`✅ ${MonitoringConfigManager.getTranslation('notifications.deleteSuccess')}`, 'success');
        
        // Удаляем из локальных данных только при успехе
        allData = allData.filter(item => item.sessionId !== sessionId);
        filteredData = filteredData.filter(item => item.sessionId !== sessionId);
        
        // Удаляем связанные данные
        if (savedAnalyses[sessionId]) delete savedAnalyses[sessionId];
        if (userContactsData[sessionId]) delete userContactsData[sessionId];
        
        // Обновляем интерфейс
        updateTable();
        updateStats();
        updateCharts();
        
    } catch (error) {
        console.error('Error deleting session:', error);
        showNotification(`❌ ${MonitoringConfigManager.getTranslation('notifications.deleteError')}`, 'error');
    }
}

// Выполнение удаления email
async function performDeleteEmail(emailAddress) {
    try {
        showNotification(`⏳ ${MonitoringConfigManager.getTranslation('notifications.deleting')}`, 'info');

        const config = MonitoringConfigManager.getTechnicalSettings();

        const response = await authFetch(config.deleteEmailEndpoint, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                email: emailAddress
            })
        });
        
        const result = await response.json();
        
        // Проверяем поле success в ответе
        if (!response.ok || !result.success) {
            throw new Error(result.message || 'Failed to delete record');
        }
        
        showNotification(`✅ ${MonitoringConfigManager.getTranslation('notifications.deleteSuccess')}`, 'success');
        
        // Удаляем из локальных данных только при успехе
        emailData = emailData.filter(item => item.email !== emailAddress);
        filteredEmailData = filteredEmailData.filter(item => item.email !== emailAddress);
        
        if (emailAnalyses[emailAddress]) delete emailAnalyses[emailAddress];
        if (emailContactsData[emailAddress]) delete emailContactsData[emailAddress];
        
        updateEmailTable();
        
    } catch (error) {
        console.error('Error deleting email:', error);
        showNotification(`❌ ${MonitoringConfigManager.getTranslation('notifications.deleteError')}`, 'error');
    }
}

// =====================================================
// КОНЕЦ ФУНКЦИЙ ДЛЯ КОНТАКТНЫХ ДАННЫХ
// =====================================================

// =====================================================
// ФУНКЦИИ ДЛЯ EMAIL МОНИТОРИНГА
// =====================================================

// Инициализация таблицы email
async function initializeEmailTable() {
    updateEmailTableHeaders();
    
    // ВАЖНО: Сначала загружаем контакты, потом анализы и данные
    await loadEmailContactsData();  // Загружаем контакты первыми
    await loadEmailAnalyses();
    await loadEmailData();
    
    // Автообновление каждые 30 секунд
    setInterval(async () => {
        await loadEmailContactsData();  // Обновляем контакты
        await loadEmailAnalyses();
        await loadEmailData();
    }, config.refreshInterval); 
}

// Переключение между вкладками
function switchTableTab(tab) {
    // Убираем активность со всех вкладок
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.classList.remove('active');
    });
    
    // Переключаем видимость контейнеров
    if (tab === 'email') {
        document.getElementById('messengersTableContainer').style.display = 'none';
        document.getElementById('emailTableContainer').style.display = 'block';
        document.querySelector('[data-tab="email"]').classList.add('active');
        loadEmailData();
    } else {
        document.getElementById('messengersTableContainer').style.display = 'block';
        document.getElementById('emailTableContainer').style.display = 'none';
        document.querySelector('[data-tab="messengers"]').classList.add('active');
    }
}

// Обновление заголовков таблицы email
function updateEmailTableHeaders() {
    const headerRow = document.getElementById('emailTableHeaderRow');
    const translations = MonitoringConfigManager.getTranslation('emailMonitoring.table.columns');
    
    headerRow.innerHTML = `
        <th onclick="sortEmailTable('leadScore')">${translations.leadScore}</th>
        <th onclick="sortEmailTable('email')">${translations.email}</th>
        <th onclick="sortEmailTable('name')">${translations.name}</th>
        <th onclick="sortEmailTable('subject')">${translations.subject}</th>
        <th onclick="sortEmailTable('status')">${translations.status}</th>
        <th onclick="sortEmailTable('satisfaction')">${translations.satisfaction}</th>
        <th onclick="sortEmailTable('messages')">${translations.messages}</th>
        <th onclick="sortEmailTable('lastActivity')">${translations.lastActivity}</th>
        <th>${translations.actions}</th>
    `;
}

// Загрузка данных email
async function loadEmailData() {
    try {
        const response = await authFetch(config.emailDataEndpoint);
        if (!response.ok) throw new Error('Ошибка загрузки данных email');
        
        const result = await response.json();
        
        if (Array.isArray(result)) {
            emailData = result;
        } else if (result.data && Array.isArray(result.data)) {
            emailData = result.data;
            // Загружаем сохраненные анализы для email
await loadEmailAnalyses();
        } else {
            emailData = [];
        }
        
        // Применяем фильтры поиска
        applyEmailFilters();
        
    } catch (error) {
        console.error('Ошибка загрузки email данных:', error);
        showError('Не удалось загрузить данные email');
    }
}

// Загрузка сохраненных анализов email
async function loadEmailAnalyses() {
    try {
        //console.log('Загружаем анализы email с:', config.getAllEmailAnalysisEndpoint);
        const response = await authFetch(config.getAllEmailAnalysisEndpoint);

        if (!response.ok) {
            console.error('Ошибка загрузки анализов, статус:', response.status);
            emailAnalyses = {};
            return;
        }
        
        const data = await response.json();
        //console.log('Получены данные анализов (raw):', data);
        
        emailAnalyses = {};
        
        // Обрабатываем массив анализов и индексируем по email
        if (Array.isArray(data)) {
            data.forEach(analysis => {
                if (analysis.email) {
                    emailAnalyses[analysis.email] = analysis;
                    //console.log('Добавлен анализ для email:', analysis.email);
                }
            });
        }
        
        //console.log('✅ Загружено анализов email:', Object.keys(emailAnalyses).length);
        //console.log('Email в emailAnalyses:', Object.keys(emailAnalyses));
        
        // Обновляем таблицу после загрузки анализов
        if (document.getElementById('emailTableContainer') && 
            document.getElementById('emailTableContainer').style.display !== 'none') {
            updateEmailTable();
        }
        
    } catch (error) {
        console.error('Ошибка загрузки анализов email:', error);
        emailAnalyses = {};
    }
}

// Загрузка сохраненных анализов email
async function loadEmailAnalyses() {
    try {
        //console.log('Загружаем анализы email с:', config.getAllEmailAnalysisEndpoint);
        const response = await authFetch(config.getAllEmailAnalysisEndpoint);

        if (!response.ok) {
            console.error('Ошибка загрузки анализов, статус:', response.status);
            return;
        }

        const data = await response.json();
        //console.log('Получены данные анализов:', data);

        if (data && data.analyses) {
            emailAnalyses = {};
            if (Array.isArray(data.analyses)) {
                data.analyses.forEach(analysis => {
                    if (analysis.threadId) {
                        emailAnalyses[analysis.threadId] = analysis;
                    }
                });
            } else {
                emailAnalyses = data.analyses;
            }
            //console.log('✅ Загружено анализов email:', Object.keys(emailAnalyses).length);
            //console.log('Анализы по threadId:', Object.keys(emailAnalyses));
        }
    } catch (error) {
        console.error('Ошибка загрузки анализов email:', error);
        emailAnalyses = {};
    }
}

// Применение фильтров для email
function applyEmailFilters() {
    const searchText = document.getElementById('emailSearchBox')?.value.toLowerCase() || '';
    const period = document.getElementById('periodFilter').value;
    
    let startDate = new Date();
    let endDate = new Date();
    
    // Применяем фильтр периода
    if (period === '1h') {
        startDate.setHours(startDate.getHours() - 1);
    } else if (period === '24h') {
        startDate.setHours(startDate.getHours() - 24);
    } else if (period === '7d') {
        startDate.setDate(startDate.getDate() - 7);
    } else if (period === '30d') {
        startDate.setDate(startDate.getDate() - 30);
    } else if (period === 'custom') {
        const customStart = document.getElementById('startDate').value;
        const customEnd = document.getElementById('endDate').value;
        if (customStart) startDate = new Date(customStart);
        if (customEnd) endDate = new Date(customEnd);
    }
    
    filteredEmailData = emailData.filter(item => {
        // Фильтр по периоду
        const itemDate = new Date(item.lastActivity || item.timestamp || 0);
        if (itemDate < startDate || itemDate > endDate) return false;
        
        // Фильтр по поиску
        if (searchText) {
            const searchFields = [
                item.email || '',
                item.senderName || '',
                item.subject || '',
                item.status || ''
            ].join(' ').toLowerCase();
            
            if (!searchFields.includes(searchText)) return false;
        }
        return true;
    });
    
    currentEmailPage = 1;
    updateEmailTable();
}

// Обновление таблицы email
function updateEmailTable() {
    const tbody = document.getElementById('emailTableBody');
    const mobileCards = document.getElementById('emailMobileCards');
    const itemsPerPage = 20;
    
    const startIndex = (currentEmailPage - 1) * itemsPerPage;
    const endIndex = startIndex + itemsPerPage;
    const pageData = filteredEmailData.slice(startIndex, endIndex);
    
    if (pageData.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="9" style="text-align: center; padding: 40px;">
                    ${MonitoringConfigManager.getTranslation('emailMonitoring.table.noData')}
                </td>
            </tr>
        `;
        mobileCards.innerHTML = `
            <div style="text-align: center; padding: 40px;">
                ${MonitoringConfigManager.getTranslation('emailMonitoring.table.noData')}
            </div>
        `;
        previousEmailTableData = {};
        updateEmailPagination(0);
        return;
    }

    // Удаляем сообщение "Нет данных" если оно есть
    const noDataRow = tbody.querySelector('tr td[colspan="9"]');
    if (noDataRow) {
        noDataRow.parentElement.remove();
    }

    const actionTranslations = MonitoringConfigManager.getTranslation('emailMonitoring.table.actions');
    const displaySettings = MonitoringConfigManager.getDisplaySettings();
    
    // Создаем карту текущих данных
    const currentDataMap = {};
    pageData.forEach(item => {
        currentDataMap[item.email] = item;
    });
    
    // Находим существующие строки
    const existingRows = {};
    tbody.querySelectorAll('tr[data-email-row]').forEach(row => {
        const emailAddress = row.getAttribute('data-email-row');
        existingRows[emailAddress] = row;
    });
    
    // 1. Удаляем строки, которых больше нет
    Object.keys(existingRows).forEach(emailAddress => {
        if (!currentDataMap[emailAddress]) {
            const row = existingRows[emailAddress];
            row.classList.add('table-row-removed');
            setTimeout(() => row.remove(), 300);
        }
    });
    
    // 2. Добавляем новые строки и обновляем существующие
    pageData.forEach((item, index) => {
        const emailAddress = item.email;
        const existingRow = existingRows[emailAddress];
        
        if (!existingRow) {
            // 🔥 НОВАЯ СТРОКА
            const leadScore = item.leadScore || 0;
            const satisfaction = item.satisfactionPercentage || 0;
            const leadClass = leadScore >= 80 ? 'hot' : leadScore >= 50 ? 'warm' : 'cold';
            const satisfactionClass = satisfaction >= 70 ? 'satisfaction-high' : 
                                     satisfaction >= 40 ? 'satisfaction-medium' : 'satisfaction-low';
            
            const hasAnalysis = emailAnalyses && emailAnalyses[emailAddress];
            const contactData = emailContactsData[emailAddress] || {};
            const displayName = contactData.full_name || contactData.name || item.userName || item.senderName || '—';
            
            const newRow = document.createElement('tr');
            newRow.className = 'table-row-new';
            newRow.setAttribute('data-email-row', emailAddress);
            newRow.innerHTML = `
                <td data-field="leadScore">
                    <div class="lead-score-cell">
                        <div class="lead-score-indicator ${leadClass}">
                            ${leadScore}
                        </div>
                    </div>
                </td>
                <td data-field="email">${emailAddress || ''}</td>
                <td data-field="name">${displayName}</td>
                <td data-field="subject" style="max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" 
                    title="${item.subject || ''}">${item.subject || '—'}</td>
                <td data-field="status">${getEmailStatus(item.status)}</td>
                <td data-field="satisfaction">
                    <span class="satisfaction-indicator ${satisfactionClass}">
                        ${satisfaction}%
                    </span>
                </td>
                <td data-field="messages">${item.messageCount || 0}</td>
                <td data-field="lastActivity">${formatRelativeTime(item.lastActivity)}</td>
                <td data-field="actions">
                    <div class="action-buttons">
                        ${displaySettings.tableColumns.actionButtons.viewDialog !== false ? `
                            <button class="view-dialog-btn" onclick="viewEmailDialog('${emailAddress}')" 
                                    title="${actionTranslations.viewDialog}">
                                📋
                            </button>
                        ` : ''}
                        ${displaySettings.tableColumns.actionButtons.analyze !== false ? `
                            <button class="analyze-btn" onclick="analyzeEmailDialog('${emailAddress}')"
                                    title="${actionTranslations.runAnalysis}">
                                🔍
                            </button>
                        ` : ''}
                        ${displaySettings.tableColumns.actionButtons.viewAnalysis !== false && hasAnalysis ? `
                            <button class="view-analysis-btn" onclick="viewEmailAnalysis('${emailAddress}')"
                                    title="${actionTranslations.viewAnalysis}">
                                📊
                            </button>
                        ` : ''}
                        ${displaySettings.tableColumns.actionButtons.extractContacts !== false ? `
                            <button class="extract-contacts-btn" 
                                    onclick="extractEmailContacts('${emailAddress}')"
                                    title="${emailContactsData[emailAddress] && (emailContactsData[emailAddress].name || emailContactsData[emailAddress].full_name || emailContactsData[emailAddress].phone || emailContactsData[emailAddress].email) ? actionTranslations.updateContacts || actionTranslations.extractContacts : actionTranslations.extractContacts}">
                                ${emailContactsData[emailAddress] && (emailContactsData[emailAddress].name || emailContactsData[emailAddress].full_name || emailContactsData[emailAddress].phone || emailContactsData[emailAddress].email) ? '🔄' : '📇'}
                            </button>
                        ` : ''}
                        ${displaySettings.tableColumns.actionButtons.deleteRecord !== false ? `
                            <button class="delete-btn action-btn" onclick="deleteEmailRecord('${emailAddress}')"
                                    title="${actionTranslations.deleteRecord}">
                                🗑️
                            </button>
                        ` : ''}
                    </div>
                </td>
            `;
            
            const rows = tbody.querySelectorAll('tr[data-email-row]');
            if (index < rows.length) {
                tbody.insertBefore(newRow, rows[index]);
            } else {
                tbody.appendChild(newRow);
            }
            
            setTimeout(() => newRow.classList.remove('table-row-new'), 50);
            
        } else {
            // 🔥 ОБНОВЛЕНИЕ СУЩЕСТВУЮЩЕЙ СТРОКИ
            const previousData = previousEmailTableData[emailAddress];
            
            if (previousData) {
                const contactData = emailContactsData[emailAddress] || {};
                const displayName = contactData.full_name || contactData.name || item.userName || item.senderName || '—';
                const leadScore = item.leadScore || 0;
                const satisfaction = item.satisfactionPercentage || 0;
                const leadClass = leadScore >= 80 ? 'hot' : leadScore >= 50 ? 'warm' : 'cold';
                const satisfactionClass = satisfaction >= 70 ? 'satisfaction-high' : 
                                         satisfaction >= 40 ? 'satisfaction-medium' : 'satisfaction-low';
                
                // Проверяем изменения по полям
                const updates = {
                    leadScore: previousData.leadScore !== leadScore,
                    name: (previousData.contactData?.full_name || previousData.contactData?.name) !== displayName,
                    subject: previousData.subject !== item.subject,
                    status: previousData.status !== item.status,
                    satisfaction: previousData.satisfactionPercentage !== satisfaction,
                    messages: previousData.messageCount !== item.messageCount,
                    lastActivity: previousData.lastActivity !== item.lastActivity
                };
                
                // Обновляем только измененные ячейки
                Object.keys(updates).forEach(field => {
                    if (updates[field]) {
                        const cell = existingRow.querySelector(`td[data-field="${field}"]`);
                        if (cell) {
                            cell.classList.add('cell-updated');
                            setTimeout(() => cell.classList.remove('cell-updated'), 600);
                            
                            // Обновляем содержимое
                            if (field === 'leadScore') {
                                cell.innerHTML = `
                                    <div class="lead-score-cell">
                                        <div class="lead-score-indicator ${leadClass}">
                                            ${leadScore}
                                        </div>
                                    </div>
                                `;
                            } else if (field === 'name') {
                                cell.textContent = displayName;
                            } else if (field === 'subject') {
                                cell.setAttribute('title', item.subject || '');
                                cell.textContent = item.subject || '—';
                            } else if (field === 'status') {
                                cell.textContent = getEmailStatus(item.status);
                            } else if (field === 'satisfaction') {
                                cell.innerHTML = `
                                    <span class="satisfaction-indicator ${satisfactionClass}">
                                        ${satisfaction}%
                                    </span>
                                `;
                            } else if (field === 'messages') {
                                cell.textContent = item.messageCount || 0;
                            } else if (field === 'lastActivity') {
                                cell.textContent = formatRelativeTime(item.lastActivity);
                            }
                        }
                    }
                });
            }
            
            // Проверяем позицию
            const rows = Array.from(tbody.querySelectorAll('tr[data-email-row]'));
            const currentIndex = rows.indexOf(existingRow);
            if (currentIndex !== index && index < rows.length) {
                tbody.insertBefore(existingRow, rows[index]);
            }
        }
    });
    
    // Сохраняем текущие данные для следующего обновления
    previousEmailTableData = {};
    pageData.forEach(item => {
        previousEmailTableData[item.email] = {
            ...item,
            contactData: emailContactsData[item.email]
        };
    });
    
    // 🔥 ТВОЙ КОД ДЛЯ МОБИЛЬНЫХ КАРТОЧЕК
    const newCardsHTML = pageData.map(item => {
        const leadScore = item.leadScore || 0;
        const satisfaction = item.satisfactionPercentage || 0;
        const leadClass = leadScore >= 80 ? 'hot' : leadScore >= 50 ? 'warm' : 'cold';
        const satisfactionClass = satisfaction >= 70 ? 'satisfaction-high' : 
                                 satisfaction >= 40 ? 'satisfaction-medium' : 'satisfaction-low';
        const emailAddress = item.email;
        const hasAnalysis = emailAnalyses && emailAnalyses[emailAddress];
        
        const contactData = emailContactsData[emailAddress] || {};
        const displayName = contactData.full_name || contactData.name || item.userName || item.senderName || 
                           MonitoringConfigManager.getTranslation('emailMonitoring.table.noName');
        const actionTranslations = MonitoringConfigManager.getTranslation('emailMonitoring.table.actions');
        const displaySettings = MonitoringConfigManager.getDisplaySettings();
        const actionButtons = displaySettings.tableColumns.actionButtons || {
            viewDialog: true,
            analyze: true,
            viewAnalysis: true,
            extractContacts: true,
            deleteRecord: true
        };
        
        return `
            <div class="user-card user-card-enter" data-email-card="${emailAddress}">
                <div class="user-card-header">
                    <div style="display: flex; align-items: center; gap: 15px;">
                        <div class="lead-score-indicator ${leadClass}">${leadScore}</div>
                        <div>
                            <strong>${displayName}</strong>
                            <div style="font-size: 11px; color: var(--text-secondary); margin-top: 3px;">
                                ${emailAddress}
                            </div>
                            <div style="margin-top: 5px;">
                                ${getEmailStatus(item.status)}
                            </div>
                        </div>
                    </div>
                </div>
                <div class="user-card-info">
                    <div class="info-row">
                        <span class="info-label">${MonitoringConfigManager.getTranslation('emailMonitoring.table.columns.subject')}:</span>
                        <span class="info-value">${item.subject || '—'}</span>
                    </div>
                    <div class="info-row">
                        <span class="info-label">${MonitoringConfigManager.getTranslation('emailMonitoring.table.columns.messages')}:</span>
                        <span class="info-value">${item.messageCount || 0}</span>
                    </div>
                    <div class="info-row">
                        <span class="info-label">${MonitoringConfigManager.getTranslation('emailMonitoring.table.columns.satisfaction')}:</span>
                        <span class="info-value">
                            <span class="satisfaction-indicator ${satisfactionClass}">${satisfaction}%</span>
                        </span>
                    </div>
                    <div class="info-row">
                        <span class="info-label">${MonitoringConfigManager.getTranslation('emailMonitoring.table.columns.lastActivity')}:</span>
                        <span class="info-value">${formatRelativeTime(item.lastActivity)}</span>
                    </div>
                </div>
                <div class="user-card-actions">
                    ${actionButtons.viewDialog !== false ? `
                        <button class="view-dialog-btn" onclick="viewEmailDialog('${emailAddress}')">
                            📋 ${actionTranslations.viewDialog}
                        </button>
                    ` : ''}
                    ${actionButtons.analyze !== false ? `
                        <button class="analyze-btn" onclick="analyzeEmailDialog('${emailAddress}')">
                            🔍 ${actionTranslations.runAnalysis}
                        </button>
                    ` : ''}
                    ${actionButtons.viewAnalysis !== false && hasAnalysis ? `
                        <button class="view-analysis-btn" onclick="viewEmailAnalysis('${emailAddress}')">
                            📊 ${actionTranslations.viewAnalysis}
                        </button>
                    ` : ''}
                    ${actionButtons.extractContacts !== false ? `
                        <button class="extract-contacts-btn" onclick="extractEmailContacts('${emailAddress}')">
                            ${contactData && (contactData.name || contactData.full_name || contactData.phone || contactData.email) ? '🔄' : '📇'} ${actionTranslations.extractContacts}
                        </button>
                    ` : ''}
                    ${actionButtons.deleteRecord !== false ? `
                        <button class="delete-btn action-btn" onclick="deleteEmailRecord('${emailAddress}')">
                            🗑️ ${actionTranslations.deleteRecord}
                        </button>
                    ` : ''}
                </div>
            </div>
        `;
    }).join('');

    // Плавное обновление мобильных карточек
    requestAnimationFrame(() => {
        mobileCards.style.opacity = '0.7';
        setTimeout(() => {
            mobileCards.innerHTML = newCardsHTML;
            mobileCards.style.opacity = '1';
        }, 100);
    });

    // Обновление пагинации
    updateEmailPagination(filteredEmailData.length);
}

// Получение статуса email
function getEmailStatus(status) {
    const statusTranslations = MonitoringConfigManager.getTranslation('emailMonitoring.table.status');
    
    // Маппинг для преобразования разных вариантов в ключи из конфигурации
    const statusMapping = {
        'new': 'new',
        'unread': 'unread',
        'waiting': 'waiting',
        'awaiting_reply': 'waiting',  // awaiting_reply это тот же waiting
        'awaiting': 'waiting',        // возможный вариант
        'pending': 'waiting',          // возможный вариант
        'conversation': 'conversation',
        'active': 'conversation',      // возможный вариант
        'inactive': 'inactive',
        'closed': 'inactive'           // возможный вариант
    };
    
    // Приводим к нижнему регистру для сравнения
    const lowerStatus = (status || '').toLowerCase().replace(/_/g, '');
    
    // Получаем ключ для перевода
    const translationKey = statusMapping[lowerStatus] || statusMapping[status] || 'inactive';
    
    // Возвращаем перевод из конфигурации
    return statusTranslations[translationKey] || statusTranslations.inactive || status;
}

// Форматирование относительного времени
function formatRelativeTime(timestamp) {
    if (!timestamp) return '—';
    
    const now = new Date();
    const date = new Date(timestamp);
    const diff = now - date;
    
    const minutes = Math.floor(diff / 60000);
    const hours = Math.floor(diff / 3600000);
    const days = Math.floor(diff / 86400000);
    
    if (minutes < 1) return 'Только что';
    if (minutes < 60) return `${minutes} мин назад`;
    if (hours < 24) return `${hours} ч назад`;
    if (days < 7) return `${days} дн назад`;
    
    return date.toLocaleDateString('ru-RU');
}

// Обновление пагинации email
function updateEmailPagination(totalItems) {
    const totalPages = Math.ceil(totalItems / 20);
    const pageNumbers = document.getElementById('emailPageNumbers');
    
    let paginationHTML = '';
    const maxVisiblePages = 5;
    let startPage = Math.max(1, currentEmailPage - Math.floor(maxVisiblePages / 2));
    let endPage = Math.min(totalPages, startPage + maxVisiblePages - 1);
    
    if (endPage - startPage < maxVisiblePages - 1) {
        startPage = Math.max(1, endPage - maxVisiblePages + 1);
    }
    
    for (let i = startPage; i <= endPage; i++) {
        paginationHTML += `
            <div class="page-number ${i === currentEmailPage ? 'active' : ''}" 
                 onclick="goToEmailPage(${i})">
                ${i}
            </div>
        `;
    }
    
    pageNumbers.innerHTML = paginationHTML;
    
    document.getElementById('emailPrevPage').disabled = currentEmailPage === 1;
    document.getElementById('emailNextPage').disabled = currentEmailPage === totalPages || totalPages === 0;
}

// Навигация по страницам email
function goToEmailPage(page) {
    currentEmailPage = page;
    updateEmailTable();
}

function changeEmailPage(direction) {
    currentEmailPage += direction;
    updateEmailTable();
}

// Сортировка таблицы email
let emailSortField = 'lastActivity';
let emailSortDirection = 'desc';

function sortEmailTable(field) {
    // Переключаем направление сортировки
    if (emailSortField === field) {
        emailSortDirection = emailSortDirection === 'asc' ? 'desc' : 'asc';
    } else {
        emailSortField = field;
        emailSortDirection = 'desc';
    }
    
    filteredEmailData.sort((a, b) => {
        let aVal = a[field];
        let bVal = b[field];
        
        // Обработка разных типов данных
        if (field === 'lastActivity') {
            aVal = new Date(aVal || 0).getTime();
            bVal = new Date(bVal || 0).getTime();
        } else if (field === 'leadScore' || field === 'messages') {
            aVal = parseInt(aVal) || 0;
            bVal = parseInt(bVal) || 0;
        } else if (field === 'satisfaction') {
            aVal = parseInt(a.satisfactionPercentage) || 0;
            bVal = parseInt(b.satisfactionPercentage) || 0;
        } else if (field === 'email' || field === 'name' || field === 'subject' || field === 'status') {
            aVal = (aVal || '').toString().toLowerCase();
            bVal = (bVal || '').toString().toLowerCase();
        }
        
        // Применяем сортировку
        if (emailSortDirection === 'asc') {
            return aVal > bVal ? 1 : -1;
        } else {
            return aVal < bVal ? 1 : -1;
        }
    });
    
    updateEmailTable();
}

// Просмотр email диалога
async function viewEmailDialog(emailAddress) {
    const modal = document.getElementById('dialogModal');
    const body = document.getElementById('dialogBody');
    const title = document.getElementById('dialogTitle');
    
    window.scrollPosition = window.pageYOffset || document.documentElement.scrollTop;
document.body.classList.add('modal-open');
document.body.style.top = `-${window.scrollPosition}px`;
    modal.style.display = 'block';
    
    body.innerHTML = `
        <div class="loading-spinner">
            <div class="spinner"></div>
            <p>${MonitoringConfigManager.getTranslation('dialogs.dialog.loading')}</p>
        </div>
    `;

    title.textContent = `📧 Email ${MonitoringConfigManager.getTranslation('dialogs.dialog.title')}`;

    try {
        const response = await authFetch(`${config.emailDialogsEndpoint}?email=${encodeURIComponent(emailAddress)}`);
        const data = await response.json();
        
        if (data && data.dialogs) {
            // Показываем тему один раз вверху, если она есть
            const firstMessageWithSubject = data.dialogs.find(msg => msg.subject);
            const subject = firstMessageWithSubject ? firstMessageWithSubject.subject : '';
            
            body.innerHTML = (subject ? `
                <div style="padding: 15px; background: var(--secondary-bg); border-radius: 8px; margin-bottom: 20px;">
                    <strong>${MonitoringConfigManager.getTranslation('emailMonitoring.table.columns.subject')}:</strong> ${subject}
                </div>
            ` : '') + 
            data.dialogs.map(msg => `
                <div class="dialog-message ${msg.message_type}">
                    <div style="display: flex; justify-content: space-between; margin-bottom: 8px;">
                        <strong style="color: ${msg.message_type === 'user' ? 'var(--accent-primary)' : 'var(--success)'};">
                            ${msg.message_type === 'user' ? '📧 ' + (msg.email || MonitoringConfigManager.getTranslation('dialogs.dialog.user')) : '✉️ ' + MonitoringConfigManager.getTranslation('dialogs.dialog.bot')}
                        </strong>
                        <span style="font-size: 11px; color: var(--text-secondary);">
                            ${formatDate(msg.timestamp)}
                        </span>
                    </div>
                    <div class="message-content">${msg.message_text}</div>
                </div>
            `).join('');
        } else {
            body.innerHTML = `<p style="text-align: center;">${MonitoringConfigManager.getTranslation('dialogs.dialog.notFound')}</p>`;
        }
    } catch (error) {
        console.error('Ошибка загрузки email диалога:', error);
        body.innerHTML = `<p style="color: var(--danger);">${MonitoringConfigManager.getTranslation('dialogs.dialog.error')}</p>`;
    }
}

// Анализ email диалога
async function analyzeEmailDialog(emailAddress) {
    const modal = document.getElementById('analysisModal');
    const body = document.getElementById('analysisBody');
    const title = document.getElementById('analysisTitle');
    
    modal.style.display = 'block';
    window.scrollPosition = window.pageYOffset || document.documentElement.scrollTop;
document.body.classList.add('modal-open');
document.body.style.top = `-${window.scrollPosition}px`;
    
    body.innerHTML = `
        <div class="loading-spinner">
            <div class="spinner"></div>
            <p>${MonitoringConfigManager.getTranslation('dialogs.analysis.loading')}</p>
        </div>
    `;

    title.textContent = `📧 ${MonitoringConfigManager.getTranslation('dialogs.analysis.title')}`;

    try {
        const response = await authFetch(config.analyzeEmailEndpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email: emailAddress })
        });
        
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        const analysis = await response.json();
        
        if (analysis) {
            // Сохраняем анализ по email
            emailAnalyses[emailAddress] = analysis;
            //console.log('Анализ сохранен для email:', emailAddress);
            
            displayAnalysisResults(body, analysis);
            
            setTimeout(() => {
                updateEmailTable();
            }, 1000);
        }
        
    } catch (error) {
        console.error('Ошибка анализа email:', error);
        body.innerHTML = `<p style="color: var(--danger);">${MonitoringConfigManager.getTranslation('dialogs.analysis.error')}</p>`;
    }
}

// Просмотр анализа email
async function viewEmailAnalysis(emailAddress) {
    const modal = document.getElementById('analysisModal');
    const body = document.getElementById('analysisBody');
    const title = document.getElementById('analysisTitle');
    
    modal.style.display = 'block';
    window.scrollPosition = window.pageYOffset || document.documentElement.scrollTop;
document.body.classList.add('modal-open');
document.body.style.top = `-${window.scrollPosition}px`;
    
    body.innerHTML = `
        <div class="loading-spinner">
            <div class="spinner"></div>
            <p>${MonitoringConfigManager.getTranslation('dialogs.dialog.loading')}</p>
        </div>
    `;
    
    title.textContent = `📧 ${MonitoringConfigManager.getTranslation('dialogs.analysis.title')}`;

    try {
        // Загружаем анализ с сервера по email
        const response = await authFetch(`${config.getEmailAnalysisEndpoint}?email=${encodeURIComponent(emailAddress)}`);
        
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        const analysis = await response.json();
        //console.log('Загруженный анализ для просмотра:', analysis);
        
        // Если анализ найден, отображаем его
        if (analysis && analysis.found) {
            displayAnalysisResults(body, analysis);
        } else {
            body.innerHTML = `<p style="text-align: center; color: var(--text-secondary);">${MonitoringConfigManager.getTranslation('dialogs.dialog.notFound')}</p>`;
        }
        
    } catch (error) {
        console.error('Ошибка загрузки анализа:', error);
        body.innerHTML = `<p style="color: var(--danger); text-align: center;">${MonitoringConfigManager.getTranslation('dialogs.analysis.error')}</p>`;
    }
}

// Извлечение контактов из email
async function extractEmailContacts(emailAddress) {
    try {
        showNotification(`⌛ ${MonitoringConfigManager.getTranslation('contacts.extracting')}`, 'info');

        const response = await authFetch(config.extractEmailContactsEndpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email: emailAddress })
        });
        
        if (response.ok) {
            // Перезагружаем контактные данные после извлечения
            await loadEmailContactsData();
            showNotification(`✅ ${MonitoringConfigManager.getTranslation('contacts.extracted')}`, 'success');
            // Обновляем таблицу для отображения новых имен
            updateEmailTable();
        }
    } catch (error) {
        console.error('Ошибка извлечения контактов:', error);
        showNotification(`❌ ${MonitoringConfigManager.getTranslation('contacts.extractError')}`, 'error');
    }
}

// Загрузка контактных данных email
async function loadEmailContactsData() {
    try {
        const response = await authFetch(config.getEmailContactsEndpoint);
        const data = await response.json();
        
        if (data.contacts) {
            // Преобразуем массив контактов в объект с ключами по email
            emailContactsData = {};
            if (Array.isArray(data.contacts)) {
                data.contacts.forEach(contact => {
                    if (contact.email) {
                        emailContactsData[contact.email] = {
                            name: contact.full_name || contact.name || '',
                            phone: contact.phone || '',
                            email: contact.email,
                            company: contact.company || '',
                            position: contact.position || '',
                            messengers: contact.other_contacts || '',
                            full_name: contact.full_name || ''  // Явно добавляем full_name
                        };
                    }
                });
            } else {
                emailContactsData = data.contacts;
            }
            
            console.log('✅ Контактные данные email загружены:', Object.keys(emailContactsData).length);
            updateEmailTable();
        }
    } catch (error) {
        console.error('Ошибка загрузки контактов email:', error);
        emailContactsData = {};
    }
}

// Загрузка текущего языка результатов анализа
async function loadAnalysisResultLanguage() {
    try {
        // Проверяем доступность конфигурации
        if (!MonitoringConfigManager || !MonitoringConfigManager.getTechnicalSettings) {
            console.error('MonitoringConfigManager не доступен при загрузке языка');
            currentAnalysisResultLanguage = 'ru';
            updateResultLanguageButton();
            return;
        }
        
        const config = MonitoringConfigManager.getTechnicalSettings();
        
        if (!config.getAnalysisLanguageEndpoint) {
            console.error('getAnalysisLanguageEndpoint не найден в конфигурации');
            currentAnalysisResultLanguage = 'ru';
            updateResultLanguageButton();
            return;
        }
        
        // Проверяем настройку автоматической синхронизации
        const syncConfig = MonitoringConfig.analysisLanguageSync || {};
        const autoSync = syncConfig.autoSync === true;
        
        if (autoSync) {
            // РЕЖИМ АВТОСИНХРОНИЗАЦИИ: устанавливаем язык анализа = языку интерфейса
            const interfaceLanguage = MonitoringConfigManager.getLanguage();

            if (config.setAnalysisLanguageEndpoint) {
                const setResponse = await authFetch(config.setAnalysisLanguageEndpoint, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ language: interfaceLanguage })
                });
                
                if (setResponse.ok) {
                    currentAnalysisResultLanguage = interfaceLanguage;
                    console.log(`Язык анализа автоматически синхронизирован: ${interfaceLanguage}`);
                } else {
                    console.error('Ошибка автосинхронизации языка:', setResponse.status);
                    currentAnalysisResultLanguage = interfaceLanguage;
                }
            } else {
                currentAnalysisResultLanguage = interfaceLanguage;
            }
        } else {
            // ОБЫЧНЫЙ РЕЖИМ: загружаем сохранённый язык с сервера
            const response = await authFetch(config.getAnalysisLanguageEndpoint);
            
            if (response.ok) {
                const data = await response.json();
                
                if (data && data.language) {
                    currentAnalysisResultLanguage = data.language;
                } else {
                    currentAnalysisResultLanguage = 'ru';
                }
            } else {
                console.error('Ошибка загрузки языка анализа:', response.status);
                currentAnalysisResultLanguage = 'ru';
            }
        }
    } catch (error) {
        console.error('Ошибка при работе с языком анализа:', error);
        currentAnalysisResultLanguage = 'ru';
    }
    
    // Обновляем кнопку в любом случае
    setTimeout(() => {
        updateResultLanguageButton();
    }, 100);
}

// Обновление кнопки языка результатов
function updateResultLanguageButton() {
    const btn = document.getElementById('resultLanguageBtn');
    if (!btn) {
        console.log('Кнопка еще не готова, повторяем через 100мс');
        setTimeout(updateResultLanguageButton, 100);
        return;
    }
    
    const flagElement = document.getElementById('resultLanguageFlag');
    const textElement = document.getElementById('resultLanguageText');
    
    if (!flagElement || !textElement) {
        console.log('Элементы кнопки не найдены');
        return;
    }
    
    // Проверяем наличие конфигурации
    if (!MonitoringConfig || !MonitoringConfig.availableResultLanguages) {
        console.error(MonitoringConfigManager.getTranslation('analysisResultLanguage.configError'));
        flagElement.textContent = '🌐';
        textElement.textContent = 'Русский';
        return;
    }
    
    const languages = MonitoringConfig.availableResultLanguages;
    const currentLang = MonitoringConfigManager.getLanguage();
    
    // Устанавливаем значение по умолчанию если не задано
    if (!currentAnalysisResultLanguage) {
        currentAnalysisResultLanguage = 'ru';
    }
    
    //console.log('Обновляем кнопку для языка:', currentAnalysisResultLanguage);
    
    if (languages[currentAnalysisResultLanguage]) {
        const langConfig = languages[currentAnalysisResultLanguage];
        flagElement.textContent = langConfig.flag || '🌐';
        textElement.textContent = langConfig.labels[currentLang] || langConfig.labels.en || 'Русский';
        //console.log('Кнопка обновлена:', textElement.textContent);
    } else {
        // Значения по умолчанию
        flagElement.textContent = '🌐';
        textElement.textContent = MonitoringConfigManager.getTranslation('formatting.loading') || 'Loading...';
    }
}

// Открытие модального окна выбора языка результатов
function openResultLanguageModal() {
    // Проверяем существование модального окна
    const modal = document.getElementById('resultLanguageModal');
    if (!modal) {
        console.error('Модальное окно выбора языка результатов не найдено');
        return;
    }
    
    // Заполняем кнопки языков
    populateResultLanguageButtons();
    
    // Показываем модальное окно
    modal.style.display = 'block';
    window.scrollPosition = window.pageYOffset || document.documentElement.scrollTop;
document.body.classList.add('modal-open');
document.body.style.top = `-${window.scrollPosition}px`;
}

// Закрытие модального окна выбора языка результатов
function closeResultLanguageModal(event) {
    if (!event || event.target.id === 'resultLanguageModal') {
        document.getElementById('resultLanguageModal').style.display = 'none';
        document.body.classList.remove('modal-open');
        document.body.style.top = '';
        window.scrollTo(0, window.scrollPosition || 0);
    }
}

// Заполнение кнопок выбора языка результатов
function populateResultLanguageButtons() {
    const container = document.getElementById('resultLanguageOptionsContainer');
    if (!container) {
        console.error(MonitoringConfigManager.getTranslation('analysisResultLanguage.containerError'));
        return;
    }
    
    // Проверяем наличие конфигурации
    if (!MonitoringConfig) {
        console.error('MonitoringConfig не загружен');
        return;
    }
    
    // Используем availableAnalysisLanguages как запасной вариант
    const languages = MonitoringConfig.availableResultLanguages || MonitoringConfig.availableAnalysisLanguages;
    
    if (!languages) {
        console.error(MonitoringConfigManager.getTranslation('analysisResultLanguage.configError'));
        return;
    }
    
    const currentLang = MonitoringConfigManager.getLanguage();
    
    // Очищаем контейнер
    container.innerHTML = '';
    
    // Сортируем по order
    const sortedLanguages = Object.entries(languages)
        .filter(([key, lang]) => lang && lang.enabled)
        .sort((a, b) => (a[1].order || 0) - (b[1].order || 0));
    
    // Создаем кнопки
    sortedLanguages.forEach(([langCode, langConfig]) => {
        const button = document.createElement('button');
        button.className = 'language-btn';
        button.onclick = () => setAnalysisResultLanguage(langCode);
        button.innerHTML = `${langConfig.flag} <span>${langConfig.labels[currentLang] || langConfig.labels.en}</span>`;
        container.appendChild(button);
    });
}

// Установка нового языка результатов анализа
async function setAnalysisResultLanguage(language) {
    try {
        //console.log('Устанавливаем язык:', language);
        
        // Проверяем наличие endpoint
        if (!MonitoringConfigManager || !MonitoringConfigManager.getTechnicalSettings) {
            console.error('MonitoringConfigManager не доступен');
            return;
        }
        
        const config = MonitoringConfigManager.getTechnicalSettings();
        
        // Проверяем что endpoint существует
        if (!config.setAnalysisLanguageEndpoint) {
            console.error('setAnalysisLanguageEndpoint не найден в конфигурации');
            console.log('Доступные endpoints:', Object.keys(config));
            return;
        }
        //console.log('Отправляем запрос на:', config.setAnalysisLanguageEndpoint);
        const response = await authFetch(config.setAnalysisLanguageEndpoint, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ language: language })
        });
        
        //console.log('Ответ получен:', response.status);
        
        if (response.ok) {
            currentAnalysisResultLanguage = language;
            updateResultLanguageButton();
            closeResultLanguageModal();
            
            // Показываем уведомление
            const languages = MonitoringConfig.availableResultLanguages || MonitoringConfig.availableAnalysisLanguages;
            const currentLang = MonitoringConfigManager.getLanguage();
            const langName = languages[language].labels[currentLang] || languages[language].labels.en;
            
            notificationText = MonitoringConfigManager.getTranslation('analysisResultLanguage.notification').replace('{language}', langName);
            showNotification(`✅ ${notificationText}`, 'success');
        } else {
            console.error('Ошибка ответа:', response.status);
            showNotification(`⚠️ ${MonitoringConfigManager.getTranslation('analysisResultLanguage.setError')}`, 'error');
        }
    } catch (error) {
        console.error('Ошибка установки языка анализа:', error);
        showNotification('❌ Ошибка при установке языка', 'error');
    }
}

// Экспорт данных email
function exportEmailData() {
    const csvContent = "data:text/csv;charset=utf-8,"
        + "Email,Имя,Тема,Статус,Lead Score,Удовлетворенность,Сообщений,Последняя активность\n"
        + filteredEmailData.map(item => [
            item.email,
            item.senderName || '',
            `"${item.subject || ''}"`,
            item.status,
            item.leadScore || 0,
            item.satisfaction || 0,
            item.messageCount || 0,
            formatRelativeTime(item.lastActivity)
        ].join(',')).join("\n");
    
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement("a");
    link.setAttribute("href", encodedUri);
    link.setAttribute("download", `email_monitoring_${new Date().toISOString()}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
}

// Обработчик поиска для email
document.addEventListener('DOMContentLoaded', function() {
    const emailSearchBox = document.getElementById('emailSearchBox');
    if (emailSearchBox) {
        emailSearchBox.addEventListener('input', applyEmailFilters);
    }
});

// =====================================================
// КОНЕЦ ФУНКЦИЙ EMAIL МОНИТОРИНГА
// =====================================================

  // Проверка наличия сохраненного анализа
async function checkSavedAnalysis(sessionId) {
    try {
        const response = await authFetch(`${config.getAnalysisEndpoint}?session_id=${sessionId}&type=single`);
        const data = await response.json();
        return data.found;
    } catch (error) {
        return false;
    }
}

/// Загрузка всех сохраненных анализов
async function loadSavedAnalyses() {
    // Инициализируем, если не существует
    if (!window.savedAnalyses) {
        window.savedAnalyses = {};
    }
    try {
        const response = await authFetch(config.getAllAnalysisEndpoint);
        const data = await response.json();
        
        if (data.analyses) {
            savedAnalyses = data.analyses;
            
            // Убеждаемся, что у каждого анализа есть sessionId
            Object.keys(savedAnalyses).forEach(sessionId => {
                if (!savedAnalyses[sessionId].sessionId) {
                    savedAnalyses[sessionId].sessionId = sessionId;
                }
            });
            
            // ============ ДОБАВЬ ЭТУ СЕКЦИЮ ============
            // Парсим дополнительные данные анализа из базы
            Object.keys(savedAnalyses).forEach(sessionId => {
                const analysis = savedAnalyses[sessionId];
                
                // Парсим Lead Scoring если есть
                if (analysis.leadScoring && typeof analysis.leadScoring === 'string') {
                    try {
                        savedAnalyses[sessionId].leadScoring = JSON.parse(analysis.leadScoring);
                    } catch (e) {
                        console.error('Ошибка парсинга Lead Scoring для', sessionId, e);
                    }
                }
                
                // Парсим BANT квалификацию если есть
                if (analysis.bantQualification && typeof analysis.bantQualification === 'string') {
                    try {
                        savedAnalyses[sessionId].bantQualification = JSON.parse(analysis.bantQualification);
                    } catch (e) {
                        console.error('Ошибка парсинга BANT для', sessionId, e);
                    }
                }
                
                // Парсим эмоциональный тон если это строка
                if (analysis.emotionalTone && typeof analysis.emotionalTone === 'string') {
                    try {
                        savedAnalyses[sessionId].emotionalTone = JSON.parse(analysis.emotionalTone);
                    } catch (e) {
                        console.error('Ошибка парсинга emotionalTone для', sessionId, e);
                    }
                }
            });
            // ============ КОНЕЦ ДОБАВЛЕННОЙ СЕКЦИИ ============
            
            // Обновляем видимость кнопок и проценты удовлетворенности
            Object.keys(savedAnalyses).forEach(sessionId => {
                const btn = document.getElementById(`viewAnalysis_${sessionId}`);
                if (btn) {
                    btn.style.display = 'inline-flex';
                }
                
                // Обновляем процент удовлетворенности в таблице
                const satisfactionCells = document.querySelectorAll(`[data-session="${sessionId}"]`);
                satisfactionCells.forEach(cell => {
                    if (cell && cell.classList && cell.classList.contains('satisfaction-cell')) {
                        const percentage = savedAnalyses[sessionId].satisfactionPercentage || 0;
                        let className = 'satisfaction-low';
                        if (percentage >= 70) className = 'satisfaction-high';
                        else if (percentage >= 50) className = 'satisfaction-medium';
                        
                        cell.innerHTML = `
                            <span class="satisfaction-indicator ${className}">
                                ${percentage}%
                            </span>
                        `;
                    }
                });
            });
            
            //console.log(`✅ Загружено анализов: ${Object.keys(savedAnalyses).length}`);
        }
    } catch (error) {
        console.error('Ошибка загрузки сохраненных анализов:', error);
    }
}

// Функция обновления кнопок анализа
function updateAnalysisButtons() {
    if (!savedAnalyses || typeof savedAnalyses !== 'object') return;
    
    Object.keys(savedAnalyses).forEach(sessionId => {
        // Обновляем кнопки в десктопной версии
        const btn = document.getElementById(`viewAnalysis_${sessionId}`);
        if (btn) {
            btn.style.display = 'inline-flex';
        }
        
        // Обновляем проценты удовлетворенности
        const satisfactionCells = document.querySelectorAll(`[data-session="${sessionId}"]`);
        satisfactionCells.forEach(cell => {
            if (cell && cell.classList && cell.classList.contains('satisfaction-cell')) {
                const percentage = savedAnalyses[sessionId].satisfactionPercentage || 0;
                let className = 'satisfaction-low';
                if (percentage >= 70) className = 'satisfaction-high';
                else if (percentage >= 50) className = 'satisfaction-medium';
                
                cell.innerHTML = `
                    <span class="satisfaction-indicator ${className}">
                        ${percentage}%
                    </span>
                `;
            }
        });
    });
}

// Просмотр сохраненного анализа
async function viewSavedAnalysis(sessionId, userName) {
    const modal = document.getElementById('analysisModal');
    const body = document.getElementById('analysisBody');
    const title = document.getElementById('analysisTitle');
    
    // ✅ ИСПРАВЛЕНИЕ: Получаем реальное имя из контактных данных
    const contactData = userContactsData[sessionId] || {};
    const sessionData = allData.find(item => item.sessionId === sessionId);
    const guestTranslation = MonitoringConfigManager.getTranslation('formatting.guest');
    
    // Получаем переводы для сравнения
// Список всех возможных переводов "Guest/User/Пользователь"
const userTranslations = ['Guest', 'Пользователь', 'Гість', 'User', 'Usuario', 'Utilisateur', 'Benutzer', 'Utente', 'Usuário', '用户', 'ユーザー', '사용자', 'Користувач', 'Invitado', 'Invité', 'Gast', 'Ospite', 'Convidado', '访客', 'ゲスト', '게스트'];

// Получаем имя с проверкой
let displayName = contactData.name;

// Если нет имени в контактах, проверяем sessionData.userName
if (!displayName && sessionData?.userName) {
    displayName = userTranslations.includes(sessionData.userName) ? guestTranslation : sessionData.userName;
}

// Если всё ещё нет, проверяем переданный userName
if (!displayName && userName) {
    displayName = userTranslations.includes(userName) ? guestTranslation : userName;
}

// Если совсем нет имени, используем перевод "Гость"
if (!displayName) {
    displayName = guestTranslation;
}
    
    modal.style.display = 'block';
    // Блокируем прокрутку body
    document.body.classList.add('modal-open');
    
    body.innerHTML = `
        <div class="loading-spinner">
            <div class="spinner"></div>
            <p>${MonitoringConfigManager.getTranslation('dialogs.dialog.loading')}</p>
        </div>
    `;

    title.textContent = `${MonitoringConfigManager.getTranslation('dialogs.analysis.title')}: ${displayName}`;

    try {
        const response = await authFetch(`${config.getAnalysisEndpoint}?session_id=${sessionId}&type=single`);
        const data = await response.json();
        
        if (data.found) {
            // Добавляем sessionId к данным анализа
            data.sessionId = sessionId;
            displayAnalysisResults(body, data);
        
        } else {
            body.innerHTML = `<p style="color: var(--text-secondary); text-align: center;">${MonitoringConfigManager.getTranslation('dialogs.dialog.notFound')}</p>`;
        }
    } catch (error) {
        console.error('Ошибка загрузки анализа:', error);
        body.innerHTML = `<p style="color: var(--danger); text-align: center;">${MonitoringConfigManager.getTranslation('dialogs.analysis.error')}</p>`;
    }
}
// Функция обновления интерфейса из конфигурации
function updateUIFromConfig() {
    //console.log('🔄 Обновление страницы для применения новой конфигурации...');
    location.reload();
}
// =====================================================
// ФУНКЦИИ КАРТОЧКИ КЛИЕНТА
// =====================================================

// Обновленная функция openClientCard с полной поддержкой многоязычности
async function openClientCard(sessionId) {
    const modal = document.getElementById('clientCardModal');
    const body = document.getElementById('clientCardBody');
    const title = document.getElementById('clientCardTitle');
    
    // ⭐ ИСПРАВЛЕНИЕ: Собираем ВСЕ данные для sessionId (как в таблице)
    const allSessionItems = allData.filter(item => item.sessionId === sessionId);
    
    if (!allSessionItems || allSessionItems.length === 0) {
        showError(MonitoringConfigManager.getTranslation('notifications.clientDataNotFound'));
        return;
    }
    
    // Берем первую запись как базу
    const firstItem = allSessionItems[0];
    
    // Собираем sessionData так же, как в таблице
    let sessionData = {
        sessionId: sessionId,
        ip: firstItem.geo?.ip || firstItem.ip || 'unknown',
        country: firstItem.geo?.country || firstItem.country || 'unknown',
        city: firstItem.geo?.city || firstItem.city || 'unknown',
        startTime: firstItem.sessionStartTime || firstItem.timestamp,
        lastActivity: firstItem.timestamp || firstItem.lastActivityTime,
        messages: 0,
        duration: 0,
        messageTimestamps: [],
       userName: firstItem.userName || MonitoringConfigManager.getTranslation('formatting.guest'),
        platform: firstItem.platform || 'webchat',
        configName: firstItem.configName
    };
    
    // Проходим по всем записям этой сессии
    allSessionItems.forEach(item => {
        sessionData.messages = Math.max(
            sessionData.messages, 
            item.messageCount || item.messages || 0
        );
        sessionData.lastActivity = item.timestamp || item.lastActivityTime;
        
        // Собираем messageTimestamps
        if (item.messageTimestamps && item.messageTimestamps.length > 0) {
            sessionData.messageTimestamps = item.messageTimestamps;
        }
    });
    
    // Пересчитываем duration так же, как в таблице
    const SESSION_TIMEOUT = 30 * 60 * 1000; // 30 минут между визитами (КАК В ТАБЛИЦЕ!)
    
    if (sessionData.messageTimestamps && sessionData.messageTimestamps.length > 0) {
        // Преобразуем timestamps в Date объекты
        const timestamps = sessionData.messageTimestamps.map(ts => new Date(ts)).filter(d => !isNaN(d.getTime()));
        
        if (timestamps.length > 0) {
            timestamps.sort((a, b) => a - b);
            
            let totalDuration = 0;
            let currentVisitStart = timestamps[0];
            let lastMessage = timestamps[0];
            
            for (let i = 1; i < timestamps.length; i++) {
                const currentMessage = timestamps[i];
                const timeSinceLastMsg = currentMessage - lastMessage;
                
                if (timeSinceLastMsg > SESSION_TIMEOUT) {
                    // Закрываем визит
                    const visitDuration = (lastMessage - currentVisitStart) / 1000;
                    totalDuration += Math.max(visitDuration, 60);
                    currentVisitStart = currentMessage;
                }
                
                lastMessage = currentMessage;
            }
            
            // Добавляем последний визит
            const lastVisitDuration = (lastMessage - currentVisitStart) / 1000;
            totalDuration += Math.max(lastVisitDuration, 60);
            
            sessionData.duration = Math.round(totalDuration);
        }
    } else {
        // Fallback: если нет messageTimestamps
        sessionData.duration = 0;
    }
    
    const contactData = userContactsData[sessionId] || {};
    const analysisData = savedAnalyses[sessionId] || null;
    
    // Блокируем прокрутку body
    window.scrollPosition = window.pageYOffset || document.documentElement.scrollTop;
document.body.classList.add('modal-open');
document.body.style.top = `-${window.scrollPosition}px`;
    modal.style.display = 'block';
    
    // Получаем все переводы для карточки клиента
    const translations = MonitoringConfigManager.getTranslation('clientCard');
    const contactTranslations = MonitoringConfigManager.getTranslation('contacts');
    const tableTranslations = MonitoringConfigManager.getTranslation('table');
    const dialogTranslations = MonitoringConfigManager.getTranslation('dialogs.dialog');
    const analysisTranslations = MonitoringConfigManager.getTranslation('analysis');
    
    // Определяем имя и инициалы
    const guestName = MonitoringConfigManager.getTranslation('formatting.guest');

// Список всех возможных переводов "Guest/User/Пользователь"
const userTranslations = ['Guest', 'Пользователь', 'Гість', 'User', 'Usuario', 'Utilisateur', 'Benutzer', 'Utente', 'Usuário', '用户', 'ユーザー', '사용자', 'Користувач', 'Invitado', 'Invité', 'Gast', 'Ospite', 'Convidado', '访客', 'ゲスト', '게스트'];

// Получаем имя с проверкой
let name = contactData.name;
if (!name && sessionData.userName) {
    name = userTranslations.includes(sessionData.userName) ? guestName : sessionData.userName;
}
if (!name) {
    name = guestName;
}
    const initials = getInitials(name);
    const isActive = (new Date() - new Date(sessionData.lastActivity || sessionData.timestamp)) < 300000;
    
    title.textContent = translations.title;
    
    // Парсим other_contacts для мессенджеров
    let otherContactsHTML = '';
    if (contactData.messengers) {
        // Разбираем строку мессенджеров вида "TG: @username, WA: +7999..."
        const messengers = contactData.messengers.split(',').map(m => m.trim());
        messengers.forEach(messenger => {
            if (messenger.includes('TG:')) {
                const tgUsername = messenger.replace('TG:', '').trim();
                otherContactsHTML += `
                    <div class="contact-item" onclick="window.open('https://t.me/${tgUsername.replace('@', '')}', '_blank')">
                        <div class="contact-icon">✈️</div>
                        <div class="contact-details">
                            <div class="contact-label">Telegram</div>
                            <div class="contact-value">
                                <a href="https://t.me/${tgUsername.replace('@', '')}" target="_blank">${tgUsername}</a>
                            </div>
                        </div>
                    </div>
                `;
            } else if (messenger.includes('WA:')) {
                const waNumber = messenger.replace('WA:', '').trim();
                otherContactsHTML += `
                    <div class="contact-item" onclick="window.open('https://wa.me/${waNumber.replace(/\D/g, '')}', '_blank')">
                        <div class="contact-icon">💚</div>
                        <div class="contact-details">
                            <div class="contact-label">WhatsApp</div>
                            <div class="contact-value">
                                <a href="https://wa.me/${waNumber.replace(/\D/g, '')}" target="_blank">${waNumber}</a>
                            </div>
                        </div>
                    </div>
                `;
            } else if (messenger.includes('IG:')) {
                const igUsername = messenger.replace('IG:', '').trim();
                otherContactsHTML += `
                    <div class="contact-item" onclick="window.open('https://instagram.com/${igUsername.replace('@', '')}', '_blank')">
                        <div class="contact-icon">📷</div>
                        <div class="contact-details">
                            <div class="contact-label">Instagram</div>
                            <div class="contact-value">
                                <a href="https://instagram.com/${igUsername.replace('@', '')}" target="_blank">${igUsername}</a>
                            </div>
                        </div>
                    </div>
                `;
            }
        });
    }
    
    // Формируем HTML карточки с использованием переводов
    body.innerHTML = `
        <div class="client-card-container">
            <!-- Левая панель -->
            <div class="client-sidebar">
                <div class="client-avatar">
                    ${initials}
                    <div class="client-status-badge ${isActive ? '' : 'inactive'}"></div>
                </div>
                
                <div class="client-name">
                    <h2>${name}</h2>
                    <div class="client-id">ID: ${sessionId.substring(0, 16)}...</div>
                </div>
                
                <div class="client-contacts">
                    ${contactData.phone ? `
                        <div class="contact-item" onclick="copyToClipboard('${contactData.phone}')" 
                             title="${translations.contact.copyToClipboard}">
                            <div class="contact-icon">📱</div>
                            <div class="contact-details">
                                <div class="contact-label">${translations.contact.phone}</div>
                                <div class="contact-value">
                                    <a href="tel:${contactData.phone}">${contactData.phone}</a>
                                </div>
                            </div>
                        </div>
                    ` : ''}
                    
                    ${contactData.email ? `
                        <div class="contact-item" onclick="copyToClipboard('${contactData.email}')"
                             title="${translations.contact.copyToClipboard}">
                            <div class="contact-icon">📧</div>
                            <div class="contact-details">
                                <div class="contact-label">${translations.contact.email}</div>
                                <div class="contact-value">
                                    <a href="mailto:${contactData.email}">${contactData.email}</a>
                                </div>
                            </div>
                        </div>
                    ` : ''}
                    
                    ${otherContactsHTML}
                </div>
                
                <div class="quick-actions">
                    ${!analysisData ? `
                        <button class="analyze-btn" onclick="analyzeUserDialog('${sessionId}', '${name}'); closeClientCard();">
                            🔍 ${translations.quickActions.analyze}
                        </button>
                    ` : ''}
                    ${!contactData.name && !contactData.phone && !contactData.email ? `
                        <button class="extract-contacts-btn" onclick="extractContactsForSession('${sessionId}'); closeClientCard();">
                            📇 ${translations.quickActions.extractContacts}
                        </button>
                    ` : ''}
                    ${MonitoringConfig.crmIntegration.enabled && analysisData && !crmSentLeads[sessionId] ? `
                        <button class="send-to-crm-btn" onclick="sendToCRMWithConfirm('${sessionId}', ${getLeadScore(sessionId, contactData, analysisData)}, '${getLeadTemperature(getLeadScore(sessionId, contactData, analysisData))}')">
                            📤 ${MonitoringConfigManager.getTranslation('leadScoring.sendToCRM')}
                        </button>
                    ` : ''}
                    ${MonitoringConfig.crmIntegration.enabled && crmSentLeads[sessionId] ? `
                        <button class="send-to-crm-btn" disabled>
                            ✅ ${MonitoringConfigManager.getTranslation('leadScoring.sentToCRM')}
                        </button>
                    ` : ''}
                </div>
            </div>
            
            <!-- Правая панель -->
            <div class="client-details">
                <div class="details-tabs">
                    <button class="tab-button active" onclick="switchTab('overview')">📊 ${translations.tabs.overview}</button>
                    <button class="tab-button" onclick="switchTab('dialog')">💬 ${translations.tabs.dialog}</button>
                    <button class="tab-button" onclick="switchTab('details')">📝 ${translations.tabs.details}</button>
                    <button class="tab-button" onclick="switchTab('history')">🕐 ${translations.tabs.history}</button>
                    ${analysisData ? `<button class="tab-button" onclick="switchTab('analysis')">📈 ${translations.tabs.analysis}</button>` : ''}
                </div>
                
                <!-- Вкладка Обзор -->
                <div id="overview-tab" class="tab-content active">
                    <div class="stats-grid">
                        <div class="stat-box">
                            <div class="stat-value">${sessionData.messages || sessionData.messageCount || 0}</div>
                            <div class="stat-label">${translations.overview.messages}</div>
                        </div>
                        <div class="stat-box">
                            <div class="stat-value">${formatDuration(sessionData.duration || sessionData.sessionDuration || 0)}</div>
                            <div class="stat-label">${translations.overview.duration}</div>
                        </div>
                        <div class="stat-box">
                            <div class="stat-value">${analysisData ? analysisData.satisfactionPercentage + '%' : '—'}</div>
                            <div class="stat-label">${translations.overview.satisfaction}</div>
                        </div>
                        <div class="stat-box">
                            <div class="stat-value">${getPlatformIcon(sessionData.platform)}</div>
                            <div class="stat-label">${sessionData.platform}</div>
                        </div>
                    </div>
                    
                    <div class="info-section">
                        <h3>📍 ${translations.overview.geolocation}</h3>
                        <div class="info-grid">
                            <div class="info-item">
                                <label>${translations.overview.ipAddress}</label>
                                <div class="value">${sessionData.ip || sessionData.geo?.ip || 'unknown'}</div>
                            </div>
                            <div class="info-item">
                                <label>${translations.overview.country}</label>
                                <div class="value">${sessionData.country || sessionData.geo?.country || 'unknown'}</div>
                            </div>
                            <div class="info-item">
                                <label>${translations.overview.city}</label>
                                <div class="value">${sessionData.city || sessionData.geo?.city || 'unknown'}</div>
                            </div>
                        </div>
                    </div>
                    
                    ${contactData.company || contactData.position || contactData.location ? `
                        <div class="info-section">
                            <h3>💼 ${translations.overview.professionalInfo}</h3>
                            <div class="info-grid">
                                ${contactData.company ? `
                                    <div class="info-item">
                                        <label>${translations.overview.company}</label>
                                        <div class="value">${contactData.company}</div>
                                    </div>
                                ` : ''}
                                ${contactData.position ? `
                                    <div class="info-item">
                                        <label>${translations.overview.position}</label>
                                        <div class="value">${contactData.position}</div>
                                    </div>
                                ` : ''}
                                ${contactData.location ? `
                                    <div class="info-item">
                                        <label>${translations.overview.location}</label>
                                        <div class="value">${contactData.location}</div>
                                    </div>
                                ` : ''}
                            </div>
                        </div>
                    ` : ''}
                    
                    ${analysisData && analysisData.bantQualification && MonitoringConfigManager.getDisplaySettings().tableColumns.bantAnalysis ? `
    <div class="bant-analysis-section" id="bantSection-${sessionId}">
        <div class="bant-header" onclick="toggleBANT('${sessionId}')">
            <div class="bant-header-left">
                <h3>📊 ${MonitoringConfigManager.getTranslation('bantAnalysis.title')}</h3>
                <span class="bant-qualification-badge ${analysisData.bantQualification.qualified ? 'qualified' : 'unqualified'}">
                    ${analysisData.bantQualification.qualified ? 
                        MonitoringConfigManager.getTranslation('bantAnalysis.qualified') : 
                        MonitoringConfigManager.getTranslation('bantAnalysis.notQualified')}
                </span>
            </div>
            <span class="bant-toggle-icon" id="bantToggle-${sessionId}">▼</span>
        </div>
        
        <div class="bant-content" id="bantContent-${sessionId}">
            <div class="bant-content-inner">
                <!-- Краткая сводка -->
                <div class="bant-summary">
                    <div class="bant-summary-item">
                        <div class="bant-summary-label">${MonitoringConfigManager.getTranslation('bantAnalysis.qualificationLevel.label')}</div>
                        <div class="bant-summary-value">${MonitoringConfigManager.getTranslation(`bantAnalysis.qualificationLevel.${analysisData.bantQualification.qualificationLevel}`)}</div>
                    </div>
                    <div class="bant-summary-item">
                        <div class="bant-summary-label">${MonitoringConfigManager.getTranslation('bantAnalysis.totalScore')}</div>
                        <div class="bant-summary-value">${analysisData.bantQualification.totalScore}/100</div>
                    </div>
                </div>
                
                <!-- Budget -->
${analysisData.bantQualification.budget ? `
    <div class="bant-factor">
        <div class="bant-factor-header" onclick="toggleBANTFactor('${sessionId}', 'budget')" style="cursor: pointer;">
            <div style="display: flex; align-items: center; gap: 10px;">
                <h4 class="bant-factor-title">${MonitoringConfigManager.getTranslation('bantAnalysis.factors.budget.title')}</h4>
                <span class="bant-toggle-icon" id="bant-budget-toggle-${sessionId}">▼</span>
            </div>
            <span class="bant-factor-score ${analysisData.bantQualification.budget.score >= 15 ? 'high' : analysisData.bantQualification.budget.score >= 8 ? 'medium' : 'low'}">
                ${analysisData.bantQualification.budget.score}/20
            </span>
        </div>
        <div class="bant-factor-content" id="bant-budget-details-${sessionId}">
            <div class="bant-factor-details">
                ${analysisData.bantQualification.budget.value ? `
                    <div class="bant-detail-row">
                        <span class="bant-detail-label">${MonitoringConfigManager.getTranslation('bantAnalysis.factors.budget.value')}:</span>
                        <span class="bant-detail-value">${analysisData.bantQualification.budget.value} ${analysisData.bantQualification.budget.currency || ''}</span>
                    </div>
                ` : ''}
                ${analysisData.bantQualification.budget.range ? `
                    <div class="bant-detail-row">
                        <span class="bant-detail-label">${MonitoringConfigManager.getTranslation('bantAnalysis.factors.budget.range')}:</span>
                        <span class="bant-detail-value">${analysisData.bantQualification.budget.range.min} - ${analysisData.bantQualification.budget.range.max} ${analysisData.bantQualification.budget.currency || ''}</span>
                    </div>
                ` : ''}
                <div class="bant-detail-row">
                    <span class="bant-detail-label">${MonitoringConfigManager.getTranslation('bantAnalysis.factors.budget.mentioned')}:</span>
                    <span class="bant-detail-value">${analysisData.bantQualification.budget.mentioned ? 
                        MonitoringConfigManager.getTranslation('bantAnalysis.factors.budget.yes') : 
                        MonitoringConfigManager.getTranslation('bantAnalysis.factors.budget.no')}</span>
                </div>
                <div class="bant-detail-row">
                    <span class="bant-detail-label">${MonitoringConfigManager.getTranslation('bantAnalysis.confidence')}:</span>
                    <span class="bant-detail-value">${Math.round(analysisData.bantQualification.budget.confidence * 100)}%</span>
                </div>
            </div>
            ${analysisData.bantQualification.budget.description ? `
                <div class="bant-description">
                    <div class="bant-description-text">${analysisData.bantQualification.budget.description}</div>
                </div>
            ` : ''}
        </div>
    </div>
` : ''}
                
                <!-- Authority -->
${analysisData.bantQualification.authority ? `
    <div class="bant-factor">
        <div class="bant-factor-header" onclick="toggleBANTFactor('${sessionId}', 'authority')" style="cursor: pointer;">
            <div style="display: flex; align-items: center; gap: 10px;">
                <h4 class="bant-factor-title">${MonitoringConfigManager.getTranslation('bantAnalysis.factors.authority.title')}</h4>
                <span class="bant-toggle-icon" id="bant-authority-toggle-${sessionId}">▼</span>
            </div>
            <span class="bant-factor-score ${analysisData.bantQualification.authority.score >= 15 ? 'high' : analysisData.bantQualification.authority.score >= 8 ? 'medium' : 'low'}">
                ${analysisData.bantQualification.authority.score}/20
            </span>
        </div>
        <div class="bant-factor-content" id="bant-authority-details-${sessionId}">
            <div class="bant-factor-details">
                <div class="bant-detail-row">
                    <span class="bant-detail-label">${MonitoringConfigManager.getTranslation('bantAnalysis.factors.authority.role')}:</span>
                    <span class="bant-detail-value">${MonitoringConfigManager.getTranslation(`bantAnalysis.factors.authority.roles.${analysisData.bantQualification.authority.role}`)}</span>
                </div>
                <div class="bant-detail-row">
                    <span class="bant-detail-label">${MonitoringConfigManager.getTranslation('bantAnalysis.factors.authority.level')}:</span>
                    <span class="bant-detail-value">${MonitoringConfigManager.getTranslation(`bantAnalysis.factors.authority.levels.${analysisData.bantQualification.authority.level}`)}</span>
                </div>
                ${analysisData.bantQualification.authority.position ? `
                    <div class="bant-detail-row">
                        <span class="bant-detail-label">${MonitoringConfigManager.getTranslation('bantAnalysis.factors.authority.position')}:</span>
                        <span class="bant-detail-value">${analysisData.bantQualification.authority.position}</span>
                    </div>
                ` : ''}
                <div class="bant-detail-row">
                    <span class="bant-detail-label">${MonitoringConfigManager.getTranslation('bantAnalysis.confidence')}:</span>
                    <span class="bant-detail-value">${Math.round(analysisData.bantQualification.authority.confidence * 100)}%</span>
                </div>
            </div>
            ${analysisData.bantQualification.authority.description ? `
                <div class="bant-description">
                    <div class="bant-description-text">${analysisData.bantQualification.authority.description}</div>
                </div>
            ` : ''}
        </div>
    </div>
` : ''}
                
                <!-- Need -->
${analysisData.bantQualification.need ? `
    <div class="bant-factor">
        <div class="bant-factor-header" onclick="toggleBANTFactor('${sessionId}', 'need')" style="cursor: pointer;">
            <div style="display: flex; align-items: center; gap: 10px;">
                <h4 class="bant-factor-title">${MonitoringConfigManager.getTranslation('bantAnalysis.factors.need.title')}</h4>
                <span class="bant-toggle-icon" id="bant-need-toggle-${sessionId}">▼</span>
            </div>
            <span class="bant-factor-score ${analysisData.bantQualification.need.score >= 23 ? 'high' : analysisData.bantQualification.need.score >= 15 ? 'medium' : 'low'}">
                ${analysisData.bantQualification.need.score}/30
            </span>
        </div>
        <div class="bant-factor-content" id="bant-need-details-${sessionId}">
            <div class="bant-factor-details">
                <div class="bant-detail-row">
                    <span class="bant-detail-label">${MonitoringConfigManager.getTranslation('bantAnalysis.factors.need.severity')}:</span>
                    <span class="bant-detail-value">${MonitoringConfigManager.getTranslation(`bantAnalysis.factors.need.severityLevels.${analysisData.bantQualification.need.severity}`)}</span>
                </div>
                <div class="bant-detail-row">
                    <span class="bant-detail-label">${MonitoringConfigManager.getTranslation('bantAnalysis.confidence')}:</span>
                    <span class="bant-detail-value">${Math.round(analysisData.bantQualification.need.confidence * 100)}%</span>
                </div>
            </div>
            ${analysisData.bantQualification.need.painPoints && analysisData.bantQualification.need.painPoints.length > 0 ? `
                <div class="bant-pain-points">
                    <div class="bant-pain-points-title">${MonitoringConfigManager.getTranslation('bantAnalysis.factors.need.painPoints')}:</div>
                    ${analysisData.bantQualification.need.painPoints.map(point => `
                        <div class="bant-pain-point">
                            <span class="bant-pain-point-icon">🔴</span>
                            <span class="bant-pain-point-text">${point}</span>
                        </div>
                    `).join('')}
                </div>
            ` : ''}
            ${analysisData.bantQualification.need.description ? `
                <div class="bant-description">
                    <div class="bant-description-text">${analysisData.bantQualification.need.description}</div>
                </div>
            ` : ''}
        </div>
    </div>
` : ''}
                
                <!-- Timeline -->
${analysisData.bantQualification.timeline ? `
    <div class="bant-factor">
        <div class="bant-factor-header" onclick="toggleBANTFactor('${sessionId}', 'timeline')" style="cursor: pointer;">
            <div style="display: flex; align-items: center; gap: 10px;">
                <h4 class="bant-factor-title">${MonitoringConfigManager.getTranslation('bantAnalysis.factors.timeline.title')}</h4>
                <span class="bant-toggle-icon" id="bant-timeline-toggle-${sessionId}">▼</span>
            </div>
            <span class="bant-factor-score ${analysisData.bantQualification.timeline.score >= 25 ? 'high' : analysisData.bantQualification.timeline.score >= 15 ? 'medium' : 'low'}">
                ${analysisData.bantQualification.timeline.score}/30
            </span>
        </div>
        <div class="bant-factor-content" id="bant-timeline-details-${sessionId}">
            <div class="bant-factor-details">
                <div class="bant-detail-row">
                    <span class="bant-detail-label">${MonitoringConfigManager.getTranslation('bantAnalysis.factors.timeline.urgency')}:</span>
                    <span class="bant-detail-value">${MonitoringConfigManager.getTranslation(`bantAnalysis.factors.timeline.urgencyLevels.${analysisData.bantQualification.timeline.urgency}`)}</span>
                </div>
                ${analysisData.bantQualification.timeline.deadline ? `
                    <div class="bant-detail-row">
                        <span class="bant-detail-label">${MonitoringConfigManager.getTranslation('bantAnalysis.factors.timeline.deadline')}:</span>
                        <span class="bant-detail-value">${analysisData.bantQualification.timeline.deadline}</span>
                    </div>
                ` : ''}
                <div class="bant-detail-row">
                    <span class="bant-detail-label">${MonitoringConfigManager.getTranslation('bantAnalysis.confidence')}:</span>
                    <span class="bant-detail-value">${Math.round(analysisData.bantQualification.timeline.confidence * 100)}%</span>
                </div>
            </div>
            ${analysisData.bantQualification.timeline.description ? `
                <div class="bant-description">
                    <div class="bant-description-text">${analysisData.bantQualification.timeline.description}</div>
                </div>
            ` : ''}
        </div>
    </div>
` : ''}
                
                <!-- Общее обоснование -->
                ${analysisData.bantQualification.reasoning ? `
                    <div class="bant-reasoning">
                        <div class="bant-reasoning-title">${MonitoringConfigManager.getTranslation('bantAnalysis.reasoning')}</div>
                        <div class="bant-reasoning-text">${analysisData.bantQualification.reasoning}</div>
                    </div>
                ` : ''}
            </div>
        </div>
    </div>
` : ''}
                    
                   ${analysisData && analysisData.emotionalTone ? `
    <div class="crm-integration-section" style="margin-top: 20px;">
        <h3>🎯 ${MonitoringConfigManager.getTranslation('leadScoring.title')}</h3>
        <div class="lead-score-display">
            <div class="lead-score-indicator ${getLeadTemperature(getLeadScore(sessionId, contactData, analysisData))}">
                ${getLeadScore(sessionId, contactData, analysisData)}
            </div>
            <div class="lead-score-details">
                <div class="lead-temp-badge ${getLeadTemperature(getLeadScore(sessionId, contactData, analysisData))}">
                   ${getLeadScore(sessionId, contactData, analysisData) >= 80 ? '🔥' : getLeadScore(sessionId, contactData, analysisData) >= 50 ? '🌡️' : '❄️'} 
${MonitoringConfigManager.getTranslation(`leadScoring.temperature.${getLeadTemperature(getLeadScore(sessionId, contactData, analysisData))}`)} ${MonitoringConfigManager.getTranslation('leadScoring.temperature.leadType')}
                </div>
                <div class="lead-factors">
                    <div class="factor-item">
    <span class="factor-label">😊 ${MonitoringConfigManager.getTranslation('leadScoring.factors.satisfaction')}:</span>
    <span class="factor-value">${analysisData.leadScoring?.factors?.satisfaction || analysisData.emotionalTone?.satisfaction || 0}%</span>
</div>
<div class="factor-item">
    <span class="factor-label">📱 ${MonitoringConfigManager.getTranslation('leadScoring.factors.contacts')}:</span>
<span class="factor-value">${analysisData.leadScoring?.factors?.contacts || 0} ${MonitoringConfigManager.getTranslation('leadScoring.factors.points')}</span>
</div>
                </div>
                ${analysisData.leadScoring && analysisData.leadScoring.recommendation ? `
                    <div style="margin-top: 15px; padding: 12px; background: var(--secondary-bg); border-radius: 8px; border-left: 3px solid var(--accent-primary);">
                        <div style="font-size: 12px; font-weight: 600; color: var(--text-secondary); margin-bottom: 5px;">📋 ${MonitoringConfigManager.getTranslation('leadScoring.recommendation')}:</div>
                        <div style="font-size: 14px; color: var(--text-primary); line-height: 1.5;">${analysisData.leadScoring.recommendation}</div>
                    </div>
                ` : ''}
            </div>
        </div>
       ${MonitoringConfig.crmIntegration.enabled && getLeadScore(sessionId, contactData, analysisData) >= 80 && !crmSentLeads[sessionId] ? 
            `<p class="hot-lead-notice">⚡ ${MonitoringConfigManager.getTranslation('leadScoring.urgentNotice')}</p>` : ''
        }
        ${MonitoringConfig.crmIntegration.enabled && crmSentLeads[sessionId] ? `
            <div class="crm-sent-info">
                <div class="info-item">
                    <label>✅ ${MonitoringConfigManager.getTranslation('leadScoring.sentToCRM')}</label>
                    <div class="value">${formatDate(crmSentLeads[sessionId].sentAt)}</div>
                </div>
                ${crmSentLeads[sessionId].crmLeadId ? `
                    <div class="info-item">
                        <label>${MonitoringConfigManager.getTranslation('leadScoring.crmIdLabel')}</label>
                        <div class="value">${crmSentLeads[sessionId].crmLeadId}</div>
                                        </div>
                                    ` : ''}
                                </div>
                            ` : ''}
                        </div>
                    ` : ''}
                </div>
                
                <!-- Вкладка Диалог -->
                <div id="dialog-tab" class="tab-content">
                    <div class="loading-spinner">
                        <div class="spinner"></div>
                        <p>${dialogTranslations.loading}</p>
                    </div>
                </div>
                
                <!-- Вкладка Детали -->
                <div id="details-tab" class="tab-content">
                    <div class="info-section">
                        <h3>🔧 ${translations.details.technicalInfo}</h3>
                        <div class="info-grid">
                            <div class="info-item">
                                <label>${translations.details.sessionId}</label>
                                <div class="value" style="font-family: monospace; font-size: 12px;">${sessionId}</div>
                            </div>
                            <div class="info-item">
                                <label>${translations.details.platform}</label>
                                <div class="value">${sessionData.platform}</div>
                            </div>
                            <div class="info-item">
                                <label>${translations.details.configuration}</label>
                                <div class="value">${sessionData.configName || 'default'}</div>
                            </div>
                            <div class="info-item">
                                <label>${translations.details.language}</label>
                                <div class="value">${sessionData.language || 'ru'}</div>
                            </div>
                        </div>
                    </div>
                    
                    <div class="info-section">
                        <h3>📅 ${translations.details.timestamps}</h3>
                        <div class="info-grid">
                            <div class="info-item">
                                <label>${translations.details.firstMessage}</label>
                                <div class="value">${formatDate(sessionData.sessionStartTime || sessionData.timestamp)}</div>
                            </div>
                            <div class="info-item">
                                <label>${translations.details.lastActivity}</label>
                                <div class="value">${formatDate(sessionData.lastActivity || sessionData.timestamp)}</div>
                            </div>
                        </div>
                    </div>
                    
                    ${contactData.extractedFrom ? `
                        <div class="info-section">
                            <h3>📝 ${translations.details.dataSource}</h3>
                            <p style="color: var(--text-secondary); font-style: italic; line-height: 1.6;">
                                ${contactData.extractedFrom}
                            </p>
                            ${contactData.confidence ? `
                                <div style="margin-top: 10px;">
                                    <label style="font-size: 12px; color: var(--text-secondary);">${translations.details.aiConfidence}</label>
                                    <div style="display: flex; align-items: center; gap: 10px; margin-top: 5px;">
                                        <div style="flex: 1; height: 8px; background: var(--border-color); border-radius: 4px; overflow: hidden;">
                                            <div style="width: ${contactData.confidence}%; height: 100%; background: ${contactData.confidence >= 70 ? 'var(--success)' : contactData.confidence >= 50 ? 'var(--warning)' : 'var(--danger)'};"></div>
                                        </div>
                                        <span style="font-weight: 600; color: ${contactData.confidence >= 70 ? 'var(--success)' : contactData.confidence >= 50 ? 'var(--warning)' : 'var(--danger)'};">${contactData.confidence}%</span>
                                    </div>
                                </div>
                            ` : ''}
                        </div>
                    ` : ''}
                </div>
                
                <!-- Вкладка История -->
                <div id="history-tab" class="tab-content">
                    <div class="timeline">
                        <div class="timeline-item">
                            <div class="timeline-dot"></div>
                            <div class="timeline-content">
                                <div class="timeline-date">${formatDate(sessionData.sessionStartTime || sessionData.timestamp)}</div>
                                <div class="timeline-title">🚀 ${translations.history.dialogStart}</div>
                            </div>
                        </div>
                        ${contactData.lastUpdated ? `
                            <div class="timeline-item">
                                <div class="timeline-dot"></div>
                                <div class="timeline-content">
                                    <div class="timeline-date">${formatDate(contactData.lastUpdated)}</div>
                                    <div class="timeline-title">📇 ${translations.history.contactsExtracted}</div>
                                </div>
                            </div>
                        ` : ''}
                        ${analysisData && analysisData.analyzedAt ? `
                            <div class="timeline-item">
                                <div class="timeline-dot"></div>
                                <div class="timeline-content">
                                    <div class="timeline-date">${formatDate(analysisData.analyzedAt)}</div>
                                    <div class="timeline-title">📊 ${translations.history.analysisCompleted} (${analysisData.satisfactionPercentage}% ${translations.history.satisfactionLevel})</div>
                                </div>
                            </div>
                        ` : ''}
                        <div class="timeline-item">
                            <div class="timeline-dot"></div>
                            <div class="timeline-content">
                                <div class="timeline-date">${formatDate(sessionData.lastActivity || sessionData.timestamp)}</div>
                                <div class="timeline-title">⏰ ${translations.history.lastActivity}</div>
                            </div>
                        </div>
                    </div>
                </div>
                
                <!-- Вкладка Анализ (если есть) -->
                ${analysisData ? `
                    <div id="analysis-tab" class="tab-content">
                        ${generateAnalysisHTML(analysisData)}
                    </div>
                ` : ''}
            </div>
        </div>
    `;
}

// Закрытие карточки клиента
function closeClientCard(event) {
    if (!event || event.target.id === 'clientCardModal') {
        document.getElementById('clientCardModal').style.display = 'none';
        document.body.classList.remove('modal-open');
        document.body.style.top = '';
        window.scrollTo(0, window.scrollPosition || 0);
    }
}

// Переключение вкладок
async function switchTab(tabName) {
    // Скрываем все вкладки
    document.querySelectorAll('.tab-content').forEach(tab => {
        tab.classList.remove('active');
    });
    
    // Убираем активность со всех кнопок
    document.querySelectorAll('.tab-button').forEach(btn => {
        btn.classList.remove('active');
    });
    
    // Показываем выбранную вкладку
    const tab = document.getElementById(`${tabName}-tab`);
    if (tab) {
        tab.classList.add('active');
    }
    
    // Активируем кнопку
    event.target.classList.add('active');
    
    // Получаем sessionId для загрузки данных
    const quickActions = document.querySelector('.quick-actions');
    let sessionId = null;
    
    // Пытаемся получить sessionId из кнопки анализа или извлечения контактов
    const analyzeBtn = quickActions?.querySelector('.analyze-btn');
    const extractBtn = quickActions?.querySelector('.extract-contacts-btn');
    const btn = analyzeBtn || extractBtn;
    
    if (btn) {
        const onclickAttr = btn.getAttribute('onclick');
        const match = onclickAttr.match(/'([^']+)'/);
        sessionId = match ? match[1] : null;
    }
    
    // Если не нашли, пробуем из ID в заголовке
    if (!sessionId) {
        const clientIdElement = document.querySelector('.client-id');
        if (clientIdElement) {
            const fullId = clientIdElement.textContent.replace('ID: ', '').replace('...', '');
            // Восстанавливаем полный ID из данных
            const allSessionIds = Object.keys(userContactsData).concat(Object.keys(savedAnalyses));
            sessionId = allSessionIds.find(id => id.startsWith(fullId)) || fullId;
        }
    }
    
    // ✅ НОВОЕ: Получаем имя пользователя из контактных данных
    const contactData = userContactsData[sessionId] || {};
    const sessionData = allData.find(item => item.sessionId === sessionId);
    // Определяем имя пользователя
const guestName = MonitoringConfigManager.getTranslation('formatting.guest');

// Список всех возможных переводов "Guest/User/Пользователь"
const userTranslations = ['Guest', 'Пользователь', 'Гість', 'User', 'Usuario', 'Utilisateur', 'Benutzer', 'Utente', 'Usuário', '用户', 'ユーザー', '사용자', 'Користувач', 'Invitado', 'Invité', 'Gast', 'Ospite', 'Convidado', '访客', 'ゲスト', '게스트'];

// Получаем имя с проверкой
let userName = contactData.name;
if (!userName && sessionData?.userName) {
    userName = userTranslations.includes(sessionData.userName) ? guestName : sessionData.userName;
}
if (!userName) {
    userName = guestName;
}
    
    // Получаем переводы
    const dialogTranslations = MonitoringConfigManager.getTranslation('dialogs.dialog');
    const analysisTranslations = MonitoringConfigManager.getTranslation('analysis');
    
    // Если переключились на вкладку диалога
    if (tabName === 'dialog' && sessionId) {
        const dialogTab = document.getElementById('dialog-tab');
        
        // Показываем загрузку
        dialogTab.innerHTML = `
            <div class="loading-spinner">
                <div class="spinner"></div>
                <p>${dialogTranslations.loading}</p>
            </div>
        `;

        try {
            const response = await authFetch(`${config.dialogsEndpoint}?session_id=${sessionId}`);
            const data = await response.json();

            let dialogs = [];
            if (data.dialogs) {
                dialogs = data.dialogs;
            } else if (Array.isArray(data)) {
                dialogs = data;
            }
            
            if (dialogs.length > 0) {
                dialogTab.innerHTML = `
                    <div class="dialog-messages" style="max-height: 500px; overflow-y: auto; padding: 20px;">
                        ${dialogs.map(msg => `
                            <div class="dialog-message ${msg.message_type}" style="margin-bottom: 16px; padding: 14px; border-radius: 12px; ${msg.message_type === 'user' ? 'background: linear-gradient(135deg, rgba(102, 126, 234, 0.1), rgba(118, 75, 162, 0.1)); border: 1px solid rgba(102, 126, 234, 0.3); margin-left: 20%;' : 'background: var(--secondary-bg); border: 1px solid var(--border-color); margin-right: 20%;'}">
                                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                                    <strong style="color: ${msg.message_type === 'user' ? 'var(--accent-primary)' : 'var(--success)'}; font-size: 14px;">
                                        ${msg.message_type === 'user' ? 
                                            '👤 ' + userName : 
                                            '🤖 ' + dialogTranslations.bot}
                                    </strong>
                                    <div style="display: flex; gap: 8px; align-items: center;">
                                        <span style="font-size: 18px;">${msg.platform_icon || '💬'}</span>
                                        <span style="font-size: 18px;">${msg.language_flag || '🌐'}</span>
                                    </div>
                                </div>
                                <div class="message-content">${msg.message_text || msg.response_text || msg.content || ''}</div>
                                <div style="font-size: 11px; color: var(--text-secondary); margin-top: 8px; display: flex; justify-content: space-between;">
                                    <span>🕐 ${formatDate(msg.timestamp)}</span>
                                    <span>${msg.platform || 'web'}</span>
                                </div>
                            </div>
                        `).join('')}
                    </div>
                `;
            } else {
                dialogTab.innerHTML = `<p style="text-align: center; color: var(--text-secondary); padding: 40px;">${dialogTranslations.notFound}</p>`;
            }
        } catch (error) {
            console.error('Ошибка загрузки диалога:', error);
            dialogTab.innerHTML = `<p style="color: var(--danger); text-align: center; padding: 40px;">${dialogTranslations.error}</p>`;
        }
    }
    
    // Если переключились на вкладку анализа
    if (tabName === 'analysis' && sessionId) {
        const analysisTab = document.getElementById('analysis-tab');
        
        // Показываем загрузку
        analysisTab.innerHTML = `
            <div class="loading-spinner">
                <div class="spinner"></div>
                <p>${dialogTranslations.loading}</p>
            </div>
        `;

        try {
            // Загружаем полный анализ
            const response = await authFetch(`${config.getAnalysisEndpoint}?session_id=${sessionId}&type=single`);
            const data = await response.json();
            
            if (data.found && data) {
                // Генерируем HTML прямо здесь, как в оригинале, но с переводами
                analysisTab.innerHTML = `
                    <div class="analysis-result">
                        ${data.emotionalTone ? `
                            <div class="info-section">
                                <h3>😊 ${analysisTranslations.emotionalTone.title}</h3>
                                <div class="analysis-metric">
                                    <span class="metric-label">${analysisTranslations.emotionalTone.overall}:</span>
                                    <span class="metric-value ${data.emotionalTone.overall}">
                                        ${data.emotionalTone.overallText || data.emotionalTone.overall}
                                    </span>
                                </div>
                                <div class="analysis-metric">
                                    <span class="metric-label">${analysisTranslations.emotionalTone.satisfaction}:</span>
                                    <span class="metric-value ${data.emotionalTone.satisfaction >= 70 ? 'positive' : data.emotionalTone.satisfaction >= 50 ? 'neutral' : 'negative'}">
                                        ${data.emotionalTone.satisfaction}%
                                    </span>
                                </div>
                                ${data.emotionalTone.description ? `
                                    <p style="margin-top: 15px; color: var(--text-secondary); line-height: 1.6;">
                                        ${data.emotionalTone.description}
                                    </p>
                                ` : ''}
                            </div>
                        ` : ''}
                        
                        ${data.customerNeeds && data.customerNeeds.length > 0 ? `
                            <div class="info-section">
                                <h3>🎯 ${analysisTranslations.needs.title}</h3>
                                <ul style="margin: 0; padding-left: 20px;">
                                    ${data.customerNeeds.map(need => `
                                        <li style="margin-bottom: 8px; color: var(--text-primary);">${need}</li>
                                    `).join('')}
                                </ul>
                            </div>
                        ` : ''}
                        
                        ${data.missedOpportunities && data.missedOpportunities.length > 0 ? `
                            <div class="info-section">
                                <h3>💡 ${analysisTranslations.missedOpportunities.title}</h3>
                                <ul style="margin: 0; padding-left: 20px;">
                                    ${data.missedOpportunities.map(opp => `
                                        <li style="margin-bottom: 8px; color: var(--warning);">${opp}</li>
                                    `).join('')}
                                </ul>
                            </div>
                        ` : ''}
                        
                        ${data.recommendations && data.recommendations.length > 0 ? `
                            <div class="info-section">
                                <h3>📌 ${analysisTranslations.recommendations.title}</h3>
                                <ul style="margin: 0; padding-left: 20px;">
                                    ${data.recommendations.map(rec => `
                                        <li style="margin-bottom: 8px; color: var(--text-primary);">${rec}</li>
                                    `).join('')}
                                </ul>
                            </div>
                        ` : ''}
                    </div>
                `;
                analysisTab.innerHTML += `</div>`;
            } else {
                analysisTab.innerHTML = `<p style="text-align: center; color: var(--text-secondary);">${dialogTranslations.notFound}</p>`;
            }
        } catch (error) {
            console.error('Ошибка загрузки анализа:', error);
            analysisTab.innerHTML = `<p style="color: var(--danger); text-align: center;">${dialogTranslations.error}</p>`;
        }
    }
}

// Получение инициалов
function getInitials(name) {
    // Список всех возможных переводов "Guest"
    const guestTranslations = ['Guest', 'Пользователь', 'Гість', 'User', 'Usuario', 'Utilisateur', 'Benutzer', 'Utente', 'Usuário', '用户', 'ユーザー', '사용자', 'Користувач'];
    
    if (!name || guestTranslations.includes(name)) {
        return '👤';
    }
    
    const parts = name.split(' ');
    if (parts.length >= 2) {
        return parts[0][0].toUpperCase() + parts[1][0].toUpperCase();
    }
    return name.substring(0, 2).toUpperCase();
}

// Копирование в буфер обмена
function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => {
        showNotification(`✅ ${MonitoringConfigManager.getTranslation('notifications.copiedToClipboard')}`, 'success');
    });
}

// Генерация HTML для анализа
function generateAnalysisHTML(analysis) {
    const translations = MonitoringConfigManager.getTranslation('analysis');
    
    let html = '<div class="analysis-result">';
    
    if (analysis.emotionalTone) {
        html += `
            <div class="info-section">
                <h3>😊 ${translations.emotionalTone.title}</h3>
                <div class="info-grid">
                    <div class="info-item">
                        <label>${translations.emotionalTone.overall}</label>
                        <div class="value">${analysis.emotionalTone.overallText}</div>
                    </div>
                    <div class="info-item">
                        <label>${translations.emotionalTone.satisfaction}</label>
                        <div class="value">${analysis.emotionalTone.satisfaction}%</div>
                    </div>
                </div>
                <p style="margin-top: 15px; color: var(--text-secondary);">
                    ${analysis.emotionalTone.description}
                </p>
            </div>
        `;
    }
    
    if (analysis.customerNeeds && analysis.customerNeeds.length > 0) {
        html += `
            <div class="info-section">
                <h3>🎯 ${translations.needs.title}</h3>
                <ul style="margin: 0; padding-left: 20px;">
                    ${analysis.customerNeeds.map(need => `<li style="margin-bottom: 8px;">${need}</li>`).join('')}
                </ul>
            </div>
        `;
    }
    
    html += '</div>';
    return html;
}
// Автооткрытие диалога по прямой ссылке
setTimeout(() => {
    const hash = window.location.hash.substring(1);
    if (hash && (hash.startsWith('webchat_') || hash.startsWith('telegram_'))) {
        viewDialog(hash);
    }
}, 3000);

// Анимация графиков при загрузке
let animationProgress = 0;
const animationDuration = 1000; // 1 секунда

function animateCharts(timestamp) {
    if (!animationStart) animationStart = timestamp;
    animationProgress = Math.min((timestamp - animationStart) / animationDuration, 1);
    
    if (animationProgress < 1) {
        requestAnimationFrame(animateCharts);
        updateCharts();
    }
}

let animationStart = null;
// АВТОМАТИЧЕСКАЯ ПРОВЕРКА ОТКЛЮЧЕНА
// Обновление только вручную (F5, кнопка или вызов функции)
// Функция переключения блока BANT
function toggleBANT(sessionId) {
    const content = document.getElementById(`bantContent-${sessionId}`);
    const toggle = document.getElementById(`bantToggle-${sessionId}`);
    
    if (content && toggle) {
        content.classList.toggle('expanded');
        toggle.classList.toggle('expanded');
    }
}

// Функция переключения отдельного фактора BANT
function toggleBANTFactor(sessionId, factorType) {
    const details = document.getElementById(`bant-${factorType}-details-${sessionId}`);
    const toggle = document.getElementById(`bant-${factorType}-toggle-${sessionId}`);
    
    if (details && toggle) {
        details.classList.toggle('expanded');
        toggle.classList.toggle('expanded');
    }
}

// Экспортируем функцию в глобальную область
window.toggleBANTFactor = toggleBANTFactor;

// Функция переключения блоков анализа
function toggleAnalysisSection(sectionId) {
    const content = document.getElementById(`analysis-content-${sectionId}`);
    const toggle = document.getElementById(`analysis-toggle-${sectionId}`);
    
    if (content && toggle) {
        requestAnimationFrame(() => {
            content.classList.toggle('expanded');
            toggle.classList.toggle('expanded');
        });
    }
}

// Экспортируем функцию в глобальную область
window.toggleAnalysisSection = toggleAnalysisSection;

// ===============================================
// HIGHLIGHTS ФУНКЦИОНАЛ
// ===============================================

// Глобальная переменная для хранения highlights
let currentHighlights = [];
let activeFilter = null; 

// Функция запуска анализа highlights
async function analyzeHighlights(sessionId, userName) {
    
     // ✅ ПРОВЕРКА: Включены ли highlights в конфигурации
    const highlightsConfig = MonitoringConfig.highlights || {};
    
    if (highlightsConfig.enabled === false) {
        console.log('❌ Highlights disabled in MonitoringConfig');
        const translations = MonitoringConfigManager.getTranslation('highlights');
        showNotification(translations?.disabled || 'Highlights функция отключена', 'info');
        return;
    }
    
    const translations = MonitoringConfigManager.getTranslation('highlights');
    
    // Показываем уведомление
    showNotification(translations.analyzing, 'info');

    try {
        const response = await authFetch(config.detectHighlightsEndpoint, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                sessionId: sessionId,
                userName: userName,
                language: MonitoringConfigManager.getLanguage()
            })
        });
        
        if (!response.ok) throw new Error('Analysis failed');
        
        const result = await response.json();
        
        if (result.success) {
            showNotification(`${translations.analyzed}! ${translations.found}: ${result.totalDetected}`, 'success');
            
            // Обновляем таблицу
            setTimeout(() => {
                updateTable();
            }, 1000);
        } else {
            throw new Error(result.message || 'Unknown error');
        }
        
    } catch (error) {
        console.error('Error analyzing highlights:', error);
        showNotification(translations.analyzeError, 'error');
    }
}

// Функция повторного анализа highlights
async function reanalyzeHighlights(sessionId, userName, language) {
    const translations = MonitoringConfigManager.getTranslation('highlights');
    
    console.log('🔄 Starting reanalysis for session:', sessionId);
    
    try {
        // Показываем индикатор загрузки
        const reanalyzeBtn = document.querySelector('.reanalyze-highlights-btn');
        if (reanalyzeBtn) {
            reanalyzeBtn.disabled = true;
            reanalyzeBtn.innerHTML = '<span class="spinner"></span> ' + (translations.reanalyzing || 'Анализ...');
        }

        // Вызываем workflow detect-highlights
        const webhookUrl = MonitoringConfig.technical.detectHighlightsEndpoint;
        const response = await authFetch(webhookUrl, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                sessionId: sessionId,
                userName: userName,
                language: language
            })
        });
        
        if (!response.ok) {
            throw new Error(`Analysis failed: ${response.status}`);
        }
        
        const result = await response.json();
        console.log('✅ Reanalysis completed:', result);
        
        // ✅ НОВОЕ: Перезагружаем highlights и ОБНОВЛЯЕМ ПАНЕЛЬ
        const highlightsData = await loadHighlights(sessionId);
        
        // Обновляем панель highlights
        const highlightsPanel = document.querySelector('.dialog-highlights-sidebar');
        if (highlightsPanel && highlightsData.hasHighlights) {
            highlightsPanel.innerHTML = renderHighlightsPanel(highlightsData);
        }
        
        // Показываем уведомление
        const message = (translations.reanalyzed || 'Анализ завершен!') + ' ' + 
                       (translations.found || 'Найдено') + ': ' + result.totalDetected;
        showNotification('success', message);
        
    } catch (error) {
        console.error('❌ Reanalysis failed:', error);
        showNotification('error', translations.reanalyzeError || 'Ошибка при повторном анализе');
        
        // Восстанавливаем кнопку
        const reanalyzeBtn = document.querySelector('.reanalyze-highlights-btn');
        if (reanalyzeBtn) {
            reanalyzeBtn.disabled = false;
            const btnText = translations.reanalyze || 'Повторный анализ';
            reanalyzeBtn.innerHTML = '🔄 <span class="reanalyze-text">' + btnText + '</span>';
        }
    }
}

// Экспортируем в глобальную область
window.reanalyzeHighlights = reanalyzeHighlights;

// Функция загрузки highlights для сессии
async function loadHighlights(sessionId) {
    // ========================================
    // ✅ ПРОВЕРКА КОНФИГУРАЦИИ
    // ========================================
    const highlightsConfig = MonitoringConfig.highlights || {};
    
    // Проверка 1: Включены ли highlights?
    if (highlightsConfig.enabled === false) {
        console.log('❌ Highlights disabled in config');
        return { hasHighlights: false, highlights: [], total: 0 };
    }
    
    // ========================================
    // ✅ ЗАГРУЗКА ДАННЫХ
    // ========================================
    try {
        const response = await authFetch(`${config.getHighlightsEndpoint}?session_id=${sessionId}`);
        
        if (!response.ok) throw new Error('Failed to load highlights');
        
        const data = await response.json();
        
        if (data.success && data.hasHighlights) {
            // ✅ ФИЛЬТРАЦИЯ по enabled типам
            const filteredHighlights = data.highlights.filter(h => {
                const typeConfig = highlightsConfig.types?.[h.type];
                
                // Если тип disabled, пропускаем
                if (typeConfig && typeConfig.enabled === false) {
                    console.log(`⚠️ Skipping disabled type: ${h.type}`);
                    return false;
                }
                
                return true;
            });
            
            //console.log(`✅ Filtered highlights: ${data.highlights.length} → ${filteredHighlights.length}`);
            
            currentHighlights = filteredHighlights;
            
            // Пересчитываем byType
            const byType = { pricing: 0, objection: 0, buying_signal: 0 };
            filteredHighlights.forEach(h => {
                if (byType[h.type] !== undefined) byType[h.type]++;
            });
            
            return {
                ...data,
                highlights: filteredHighlights,
                total: filteredHighlights.length,
                byType: byType
            };
        } else {
            currentHighlights = [];
            return { hasHighlights: false, highlights: [], total: 0 };
        }
        
    } catch (error) {
        console.error('Error loading highlights:', error);
        currentHighlights = [];
        return { hasHighlights: false, highlights: [], total: 0 };
    }
}

// Функция отображения highlights панели
function renderHighlightsPanel(highlightsData) {
    const translations = MonitoringConfigManager.getTranslation('highlights');
    const config = MonitoringConfig.highlights;
    
    // ✅ НОВОЕ: Определяем currentDialog
    const currentDialog = window.currentDialog || {
        userName: 'User',
        language: 'ru'
    };
    
    // ✅ ПРОВЕРКА: Если highlights выключены вообще
    if (config.enabled === false) {
        return ''; // Возвращаем пустоту
    }
    
    if (!highlightsData || !highlightsData.hasHighlights || highlightsData.highlights.length === 0) {
        return `
            <div class="highlights-panel-empty">
                <div class="empty-state">
                    <span style="font-size: 48px;">🔍</span>
                    <p style="margin-top: 16px; color: var(--text-secondary);">
                        ${translations.noHighlights}
                    </p>
                </div>
            </div>
        `;
    }
    
    const byType = highlightsData.byType || {
        pricing: 0,
        objection: 0,
        buying_signal: 0
    };
    
    // ✅ ФИЛЬТРАЦИЯ: Показываем только выбранный тип или все
    const filteredHighlights = highlightsData.highlights.filter(h => {
        return !activeFilter || h.type === activeFilter;
    });
    
    // ✅ НОВОЕ: Проверяем нужен ли ре-анализ
    const needsReanalysis = highlightsData.needsReanalysis || false;
    const newUserMessages = highlightsData.newUserMessages || 0;
    
    // Генерируем HTML для highlights
    const highlightItems = filteredHighlights.map((h, index) => {
        const typeConfig = config.types[h.type];
        
        // ✅ ПРИМЕНЯЕМ color и icon из конфига
        const color = typeConfig?.color || '#808080';
        const icon = typeConfig?.icon || '📌';
        
        const typeLabel = translations.types[h.type] || h.type;
        const confidencePercent = Math.round(h.confidence * 100);
        
        return `
            <div class="highlight-item" data-highlight-id="${h.id}" data-message-id="${h.messageId}" onclick="scrollToMessage(${h.messageId})">
                <div class="highlight-header">
                    <span class="highlight-type" style="color: ${color};">
                        ${icon} ${typeLabel}
                    </span>
                    <span class="highlight-confidence" title="${translations.confidence}: ${confidencePercent}%">
                        ${confidencePercent}%
                    </span>
                </div>
                <div class="highlight-text">
                    ${h.messageText}
                </div>
                <div class="highlight-meta">
                    <span class="highlight-time">🕐 ${formatDate(h.messageTimestamp)}</span>
                    ${h.matchedKeywords && h.matchedKeywords.length > 0 ? `
                        <span class="highlight-keywords" title="${h.matchedKeywords.join(', ')}">
                            🔑 ${h.matchedKeywords.slice(0, 3).join(', ')}
                        </span>
                    ` : ''}
                </div>
            </div>
        `;
    }).join('');
    
    // ✅ Сообщение если после фильтрации ничего не осталось
const noResultsMessage = filteredHighlights.length === 0 ? `
    <div class="no-filter-results">
        <p style="text-align: center; color: var(--text-secondary); padding: 20px;">
            ${translations.noFilterResults}
        </p>
    </div>
` : '';
    
    return `
        <div class="highlights-panel">
            <div class="highlights-header">
                <div class="highlights-header-left">
                    <h3>${translations.title}</h3>
                    <span class="highlights-count">${filteredHighlights.length} / ${highlightsData.total}</span>
                </div>
               ${needsReanalysis ? `
    <button class="reanalyze-highlights-btn" 
            onclick="reanalyzeHighlights('${highlightsData.sessionId}', 'User', 'ru')"
            title="${(translations.newMessagesDetected || 'Обнаружено {count} новых сообщений').replace('{count}', newUserMessages)}">
        🔄 <span class="reanalyze-text">${translations.reanalyze || 'Повторный анализ'}</span>
        ${newUserMessages > 0 ? `<span class="new-messages-badge">${newUserMessages}</span>` : ''}
    </button>
` : ''}
            </div>
            
            <div class="highlights-stats">
                <div class="stat-item ${activeFilter === 'pricing' ? 'active' : ''}" 
                     data-filter-type="pricing"
                     onclick="toggleHighlightFilter('pricing')"
                     style="border-left-color: ${config.types.pricing.color}; cursor: pointer; opacity: ${activeFilter === 'pricing' ? '1' : '0.7'};">
                    <span class="stat-icon">${config.types.pricing.icon}</span>
                    <span class="stat-count">${byType.pricing}</span>
                </div>
                <div class="stat-item ${activeFilter === 'objection' ? 'active' : ''}" 
                     data-filter-type="objection"
                     onclick="toggleHighlightFilter('objection')"
                     style="border-left-color: ${config.types.objection.color}; cursor: pointer; opacity: ${activeFilter === 'objection' ? '1' : '0.7'};">
                    <span class="stat-icon">${config.types.objection.icon}</span>
                    <span class="stat-count">${byType.objection}</span>
                </div>
                <div class="stat-item ${activeFilter === 'buying_signal' ? 'active' : ''}" 
                     data-filter-type="buying_signal"
                     onclick="toggleHighlightFilter('buying_signal')"
                     style="border-left-color: ${config.types.buying_signal.color}; cursor: pointer; opacity: ${activeFilter === 'buying_signal' ? '1' : '0.7'};">
                    <span class="stat-icon">${config.types.buying_signal.icon}</span>
                    <span class="stat-count">${byType.buying_signal}</span>
                </div>
            </div>
            
            <div class="highlights-list">
                ${highlightItems}
                ${noResultsMessage}
            </div>
        </div>
    `;
}

// ===============================================
// Функция прокрутки к сообщению
// ===============================================
function scrollToMessage(messageId) {
    //console.log('🎯 Scrolling to message ID:', messageId);
    
    // Находим контейнер с диалогом (scrollable container)
    const dialogContainer = document.querySelector('.dialog-messages-content');
    
    if (!dialogContainer) {
        console.error('❌ Dialog container (.dialog-messages-content) not found');
        return;
    }
    
    // Находим сообщение по data-message-id
    const messageElement = dialogContainer.querySelector(`[data-message-id="${messageId}"]`);
    
    if (!messageElement) {
        console.error('❌ Message element not found for ID:', messageId);
        console.log('Available message IDs:', 
            Array.from(dialogContainer.querySelectorAll('[data-message-id]'))
                .map(el => el.getAttribute('data-message-id'))
        );
        return;
    }
    
    //console.log('✅ Found message element, initiating scroll...');
    
    // ✅ ИСПРАВЛЕННЫЙ РАСЧЕТ: используем getBoundingClientRect для точного позиционирования
    const containerRect = dialogContainer.getBoundingClientRect();
    const messageRect = messageElement.getBoundingClientRect();
    
    // Текущая позиция скролла контейнера
    const currentScroll = dialogContainer.scrollTop;
    
    // Позиция сообщения относительно верха контейнера
    const messageRelativeTop = messageRect.top - containerRect.top;
    
    // Вычисляем целевую позицию скролла, чтобы сообщение было строго по центру
    const targetScroll = currentScroll + messageRelativeTop - (containerRect.height / 2) + (messageRect.height / 2);
    
    // Плавный скролл КОНТЕЙНЕРА (не window!)
    dialogContainer.scrollTo({
        top: Math.max(0, targetScroll), // Не скролим в минус
        behavior: 'smooth'
    });
    
    // Визуальная подсветка с небольшой задержкой для завершения скролла
    setTimeout(() => {
        messageElement.classList.add('highlight-flash');
        setTimeout(() => {
            messageElement.classList.remove('highlight-flash');
        }, 2000);
    }, 300); // Задержка 300мс для завершения плавного скролла
    
    //console.log('✅ Scroll completed to position:', targetScroll);
}

// Функция добавления inline маркеров к сообщениям
function addHighlightMarkers(messageElement, messageId) {
    const highlights = currentHighlights.filter(h => h.messageId === messageId);
    
    if (highlights.length === 0) return;
    
    const config = MonitoringConfig.highlights;
    
    highlights.forEach(h => {
        const typeConfig = config.types[h.type];
        const marker = document.createElement('span');
        marker.className = 'highlight-marker';
        marker.style.backgroundColor = typeConfig.color;
        marker.title = `${typeConfig.icon} ${h.type}`;
        marker.textContent = typeConfig.icon;
        
        messageElement.appendChild(marker);
    });
}

// Функция переключения фильтра highlights
function toggleHighlightFilter(type) {
    //console.log('🔍 Toggle filter:', type, 'Current:', activeFilter);
    
    if (activeFilter === type) {
        activeFilter = null;
        //console.log('✅ Filter disabled, showing all');
    } else {
        activeFilter = type;
        //console.log('✅ Filter enabled:', type);
    }
    
    const highlightsData = {
        hasHighlights: true,
        highlights: currentHighlights,
        total: currentHighlights.length,
        byType: calculateByType(currentHighlights)
    };
    
    const panel = document.querySelector('.dialog-highlights-sidebar');
    if (panel) {
        panel.innerHTML = renderHighlightsPanel(highlightsData);
    }
}

function calculateByType(highlights) {
    const byType = { pricing: 0, objection: 0, buying_signal: 0 };
    highlights.forEach(h => {
        if (byType[h.type] !== undefined) byType[h.type]++;
    });
    return byType;
}

// =====================================================
// ФУНКЦИЯ ДЛЯ СОЗДАНИЯ БРЕНДИРОВАНИЯ
// =====================================================

/**
 * Создает элемент брендирования в правом нижнем углу таблицы пользователей
 */
function createBrandingElement() {
    // Проверяем, включено ли брендирование
    if (!MonitoringConfig.branding || !MonitoringConfig.branding.enabled) {
        return;
    }

    const branding = MonitoringConfig.branding;

    // Удаляем старый элемент брендирования, если он существует
    const existingBranding = document.querySelector('.monitoring-branding');
    if (existingBranding) {
        existingBranding.remove();
    }

    // Создаем контейнер для брендирования
    const brandingContainer = document.createElement('div');
    brandingContainer.className = 'monitoring-branding';

    // Создаем HTML для логотипа
    let logoHtml = '';
    if (branding.logoType === 'svg' && branding.logoSvg) {
        const logoSize = branding.size || {};
        const width = logoSize.logoWidth || 32;
        const height = logoSize.logoHeight || 32;
        logoHtml = `<div class="monitoring-branding-logo" style="width: ${width}px; height: ${height}px;">${branding.logoSvg}</div>`;
    } else if (branding.logoType === 'icon' && branding.icon) {
        const logoSize = branding.size || {};
        const height = logoSize.logoHeight || 32;
        logoHtml = `<div class="monitoring-branding-icon" style="font-size: ${height}px;">${branding.icon}</div>`;
    } else if (branding.logoType === 'image' && branding.imageUrl) {
        const logoSize = branding.size || {};
        const width = logoSize.logoWidth || 32;
        const height = logoSize.logoHeight || 32;
        logoHtml = `<img src="${branding.imageUrl}" class="monitoring-branding-image" style="width: ${width}px; height: ${height}px;" alt="Logo" />`;
    }

    // Создаем HTML для текста
    const fontSize = (branding.size && branding.size.fontSize) || 12;
    const companyName = branding.companyName || 'NexusMindAI';
    const companyUrl = (branding.companyUrl || '').trim();
    const poweredByText = (branding.poweredByText || '').trim();

    // Генерируем HTML для названия компании (с ссылкой или без)
    const companyNameHTML = companyUrl ?
        `<a href="${companyUrl}" target="_blank" rel="noopener noreferrer" style="text-decoration: none; color: inherit;">
            <span class="monitoring-branding-company">${companyName}</span>
        </a>` :
        `<div class="monitoring-branding-company">${companyName}</div>`;

    brandingContainer.innerHTML = `
        ${logoHtml}
        <div class="monitoring-branding-text" style="font-size: ${fontSize}px;">
            ${poweredByText ? `<div class="monitoring-branding-powered">${poweredByText}</div>` : ''}
            ${companyNameHTML}
        </div>
    `;

    // Находим контейнер пагинации и добавляем брендирование
    const paginationContainer = document.querySelector('.pagination');
    if (paginationContainer) {
        paginationContainer.appendChild(brandingContainer);
    } else {
        // Если контейнера пагинации нет, пытаемся добавить в конец таблицы
        const tableContainer = document.querySelector('.table-container');
        if (tableContainer) {
            tableContainer.appendChild(brandingContainer);
        }
    }
}

// Экспортируем функцию в глобальную область
window.toggleBANT = toggleBANT;
// Экспортируем функцию в глобальную область
window.updateUIFromConfig = updateUIFromConfig;
// Экспортируем функцию создания брендирования
window.createBrandingElement = createBrandingElement;