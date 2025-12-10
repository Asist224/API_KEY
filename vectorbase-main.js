// =====================================================
// СИСТЕМА АУТЕНТИФИКАЦИИ
// =====================================================

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
 * Удалить токен
 */
function clearAuthToken() {
    localStorage.removeItem('authToken');
    sessionStorage.removeItem('authToken');
    localStorage.removeItem('userData');
}

/**
 * Валидация токена на сервере
 */
async function validateToken(token) {
    try {
        const baseUrl = VectorBaseConfig.technical.baseUrl;
        const endpoint = VectorBaseConfig.technical.endpoints.authValidate;
        const apiKey = VectorBaseConfig.technical.apiKey;

        const response = await fetch(`${baseUrl}${endpoint}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`,
                ...(apiKey && { 'X-API-Key': apiKey })
            }
        });

        const data = await response.json();

        if (data.valid) {
            // Сохраняем данные пользователя
            localStorage.setItem('userData', JSON.stringify(data.user));
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
    // Обновляем все текстовые элементы
    document.querySelectorAll('#authModal [data-i18n]').forEach(element => {
        const key = element.getAttribute('data-i18n');
        const translation = t(key);
        if (translation) {
            element.textContent = translation;
        }
    });
    
    // Обновляем placeholder'ы
    const usernameInput = document.getElementById('authUsername');
    const passwordInput = document.getElementById('authPassword');
    
    if (usernameInput) {
        usernameInput.placeholder = t('auth.usernamePlaceholder');
    }
    
    if (passwordInput) {
        passwordInput.placeholder = t('auth.passwordPlaceholder');
    }
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
        const baseUrl = VectorBaseConfig.technical.baseUrl;
        const endpoint = VectorBaseConfig.technical.endpoints.authLogin;
        const apiKey = VectorBaseConfig.technical.apiKey;

        const response = await fetch(`${baseUrl}${endpoint}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                ...(apiKey && { 'X-API-Key': apiKey })
            },
            body: JSON.stringify({ username, password })
        });

        const data = await response.json();

        if (data.success && data.token) {
            // Успешный вход - сохраняем токен
            saveAuthToken(data.token, rememberMe);

            // Сохраняем данные пользователя
            localStorage.setItem('userData', JSON.stringify(data.user));

            // Показываем успешное уведомление
            showToast(t('auth.loginSuccess'), 'success');

            // Скрываем модальное окно
hideAuthModal();

// Добавляем кнопку выхода и имя пользователя
addLogoutButton();
showUserInfo();

// Инициализируем интерфейс после входа
initializeInterface();

        } else {
            throw new Error(data.message || t('auth.invalidCredentials'));
        }
    } catch (error) {
        console.error('Login error:', error);

        errorText.textContent = error.message || t('auth.loginError');
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
 * Защищенный fetch с автоматической передачей JWT токена
 */
async function authFetch(url, options = {}) {
    const token = getAuthToken();

    if (!token) {
        showAuthModal();
        throw new Error('No authentication token');
    }

    // Добавляем токен в заголовки
    const authOptions = {
        ...options,
        headers: {
            ...(options.headers || {}),
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json'
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
    if (confirm(t('auth.logoutConfirm'))) {
        // Останавливаем автообновление
        stopAutoRefresh();
        
        // Очищаем токен
        clearAuthToken();
        
        // Показываем уведомление
       showToast(t('auth.logoutSuccess'), 'info');

        // Перезагружаем страницу (покажется модальное окно логина)
        setTimeout(() => {
            window.location.reload();
        }, 500);
    }
}

// =====================================================
// УПРАВЛЕНИЕ РОЛЯМИ И ДОСТУПОМ
// =====================================================

/**
 * Получить данные текущего пользователя
 */
function getCurrentUser() {
    const userDataStr = localStorage.getItem('userData');
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
        // Скрываем вкладку "Запись"
        const writeTab = document.querySelector('[onclick*="switchSection(\'write\')"]');
        if (writeTab) writeTab.style.display = 'none';
        
        // Скрываем кнопки действий с записями
        hideActionButtons(['edit', 'delete']);
        
        // Скрываем кнопку "Очистить все"
        const clearAllBtn = document.querySelector('[onclick*="clearAllRecords"]');
        if (clearAllBtn) clearAllBtn.style.display = 'none';
        
        console.log('✅ Ограничения для Viewer применены');
    }
    
    // ===== ОГРАНИЧЕНИЯ ДЛЯ MANAGER =====
    if (user.role === 'manager') {
        // Скрываем только кнопки удаления
        hideActionButtons(['delete']);
        
        // Скрываем кнопку "Очистить все"
        const clearAllBtn = document.querySelector('[onclick*="clearAllRecords"]');
        if (clearAllBtn) clearAllBtn.style.display = 'none';
        
        console.log('✅ Ограничения для Manager применены');
    }
    
    // ===== ADMIN - БЕЗ ОГРАНИЧЕНИЙ =====
    if (user.role === 'admin') {
        console.log('✅ Admin - полный доступ');
    }
}

/**
 * Скрыть кнопки действий
 */
function hideActionButtons(actionsToHide) {
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
        showToast(t('auth.notAuthorized'), 'error');
        return false;
    }
    
    const permissions = {
        'view': ['viewer', 'manager', 'admin'],
        'edit': ['manager', 'admin'],
        'write': ['manager', 'admin'],
        'delete': ['admin']
    };
    
    if (!permissions[action] || !permissions[action].includes(user.role)) {
        const requiredRoles = permissions[action].join(t('auth.or'));
        showToast(t('auth.accessDenied') + requiredRoles, 'error');
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
        <span class="logout-text" data-i18n="auth.logoutButton">${t('auth.logoutButton')}</span>
    `;

    headerControls.appendChild(logoutBtn);
}

/**
 * Показать имя пользователя в header
 */
function showUserInfo() {
    const userData = localStorage.getItem('userData');

    if (!userData) return;

    try {
        const user = JSON.parse(userData);
        const headerControls = document.querySelector('.header-controls');

        if (!headerControls || document.querySelector('.user-info')) return;

        const userInfo = document.createElement('div');
        userInfo.className = 'user-info';
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
        
        // Применяем ограничения по ролям ПОСЛЕ загрузки интерфейса
        setTimeout(() => {
            applyRoleBasedRestrictions();
        }, 200);
    }
    
    return isAuthenticated;
}

// =====================================================
// КОНЕЦ СИСТЕМЫ АУТЕНТИФИКАЦИИ
// =====================================================

// Получаем настройки из config.js
const BASE_URL = VectorBaseConfig.technical.baseUrl;
const API_KEY = VectorBaseConfig.technical.apiKey;

// Глобальные настройки Chart.js
if (typeof Chart !== 'undefined') {
    Chart.defaults.responsive = true;
    Chart.defaults.maintainAspectRatio = false;
}

let uploadedFiles = [];
let currentRecords = [];
let monitoringData = null;
let charts = {};

// Переменные для автообновления
let autoRefreshInterval = null;
let isMonitoringTabActive = false;
let refreshIntervalSeconds = 10; // Интервал обновления в секундах
let lastUpdateTime = null;

// Функция для перевода дней недели
function translateDay(dayKey) {
    // Словарь для конвертации разных форматов в ключи
    const dayMap = {
        'Пн': 'mon', 'Mon': 'mon', 'Lun': 'mon', 'Mo': 'mon', '月': 'mon', '월': 'mon', '周一': 'mon',
        'Вт': 'tue', 'Tue': 'tue', 'Mar': 'tue', 'Di': 'tue', '火': 'tue', '화': 'tue', '周二': 'tue',
        'Ср': 'wed', 'Wed': 'wed', 'Mer': 'wed', 'Mi': 'wed', '水': 'wed', '수': 'wed', '周三': 'wed',
        'Чт': 'thu', 'Thu': 'thu', 'Jeu': 'thu', 'Do': 'thu', '木': 'thu', '목': 'thu', '周四': 'thu',
        'Пт': 'fri', 'Fri': 'fri', 'Ven': 'fri', 'Fr': 'fri', '金': 'fri', '금': 'fri', '周五': 'fri',
        'Сб': 'sat', 'Sat': 'sat', 'Sam': 'sat', 'Sa': 'sat', '土': 'sat', '토': 'sat', '周六': 'sat',
        'Вс': 'sun', 'Нд': 'sun', 'Sun': 'sun', 'Dim': 'sun', 'So': 'sun', '日': 'sun', '일': 'sun', '周日': 'sun'
    };
    
    // Если это уже ключ (mon, tue и т.д.), возвращаем как есть
    if (['mon', 'tue', 'wed', 'thu', 'fri', 'sat', 'sun'].includes(dayKey)) {
        return t(`days.${dayKey}`);
    }
    
    // Конвертируем в ключ
    const key = dayMap[dayKey] || dayKey;
    return t(`days.${key}`);
}

// Инициализация
document.addEventListener('DOMContentLoaded', async function() {
    // ===== ИНИЦИАЛИЗАЦИЯ АУТЕНТИФИКАЦИИ =====
    const isAuthenticated = await initializeAuthentication();
    
    if (!isAuthenticated) {
        // Если пользователь не авторизован - не инициализируем остальное
        return;
    }
    
    // ===== ОСТАЛЬНАЯ ИНИЦИАЛИЗАЦИЯ =====
    // Инициализируем после успешной аутентификации
    initializeInterface();
});

// Новая функция для инициализации интерфейса
// Новая функция для инициализации интерфейса
function initializeInterface() {
    setupFileUpload('file-upload-area', 'file-input', 'uploaded-files');
    
    // Инициализация селектов баз данных
    populateDatabaseSelect(document.getElementById('database-selector'));
    populateDatabaseSelect(document.getElementById('write-table'));
    document.getElementById('database-selector').addEventListener('change', updateDatabaseTitle);
    
    // Инициализация кнопки FULL при загрузке
    const appendRadio = document.querySelector('input[name="write-mode"][value="append"]');
    const fullButtonContainer = document.getElementById('fullButtonContainer');
    
    if (appendRadio && appendRadio.checked && fullButtonContainer) {
        fullButtonContainer.style.display = 'block';
    }
    
    // Инициализация переключателя языка
    const savedLang = localStorage.getItem('vectorbase_language') || 'ru';
    if (VectorBaseConfig.supportedLanguages[savedLang]) {
        VectorBaseConfig.currentLanguage = savedLang;
        
        const langInfo = VectorBaseConfig.supportedLanguages[savedLang];
        const flagEl = document.getElementById('currentLanguageFlag');
        const nameEl = document.getElementById('currentLanguageName');
        
        if (flagEl) flagEl.textContent = langInfo.flag;
        if (nameEl) nameEl.textContent = langInfo.name;
        
        // Отмечаем активный язык в меню
        document.querySelectorAll('.language-item').forEach((item, index) => {
            const langs = Object.keys(VectorBaseConfig.supportedLanguages);
            if (langs[index] === savedLang) {
                item.classList.add('active');
            }
        });
    }
    
    // Обновляем интерфейс
    updateUILanguage();
    
    // Показываем плейсхолдер вместо автозагрузки
    const recordsList = document.getElementById('records-list');
    const msgDiv = document.getElementById('read-result-msg');
    if (recordsList && msgDiv) {
        recordsList.style.display = 'none';
        msgDiv.innerHTML = `
            <div style="text-align: center; padding: 60px 20px; color: var(--text-secondary);">
                <div style="font-size: 48px; margin-bottom: 20px;">📚</div>
                <h3 style="margin-bottom: 10px; color: var(--text-primary);" data-i18n="records.placeholder.title">${t('records.placeholder.title')}</h3>
                <p data-i18n="records.placeholder.subtitle">${t('records.placeholder.subtitle')}</p>
            </div>
        `;
    }
    
    // Применяем ограничения по ролям ПОСЛЕ загрузки интерфейса
    setTimeout(() => {
        applyRoleBasedRestrictions();
    }, 100);
}

// Toast уведомления
function showToast(message, type = 'info') {
    const container = document.getElementById('toastContainer');
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    
    const icons = {
        success: '✅',
        error: '❌',
        info: 'ℹ️',
        warning: '⚠️'
    };
    
    toast.innerHTML = `
        <span class="toast-icon">${icons[type]}</span>
        <span class="toast-message">${message}</span>
        <span class="toast-close" onclick="this.parentElement.remove()">✕</span>
    `;
    
    container.appendChild(toast);
    
    // Автоудаление через 5 секунд
    setTimeout(() => {
        toast.style.animation = 'slideIn 0.3s ease-out reverse';
        setTimeout(() => toast.remove(), 300);
    }, 5000);
}

// Модальное окно
function showConfirmModal(message, onConfirm) {
    const modal = document.getElementById('confirmModal');
    const confirmBtn = document.getElementById('confirmBtn');
    const confirmMessage = document.getElementById('confirmMessage');
    
    confirmMessage.textContent = message;
    modal.classList.add('show');
    
    // Удаляем старые обработчики
    const newConfirmBtn = confirmBtn.cloneNode(true);
    confirmBtn.parentNode.replaceChild(newConfirmBtn, confirmBtn);
    
    newConfirmBtn.addEventListener('click', function() {
        onConfirm();
        closeModal();
    });
}

function closeModal() {
    const modal = document.getElementById('confirmModal');
    modal.classList.remove('show');
}

// Обновление названия базы данных
function updateDatabaseTitle() {
    const selector = document.getElementById('database-selector');
    const badge = document.getElementById('current-database-badge');
    const selectedValue = selector.value;
    const selectedText = t(`databases.${selectedValue}`) || t('databases.knowledge_base');
    
    if (badge) {
        badge.textContent = selectedText.replace(/[📚💼📧💬🎭📋📊]\s/, '');
    }
}

// Обработчик режима записи
document.querySelectorAll('input[name="write-mode"]').forEach(radio => {
    radio.addEventListener('change', function() {
        const editIdGroup = document.getElementById('edit-id-group');
        const editIdLabel = document.getElementById('edit-id-label');
        const inputTabsContainer = document.getElementById('input-tabs-container');
        const fullButtonContainer = document.getElementById('fullButtonContainer'); // НОВОЕ
        
        if (this.value === 'edit' || this.value === 'delete') {
            editIdGroup.style.display = 'block';
            fullButtonContainer.style.display = 'none'; // НОВОЕ: Скрываем кнопку FULL
            
            if (this.value === 'delete') {
                editIdLabel.textContent = 'ID записи для удаления:';
                inputTabsContainer.style.display = 'none';
            } else {
                editIdLabel.textContent = 'ID записи для редактирования:';
                inputTabsContainer.style.display = 'block';
            }
        } else {
            editIdGroup.style.display = 'none';
            inputTabsContainer.style.display = 'block';
            
            // НОВОЕ: Показываем кнопку FULL только для режима "append"
            if (this.value === 'append') {
                fullButtonContainer.style.display = 'block';
            } else {
                fullButtonContainer.style.display = 'none';
            }
        }
    });
});

// Переключение вкладок
// Переключение вкладок
function switchTab(event, tabName) {
    const contents = document.querySelectorAll('.tab-content');
    contents.forEach(content => content.classList.remove('active'));
    
    const tabs = document.querySelectorAll('.tab');
    tabs.forEach(tab => tab.classList.remove('active'));
    
    document.getElementById(tabName).classList.add('active');
    event.currentTarget.classList.add('active');
    
    // Скрываем/показываем фильтры в зависимости от вкладки
    const mainFilters = document.getElementById('mainFilters');
    if (tabName === 'records') {
        mainFilters.style.display = 'flex';
    } else {
        mainFilters.style.display = 'none';
    }
    
    // ============ ДОБАВЬ ЭТО ============
    // Показываем кнопку FULL если вкладка "editor" и режим "append"
    if (tabName === 'editor') {
        const appendRadio = document.querySelector('input[name="write-mode"][value="append"]');
        const fullButtonContainer = document.getElementById('fullButtonContainer');
        
        if (appendRadio && appendRadio.checked && fullButtonContainer) {
            fullButtonContainer.style.display = 'block';
        }
    }
    // ====================================
    
    // Автоматическое управление обновлением для мониторинга
    if (tabName === 'monitoring') {
        isMonitoringTabActive = true;
        loadMonitoringData();
        startAutoRefresh(); // Автоматически запускаем
    } else {
        isMonitoringTabActive = false;
        stopAutoRefresh(); // Автоматически останавливаем
    }
}

// Переключение вкладок ввода
function switchInputTab(tabName) {
    document.querySelectorAll('.input-tab').forEach(tab => tab.classList.remove('active'));
    document.querySelectorAll('.input-content').forEach(content => content.classList.remove('active'));
    
    event.target.classList.add('active');
    document.getElementById(`input-${tabName}`).classList.add('active');
}

// Переключение вкладок мониторинга
function switchMonitoringTab(event, tabName) {
    const contents = document.querySelectorAll('.sub-content');
    contents.forEach(content => content.classList.remove('active'));
    
    const tabs = document.querySelectorAll('.sub-tab');
    tabs.forEach(tab => tab.classList.remove('active'));
    
    document.getElementById(tabName).classList.add('active');
    event.currentTarget.classList.add('active');
    
    // Обновляем данные аналитики при переключении на вкладку "Аналитика"
    if (tabName === 'analytics' && monitoringData) {
        updateAnalyticsDashboard(monitoringData);
    }
}

// Переключение на редактор
function switchToEditor(mode) {
    if (mode === 'add') {
        document.querySelector('input[value="append"]').checked = true;
        document.getElementById('edit-id-group').style.display = 'none';
        document.getElementById('input-tabs-container').style.display = 'block';
    }
    clearEditor();
    document.querySelector('[onclick*="editor"]').click();
}

// AJAX удаление записи
async function quickDeleteRecord(id) {
     // Проверка прав доступа
    if (!checkActionPermission('delete')) {
        return;
    }
    const table = document.getElementById('database-selector').value;
    
    showConfirmModal(tf('modals.confirm.deleteRecord', {id: id}), async () => {
        const recordElement = document.querySelector(`.record-item[data-id="${id}"]`);
        
        try {
            const response = await authFetch(BASE_URL + 'write-vector-base', {
                method: 'POST',
                headers: {
    'Content-Type': 'application/json',
    'X-API-Key': API_KEY
},
                body: JSON.stringify({
    table,
    mode: 'delete',
    content: 'DELETE_RECORD',
    editId: parseInt(id)
})
            });
            
            const data = await response.json();
            
            if (data.success) {
                // Анимация удаления
                if (recordElement) {
                    recordElement.classList.add('deleting');
                    setTimeout(() => {
                        recordElement.remove();
                        showToast(tf('notifications.recordDeleted', {id: id}), 'success');
                    }, 500);
                }
            } else {
                showToast(t('notifications.deleteError') + (data.message || t('notifications.unknownError')), 'error');
            }
        } catch (error) {
            showToast(t('notifications.connectionError') + error.message, 'error');
        }
    });
}

// Редактирование записи
function quickEditRecord(id, content) {
    // Проверка прав доступа
    if (!checkActionPermission('edit')) {
        return;
    }
    document.querySelector('[onclick*="editor"]').click();
    document.querySelector('input[value="edit"]').checked = true;
    document.querySelector('input[value="edit"]').dispatchEvent(new Event('change'));
    document.getElementById('edit-id').value = id;
    document.querySelector('[onclick*="text"]').click();
    document.getElementById('write-content').value = content;
    
    const currentTable = document.getElementById('database-selector').value;
    document.getElementById('write-table').value = currentTable;
}

// Редактирование записи из элемента (безопасный вариант)
function quickEditRecordFromElement(button) {
    // Проверка прав доступа
    if (!checkActionPermission('edit')) {
        return;
    }
    
    // Получаем record-item родителя
    const recordItem = button.closest('.record-item');
    const id = recordItem.getAttribute('data-id');
    const content = recordItem.getAttribute('data-content')
        .replace(/&quot;/g, '"')
        .replace(/&#39;/g, "'");
    
    // Вызываем оригинальную функцию
    quickEditRecord(id, content);
}

// Парсинг записей
function parseRecords(text) {
    const records = [];
    const lines = text.split('\n');
    let currentRecord = null;
    let contentLines = [];
    
    for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        
        const idMatch = line.match(/^Запись\s+#(\d+)\s+\(ID:\s+(\d+)\)/);
        if (idMatch) {
            if (currentRecord && contentLines.length > 0) {
                currentRecord.content = contentLines.join('\n').trim();
                records.push(currentRecord);
            }
            
            currentRecord = {
                number: idMatch[1],
                id: idMatch[2],
                content: '',
                created: ''
            };
            contentLines = [];
        } 
        else if (line.startsWith('Создано:')) {
            if (currentRecord) {
                currentRecord.created = line.replace('Создано:', '').trim();
            }
        }
        else if (line.match(/^[-=]+$/)) {
            continue;
        }
        else if (currentRecord && line.trim() !== '') {
            if (!line.startsWith('Создано:')) {
                contentLines.push(line);
            }
        }
    }
    
    if (currentRecord && contentLines.length > 0) {
        currentRecord.content = contentLines.join('\n').trim();
        records.push(currentRecord);
    }
    
    return records;
}

// Отображение записей
function displayRecords(records) {
    const container = document.getElementById('records-list');
    
    if (records.length === 0) {
        container.innerHTML = `
            <div class="empty-state">
                <h3>${t('records.emptyTitle')}</h3>
                <p>${t('records.emptyText')}</p>
            </div>
        `;
        return;
    }
    
    // 🆕 УЛУЧШЕННОЕ ОТОБРАЖЕНИЕ С БЕЗОПАСНОЙ ПЕРЕДАЧЕЙ ДАННЫХ
    container.innerHTML = records.map(record => {
        // Преобразуем переносы строк в <br> для отображения
        const displayContent = record.content.replace(/\n/g, '<br>');
        
        // Экранируем для безопасной передачи в data-атрибут
        const safeContent = record.content
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
        
        return `
            <div class="record-item" data-id="${record.id}" data-content="${safeContent}">
                <div class="record-header">
                    <div>
                        <span class="record-id">${t('records.recordNumber')} #${record.number} (ID: ${record.id})</span>
                    </div>
                    <div class="record-actions">
                        <button class="btn btn-icon btn-edit" data-action="edit" 
                            onclick="quickEditRecordFromElement(this)" 
                            title="${t('records.editTooltip')}">
                            ${t('records.editButton')}
                        </button>
                        <button class="btn btn-icon btn-delete" data-action="delete" 
                            onclick="quickDeleteRecord(${record.id})" 
                            title="${t('records.deleteTooltip')}">
                            ${t('records.deleteButton')}
                        </button>
                    </div>
                </div>
                <div class="record-content">${displayContent}</div>
                ${record.created ? `<div class="record-meta">${t('records.created')} ${record.created}</div>` : ''}
            </div>
        `;
    }).join('');
    
    // Сбрасываем на первую страницу
    currentPage = 1;
    paginateRecords();
}

// Настройка загрузки файлов
function setupFileUpload(areaId, inputId, displayId) {
    const area = document.getElementById(areaId);
    const input = document.getElementById(inputId);
    
    if (!area || !input) return;
    
    area.addEventListener('click', () => input.click());
    
    area.addEventListener('dragover', (e) => {
        e.preventDefault();
        area.classList.add('drag-over');
    });
    
    area.addEventListener('dragleave', () => {
        area.classList.remove('drag-over');
    });
    
    area.addEventListener('drop', (e) => {
        e.preventDefault();
        area.classList.remove('drag-over');
        handleFiles(e.dataTransfer.files, displayId);
    });
    
    input.addEventListener('change', (e) => {
        handleFiles(e.target.files, displayId);
    });
}

// Замените функцию handleFiles на эту версию:
async function handleFiles(files, displayId) {
    // НОВЫЕ ЛИМИТЫ
    const MAX_FILE_SIZE = 10 * 1024 * 1024; // 10MB на файл
    const MAX_TOTAL_SIZE = 50 * 1024 * 1024; // 50MB всего
    
    const allowedTypes = [
        'application/pdf',
        'text/plain',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'application/vnd.ms-excel',
        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        'text/csv',
        'application/csv'
    ];
    
    const allowedExtensions = ['.pdf', '.txt', '.docx', '.xlsx', '.xls', '.csv'];
    
    let totalSize = 0;
    
    for (let file of files) {
        const fileName = file.name.toLowerCase();
        const hasValidExtension = allowedExtensions.some(ext => fileName.endsWith(ext));
        
        // Проверка размера
        if (file.size > MAX_FILE_SIZE) {
            showToast(tf('notifications.fileTooBig', {name: file.name}), 'error');
            continue;
        }
        
        totalSize += file.size;
        if (totalSize > MAX_TOTAL_SIZE) {
            showToast(t('notifications.totalSizeExceeded'), 'error');
            break;
        }
        
        if (!hasValidExtension) {
            showToast(tf('notifications.fileNotSupported', {name: file.name}), 'warning');
            continue;
        }
        
        // Проверяем, не загружен ли уже файл с таким именем
        const alreadyUploaded = uploadedFiles.some(f => f.name === file.name);
        if (alreadyUploaded) {
            showToast(tf('notifications.fileAlreadyUploaded', {name: file.name}), 'info');
            continue;
        }
        
        const reader = new FileReader();
        reader.onload = function(e) {
            const fileData = {
                name: file.name,
                type: file.type || getMimeTypeFromExtension(fileName),
                size: file.size,
                content: e.target.result
            };
            
            uploadedFiles.push(fileData);
            displayUploadedFiles();
            showToast(tf('notifications.fileUploaded', {name: file.name}), 'success');
        };
        
        reader.onerror = function() {
            showToast(tf('notifications.fileReadError', {name: file.name}), 'error');
        };
        
        reader.readAsDataURL(file);
    }
}

// Вспомогательная функция для определения MIME типа
function getMimeTypeFromExtension(fileName) {
    const ext = fileName.split('.').pop().toLowerCase();
    const mimeTypes = {
        'pdf': 'application/pdf',
        'txt': 'text/plain',
        'docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        'xls': 'application/vnd.ms-excel',
        'csv': 'text/csv'
    };
    return mimeTypes[ext] || 'application/octet-stream';
}

// Отображение загруженных файлов
function displayUploadedFiles() {
    const container = document.getElementById('uploaded-files');
    container.innerHTML = uploadedFiles.map((file, index) => `
        <div class="file-item">
            <span>${file.name} (${(file.size / 1024).toFixed(2)} KB)</span>
            <button onclick="removeFile(${index})">Удалить</button>
        </div>
    `).join('');
}

// Удаление файлов
function removeFile(index) {
    uploadedFiles.splice(index, 1);
    displayUploadedFiles();
}

// Добавление поля URL
function addUrlInput() {
    const container = document.getElementById('url-inputs');
    const div = document.createElement('div');
    div.className = 'url-input-group';
    div.innerHTML = `
        <input type="url" placeholder="https://example.com/article" class="url-input">
        <button class="btn btn-danger btn-sm" onclick="removeUrlInput(this)">Удалить</button>
    `;
    container.appendChild(div);
}

// Удаление поля URL
function removeUrlInput(button) {
    button.parentElement.remove();
}

// Чтение базы данных
// Чтение базы данных
async function readDatabase() {
    const table = document.getElementById('database-selector').value;
    const loading = document.getElementById('read-loading');
    const recordsList = document.getElementById('records-list');
    const msgDiv = document.getElementById('read-result-msg');
    
    updateDatabaseTitle();

    loading.style.display = 'flex';
    recordsList.style.display = 'none';
    msgDiv.innerHTML = '';
    
    try {
        const response = await authFetch(BASE_URL + 'read-vector-base', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ 
                table: table,
                apiKey: API_KEY
            })
        });
        
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        const data = await response.json();
        
        if (data.success) {
            let records = [];
            
            if (data.formatted_text) {
                records = parseRecords(data.formatted_text);
            } else if (data.records) {
                // 🆕 УЛУЧШЕННАЯ ОБРАБОТКА ЗАПИСЕЙ С ПАРСИНГОМ КОНТЕНТА
                records = data.records.map((rec, index) => {
                    let contentText = '';
                    
                    // Парсим content если это JSON
                    if (typeof rec.content === 'string') {
                        const trimmed = rec.content.trim();
                        
                        // Старый формат: JSON внутри content
                        if (trimmed.startsWith('[') || trimmed.startsWith('{')) {
                            try {
                                const parsed = JSON.parse(trimmed);
                                
                                if (Array.isArray(parsed) && parsed.length > 0) {
                                    contentText = parsed[0].content || trimmed;
                                } else if (parsed.content) {
                                    contentText = parsed.content;
                                } else {
                                    contentText = trimmed;
                                }
                            } catch (e) {
                                // Не JSON - используем как есть
                                contentText = rec.content;
                            }
                        } else {
                            // Новый формат: чистый текст
                            contentText = rec.content;
                        }
                    } else {
                        contentText = JSON.stringify(rec);
                    }
                    
                    return {
                        number: index + 1,
                        id: rec.id || index + 1,
                        content: contentText,
                        created: rec.created || '',
                        metadata: rec.metadata || {}
                    };
                });
            }
            
            currentRecords = records;
            displayRecords(records);
            recordsList.style.display = 'block';
        } else {
            msgDiv.innerHTML = `<div class="error-msg">${t('notifications.deleteError')} ${data.message || data.error || t('notifications.unknownError')}</div>`;
        }
    } catch (error) {
        msgDiv.innerHTML = `<div class="error-msg">${t('notifications.connectionError')} ${error.message}</div>`;
    } finally {
        loading.style.display = 'none';
    }
}

// Замените функцию writeDatabase на эту версию:
// Замените функцию writeDatabase на эту версию:
async function writeDatabase() {
    // ===== ПРОВЕРКА ПРАВ ДОСТУПА =====
    const mode = document.querySelector('input[name="write-mode"]:checked').value;
    
    if (mode === 'edit') {
        if (!checkActionPermission('edit')) {
            return;
        }
    } else if (mode === 'delete') {
        if (!checkActionPermission('delete')) {
            return;
        }
    } else {
        // append или replace
        if (!checkActionPermission('write')) {
            return;
        }
    }
    // ===== КОНЕЦ ПРОВЕРКИ ПРАВ =====
    
    const table = document.getElementById('write-table').value;
    const editId = document.getElementById('edit-id').value;
    const loading = document.getElementById('write-loading');
    const resultDiv = document.getElementById('write-result');
    
    if ((mode === 'edit' || mode === 'delete') && !editId) {
        const action = mode === 'edit' ? t('actions.editing') : t('actions.deletion');
        showToast(tf('notifications.pleaseEnterEditId', {action: action}), 'warning');
        return;
    }
    
    if (mode === 'delete') {
        showConfirmModal(tf('modals.confirm.deleteFromTable', {id: editId, table: table}), async () => {
            await performWrite();
        });
    } else {
        await performWrite();
    }
    
    async function performWrite() {
        let content = '';
        
        if (mode === 'delete') {
            content = 'DELETE_RECORD';
        } else {
            const activeTab = document.querySelector('.input-content.active')?.id;
            
            switch(activeTab) {
                case 'input-text':
                    content = document.getElementById('write-content').value;
                    break;
                    
                case 'input-files':
                    if (uploadedFiles.length > 0) {
                        content = 'ФАЙЛЫ ДЛЯ ОБРАБОТКИ:\n';
                        uploadedFiles.forEach(file => {
                            content += `\nДокумент: ${file.name}\n[Документ для анализа и добавления в базу знаний]\n`;
                        });
                    }
                    break;
                    
                case 'input-urls':
                    const urls = Array.from(document.querySelectorAll('#url-inputs .url-input'))
                        .map(input => input.value)
                        .filter(url => url);
                    if (urls.length > 0) {
                        content = 'ССЫЛКИ ДЛЯ АНАЛИЗА:\n' + urls.join('\n');
                    }
                    break;
            }
            
            if (!content.trim() && mode !== 'delete') {
                showToast(t('notifications.pleaseEnterContent'), 'warning');
                return;
            }
        }
        
        loading.style.display = 'flex';
        resultDiv.innerHTML = '';

        try {
          // Проверяем режим AI-обработки
            const aiProcessingToggle = document.getElementById('ai-processing-toggle');
            const skipAI = aiProcessingToggle && !aiProcessingToggle.checked;
            
            const requestBody = {
    table,
    mode,
    content,
    hasFiles: uploadedFiles.length > 0,
    skipAI: skipAI && (mode === 'append' || mode === 'replace') // skipAI только для новой загрузки
};
            
            if (mode === 'edit' || mode === 'delete') {
                requestBody.editId = parseInt(editId);
            }
            
            if (uploadedFiles.length > 0) {
                requestBody.files = uploadedFiles;
            }
            
            const response = await authFetch(BASE_URL + 'write-vector-base', {
                method: 'POST',
                headers: {
    'Content-Type': 'application/json',
    'X-API-Key': API_KEY
},
                body: JSON.stringify(requestBody)
            });
            
            const data = await response.json();
            
            if (data.success) {
    let message;
    
    if (mode === 'edit') {
        message = tf('notifications.recordUpdated', {id: editId});
    } else if (mode === 'delete') {
        message = tf('notifications.recordDeleted', {id: editId});
    } else if (mode === 'append') {
        message = t('notifications.recordAdded');
    } else if (mode === 'replace') {
        message = t('notifications.databaseReplaced');
    } else {
        message = t('notifications.operationSuccess');
    }
    
    showToast(message, 'success');
                
                // ВАЖНО: Очищаем массив файлов после успешной отправки
                uploadedFiles = [];
                displayUploadedFiles();
                
                // Сбрасываем input файлов
                const fileInput = document.getElementById('file-input');
                if (fileInput) {
                    fileInput.value = '';
                }
                
                if (mode !== 'edit') {
                    clearEditor();
                }
            } else {
                showToast(t('notifications.updateError') + (data.message || t('notifications.unknownError')), 'error');
            }
        } catch (error) {
            showToast(t('notifications.connectionError') + error.message, 'error');
        } finally {
            loading.style.display = 'none';
        }
    }
}

// Замените функцию clearEditor на эту версию:
function clearEditor() {
    // Скрываем кнопку FULL при очистке
    const fullButtonContainer = document.getElementById('fullButtonContainer');
    if (fullButtonContainer) {
        fullButtonContainer.style.display = 'none';
    }
    document.getElementById('write-content').value = '';
    document.getElementById('edit-id').value = '';
    document.getElementById('write-result').innerHTML = '';
    
    // Очищаем массив файлов
    uploadedFiles = [];
    displayUploadedFiles();
    
    // Сбрасываем файловый input
    const fileInput = document.getElementById('file-input');
    if (fileInput) {
        fileInput.value = '';
    }
    
    // Очищаем URL inputs
    document.querySelectorAll('.url-input').forEach(input => {
        if (input.value) input.value = '';
    });
    
    // Возвращаемся на первую вкладку (текст)
    document.querySelector('.input-tab.active')?.classList.remove('active');
    document.querySelector('.input-content.active')?.classList.remove('active');
    document.querySelector('.input-tab')?.classList.add('active');
    document.getElementById('input-text')?.classList.add('active');
}

// Быстрый поиск
document.getElementById('quick-search')?.addEventListener('input', (e) => {
    const searchTerm = e.target.value.toLowerCase();
    const records = document.querySelectorAll('.record-item');
    
    records.forEach(record => {
        const content = record.querySelector('.record-content').textContent.toLowerCase();
        const id = record.getAttribute('data-id');
        
        if (content.includes(searchTerm) || id.includes(searchTerm)) {
            record.style.display = 'block';
        } else {
            record.style.display = 'none';
        }
    });
});

// Функция добавления команды [FULL]
function addFullCommand() {
    const textarea = document.getElementById('write-content');
    const currentText = textarea.value.trim();
    
    // Проверяем, не добавлена ли уже команда
    if (currentText.endsWith('[FULL]')) {
        showToast(t('editor.fullAlreadyAdded'), 'info');
        return;
    }
    
    // Если текст пустой
    if (!currentText) {
        showToast(t('editor.fullEnterText'), 'warning');
        return;
    }
    
    // Добавляем команду в конец текста
    textarea.value = currentText + ' [FULL]';
    
    // Визуальная анимация
    textarea.style.borderColor = 'var(--accent-primary)';
    setTimeout(() => {
        textarea.style.borderColor = '';
    }, 1000);
    
    showToast(t('editor.fullSuccess'), 'success');
}

// Функция переключения режима прямой загрузки
function toggleDirectMode() {
    const toggle = document.getElementById('ai-processing-toggle');
    const hint = document.getElementById('direct-mode-hint');
    const fullButton = document.getElementById('fullButtonContainer');
    
    // Обновляем визуальное состояние и подсказки
    if (!toggle.checked) {
        // Режим DIRECT активен
        hint.style.display = 'block';
        if (fullButton) fullButton.style.display = 'none'; // Скрываем FULL
        showToast(t('notifications.directModeActivated'), 'info');
    } else {
        // AI-обработка активна
        hint.style.display = 'none';
        if (fullButton) fullButton.style.display = 'block'; // Показываем FULL
        showToast(t('notifications.aiProcessingEnabled'), 'success');
    }
}

// Обновление UI при изменении режима
function updateDirectModeUI() {
    const toggle = document.getElementById('ai-processing-toggle');
    const hint = document.getElementById('direct-mode-hint');
    const fullButton = document.getElementById('fullButtonContainer');
    
    if (!toggle.checked) {
        // Режим DIRECT активен
        hint.style.display = 'block';
        if (fullButton) fullButton.style.display = 'none';
    } else {
        // AI-обработка активна
        hint.style.display = 'none';
        if (fullButton) fullButton.style.display = 'block';
    }
}

// Слушатель изменения toggle с уведомлениями
document.addEventListener('DOMContentLoaded', function() {
    const toggle = document.getElementById('ai-processing-toggle');
    if (toggle) {
        toggle.addEventListener('change', toggleDirectMode);
    }
    
    // Слушатель изменения режима записи
    const modeRadios = document.querySelectorAll('input[name="write-mode"]');
    modeRadios.forEach(radio => {
        radio.addEventListener('change', updateToggleVisibility);
    });
    
    // Инициализация видимости toggle и FULL кнопки
    updateToggleVisibility();
    updateDirectModeUI(); // Добавлено для инициализации FULL кнопки
});

// Функция управления видимостью toggle в зависимости от режима
function updateToggleVisibility() {
    const mode = document.querySelector('input[name="write-mode"]:checked').value;
    const toggle = document.getElementById('ai-processing-toggle');
    const toggleContainer = toggle ? toggle.closest('div[style*="padding: 15px"]') : null;
    const fullButton = document.getElementById('fullButtonContainer');
    
    if (!toggleContainer) return;
    
    // Показываем toggle только для append и replace
    if (mode === 'append' || mode === 'replace') {
        toggleContainer.style.display = 'block';
        // ВАЖНО: После показа toggle, обновляем состояние FULL кнопки
        updateDirectModeUI();
    } else {
        // Для edit/delete скрываем и toggle, и FULL кнопку
        toggleContainer.style.display = 'none';
        if (fullButton) fullButton.style.display = 'none';
    }
}

// Экспорт данных
function exportData() {
    if (currentRecords.length === 0) {
        showToast(t('notifications.noDataToExport'), 'warning');
        return;
    }
    
    const exportText = currentRecords.map(record => 
        `Запись #${record.number} (ID: ${record.id})\n${record.content}\n${record.created ? `Создано: ${record.created}` : ''}\n${'='.repeat(50)}`
    ).join('\n\n');
    
    const blob = new Blob([exportText], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `vector_base_${new Date().getTime()}.txt`;
    a.click();
    showToast(t('notifications.dataExported'), 'success');
}

// ============= ФУНКЦИИ МОНИТОРИНГА =============

// Загрузка данных мониторинга
async function loadMonitoringData() {
    try {
        const response = await authFetch(BASE_URL + 'get-learning-stats', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                period: 'last_7_days',
                include_details: true
            })
        });
        
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }
        
        const data = await response.json();
        
        if (data.success) {
            monitoringData = data.stats;
            updateMonitoringDashboard(monitoringData);
            updateAnalyticsDashboard(monitoringData);
        } else {
            throw new Error('Данные недоступны');
        }
    } catch (error) {
        console.warn('Эндпоинт статистики недоступен, используем демо-данные');
        useDemoMonitoringData();
    }
}

// ========== АВТООБНОВЛЕНИЕ С ОТЛАДКОЙ ==========

// Функция автообновления с визуальной индикацией
async function autoRefreshMonitoring() {
    if (!isMonitoringTabActive) {
        return;
    }
    
    try {
        const statsResponse = await authFetch(BASE_URL + 'get-learning-stats', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                period: 'last_7_days',
                include_details: true
            })
        });
        
        if (!statsResponse.ok) {
            console.warn('Не удалось получить статистику обучения');
            return;
        }
        
        const statsData = await statsResponse.json();
        
        if (statsData.success) {
            monitoringData = statsData.stats;
            
            // ВАЖНО: Проверяем статус цикла
            const cycleStatus = monitoringData.currentCycle?.status;
            
            // Если цикл завершен - останавливаем автообновление
            if (cycleStatus === 'completed') {
                console.log('Цикл обучения завершен - автообновление остановлено');
                stopAutoRefresh();
            }
            
            animateDataUpdate();
            updateMonitoringDashboard(monitoringData);
            updateAnalyticsDashboard(monitoringData);
            
            lastUpdateTime = new Date();
        }
    } catch (error) {
        console.warn('Ошибка автообновления:', error.message);
        // Не показываем toast при ошибке автообновления, чтобы не мешать пользователю
    }
}


// Визуальная индикация обновления
function showRefreshIndicator() {
    let indicator = document.getElementById('refresh-indicator');
    if (!indicator) {
        indicator = document.createElement('div');
        indicator.id = 'refresh-indicator';
        indicator.innerHTML = '🔄 Обновление данных...';
        indicator.style.cssText = `
            position: fixed;
            top: 80px;
            right: 20px;
            background: var(--accent-primary);
            color: white;
            padding: 10px 20px;
            border-radius: 8px;
            font-size: 14px;
            z-index: 9999;
            animation: slideIn 0.3s ease-out;
            box-shadow: 0 4px 12px rgba(102, 126, 234, 0.3);
        `;
        document.body.appendChild(indicator);
    }
    indicator.style.display = 'block';
}

function hideRefreshIndicator() {
    const indicator = document.getElementById('refresh-indicator');
    if (indicator) {
        indicator.style.animation = 'slideIn 0.3s ease-out reverse';
        setTimeout(() => {
            indicator.style.display = 'none';
        }, 300);
    }
}

// Анимация обновления данных
function animateDataUpdate() {
    // Даем браузеру время отрендерить новые элементы
    requestAnimationFrame(() => {
        // Анимируем карточки и timeline
        const cards = document.querySelectorAll('.stat-card, .timeline-item');
        cards.forEach((card, index) => {
            setTimeout(() => {
                card.classList.add('data-updated');
                setTimeout(() => {
                    card.classList.remove('data-updated');
                }, 600);
            }, index * 30);
        });
        
        // Анимируем строки таблицы истории
        const historyRows = document.querySelectorAll('#historyTableBody tr:not(.content-row)');
        historyRows.forEach((row, index) => {
            setTimeout(() => {
                row.classList.add('data-updated');
                setTimeout(() => {
                    row.classList.remove('data-updated');
                }, 600);
            }, index * 20);
        });
    });
}

// Запуск автообновления
function startAutoRefresh() {
    if (autoRefreshInterval) {
        //console.log('[AUTO-REFRESH] Уже запущено');
        return;
    }
    
    //console.log(`[AUTO-REFRESH] ЗАПУСК (интервал: ${refreshIntervalSeconds}с)`);
    autoRefreshInterval = setInterval(autoRefreshMonitoring, refreshIntervalSeconds * 1000);
}

// Остановка автообновления
function stopAutoRefresh() {
    if (autoRefreshInterval) {
        //console.log('[AUTO-REFRESH] ОСТАНОВКА');
        clearInterval(autoRefreshInterval);
        autoRefreshInterval = null;
    }
}

// Проверка изменений в данных
function checkForChanges(oldData, newData) {
    if (!oldData) return true;
    
    // Сравниваем ключевые метрики
    return (
        oldData.approvedUpdates !== newData.approvedUpdates ||
        oldData.rejectedUpdates !== newData.rejectedUpdates ||
        oldData.totalDialogs !== newData.totalDialogs ||
        oldData.recentUpdates?.length !== newData.recentUpdates?.length
    );
}

// Визуальная индикация обновления
function showRefreshIndicator() {
    let indicator = document.getElementById('refresh-indicator');
    if (!indicator) {
        indicator = document.createElement('div');
        indicator.id = 'refresh-indicator';
        indicator.innerHTML = '🔄 Обновление данных...';
        indicator.style.cssText = `
            position: fixed;
            top: 80px;
            right: 20px;
            background: var(--accent-primary);
            color: white;
            padding: 10px 20px;
            border-radius: 8px;
            font-size: 14px;
            z-index: 9999;
            animation: slideIn 0.3s ease-out;
            box-shadow: 0 4px 12px rgba(102, 126, 234, 0.3);
        `;
        document.body.appendChild(indicator);
    }
    indicator.style.display = 'block';
}

function hideRefreshIndicator() {
    const indicator = document.getElementById('refresh-indicator');
    if (indicator) {
        indicator.style.animation = 'slideIn 0.3s ease-out reverse';
        setTimeout(() => {
            indicator.style.display = 'none';
        }, 300);
    }
}

// Анимация обновления данных
function animateDataUpdate() {
    const cards = document.querySelectorAll('.stat-card, .timeline-item');
    cards.forEach((card, index) => {
        setTimeout(() => {
            card.style.animation = 'pulse 0.5s ease-out';
            setTimeout(() => {
                card.style.animation = '';
            }, 500);
        }, index * 50);
    });
}

// Запуск автообновления (без уведомлений)
function startAutoRefresh() {
    if (autoRefreshInterval) return; // Уже запущено
    
    autoRefreshInterval = setInterval(autoRefreshMonitoring, refreshIntervalSeconds * 1000);
    //console.log(`Автообновление включено (каждые ${refreshIntervalSeconds}с)`);
}

// Остановка автообновления (без уведомлений)
function stopAutoRefresh() {
    if (autoRefreshInterval) {
        clearInterval(autoRefreshInterval);
        autoRefreshInterval = null;
        //console.log('Автообновление остановлено');
    }
}

// Демо-данные для мониторинга
function useDemoMonitoringData() {
    monitoringData = {
        totalCycles: 8,
        totalDialogs: 120,
        approvedUpdates: 18,
        rejectedUpdates: 3,
        currentCycle: {
            status: 'running',
            startTime: '2025-09-16T18:33:31',
            dialogs: 5,
            totalDialogs: 15,
            workflowId: '162871'
        },
        recentUpdates: [
            {
                time: '2025-09-16 19:29:09',
                type: 'approved_update',
                action: 'append',
                table: 'conversation_scenarios',
                status: 'applied',
                priority: 90
            },
            {
                time: '2025-09-16 19:27:39',
                type: 'approved_update',
                action: 'edit',
                table: 'sales_strategies',
                status: 'applied',
                priority: 90
            },
            {
                time: '2025-09-16 19:26:27',
                type: 'rejected_update',
                action: 'append',
                table: 'communication_style',
                status: 'rejected',
                priority: null
            }
        ],
        dailyStats: [
    { date: 'Пн', updates: 12, rejected: 2 },
    { date: 'Вт', updates: 8, rejected: 1 },
    { date: 'Ср', updates: 15, rejected: 3 },
    { date: 'Чт', updates: 10, rejected: 1 },
    { date: 'Пт', updates: 18, rejected: 2 },
    { date: 'Сб', updates: 7, rejected: 1 },
    { date: 'Вс', updates: 5, rejected: 0 }
]
    };
    
    // Убедимся что dailyStats существует
    if (!monitoringData.dailyStats || monitoringData.dailyStats.length === 0) {
        monitoringData.dailyStats = [
            { date: 'Пн', updates: 12, rejected: 2 },
            { date: 'Вт', updates: 8, rejected: 1 },
            { date: 'Ср', updates: 15, rejected: 3 },
            { date: 'Чт', updates: 10, rejected: 1 },
            { date: 'Пт', updates: 18, rejected: 2 },
            { date: 'Сб', updates: 7, rejected: 1 },
            { date: 'Вс', updates: 5, rejected: 0 }
        ];
    }
    
    updateMonitoringDashboard(monitoringData);
}

// Обновление дашборда мониторинга
function updateMonitoringDashboard(data) {
    
    // Проверяем статус и управляем автообновлением
    if (data.currentCycle && data.currentCycle.status === 'running') {
        // Если цикл в процессе и автообновление не запущено - запускаем
        if (!autoRefreshInterval) {
            startAutoRefresh();
        }
    } else if (data.currentCycle && data.currentCycle.status === 'completed') {
        // Если цикл завершен - останавливаем автообновление
        stopAutoRefresh();
    }
    
    // Обновление статистических карточек
    document.getElementById('totalCycles').textContent = data.totalCycles || 0;
    document.getElementById('totalDialogs').textContent = data.totalDialogs || 0;
    document.getElementById('approvedUpdates').textContent = data.approvedUpdates || 0;
    document.getElementById('rejectedUpdates').textContent = data.rejectedUpdates || 0;
    // НОВОЕ: Обновляем динамические тексты изменений в карточках
const totalUpdates = (data.approvedUpdates || 0) + (data.rejectedUpdates || 0);
const successRate = totalUpdates > 0 ? Math.round((data.approvedUpdates / totalUpdates) * 100) : 85;
const rejectionRate = totalUpdates > 0 ? Math.round((data.rejectedUpdates / totalUpdates) * 100) : 15;

// Получаем все карточки в нужном порядке
const allStatCards = document.querySelectorAll('#overview .stat-card');

// Карточка 1: "Всего циклов обучения" - изменение за 24ч
if (allStatCards[0]) {
    const cyclesChange = data.cyclesLast24h || 2;
    const cyclesChangeSpan = allStatCards[0].querySelector('.stat-card-change span:last-child');
    if (cyclesChangeSpan) {
        cyclesChangeSpan.textContent = '+' + cyclesChange + ' ' + t('monitoring.stats.change24h');
    }
}

// Карточка 2: "Обработано диалогов" - изменение за последний цикл  
if (allStatCards[1]) {
    const dialogsChange = data.dialogsLastCycle || 15;
    const dialogsChangeSpan = allStatCards[1].querySelector('.stat-card-change span:last-child');
    if (dialogsChangeSpan) {
        dialogsChangeSpan.textContent = '+' + dialogsChange + ' ' + t('monitoring.stats.changeLastCycle');
    }
}

// Карточка 3: "Принято обновлений" - процент успешности
if (allStatCards[2]) {
    const approvedChangeDiv = allStatCards[2].querySelector('.stat-card-change');
    if (approvedChangeDiv) {
        approvedChangeDiv.innerHTML = `
            <span>↑</span>
            <span>${successRate}% ${t('monitoring.stats.percentSuccess')}</span>
        `;
        approvedChangeDiv.className = 'stat-card-change positive';
    }
}

// Карточка 4: "Отклонено правил" - процент от общего
if (allStatCards[3]) {
    const rejectedChangeDiv = allStatCards[3].querySelector('.stat-card-change');
    if (rejectedChangeDiv) {
        rejectedChangeDiv.innerHTML = `
            <span>${rejectionRate}%</span>
            <span>${t('monitoring.stats.percentOfTotal')}</span>
        `;
        rejectedChangeDiv.className = 'stat-card-change negative';
    }
}
    
   // Обновление текущего цикла
if (data.currentCycle) {
    document.getElementById('currentStartTime').textContent = 
        new Date(data.currentCycle.startTime).toLocaleString('ru-RU');
    document.getElementById('currentDialogs').textContent = 
    `${data.currentCycle.dialogs || 0}/${data.currentCycle.totalDialogs || 15}`;
    document.getElementById('currentWorkflow').textContent = 
        data.currentCycle.workflowId;
    
    // Обновляем статус badge
    const badge = document.getElementById('cycleStatusBadge');
    if (badge) {
        if (data.currentCycle.status === 'completed') {
            badge.className = 'status-badge approved';
            badge.textContent = t('monitoring.current.completed');
            
            // Показываем время завершения если есть
const completionSpan = document.getElementById('cycleCompletionTime');
if (completionSpan) {
    completionSpan.style.display = 'block';
    
    // Используем реальное время завершения если оно есть
    if (data.currentCycle.completionTime) {
        document.getElementById('completionTime').textContent = 
            new Date(data.currentCycle.completionTime).toLocaleString('ru-RU');
    } else {
        // Если нет реального времени, используем расчетное
        const endTime = new Date(data.currentCycle.startTime);
        endTime.setMinutes(endTime.getMinutes() + 30);
        document.getElementById('completionTime').textContent = endTime.toLocaleString('ru-RU');
    }
}
        } else {
            badge.className = 'status-badge running';
            badge.textContent = t('monitoring.current.running');
        }
    }
}
    
    // Создание графиков
    createCharts(data);
    
    // Обновление Timeline
    updateTimeline(data.recentUpdates);
    
    // Обновление таблицы истории
    updateHistoryTable(data.recentUpdates);
    
    // Расчет аналитики
    calculateAnalytics(data);
}

// Функция обновления вкладки Аналитика
function updateAnalyticsDashboard(data) {
    // Обновляем метрики
    const avgPriorityEl = document.getElementById('avgPriority');
    if (avgPriorityEl) {
        avgPriorityEl.textContent = data.avgPriority || '0';
    }
    
    const mostActiveTableEl = document.getElementById('mostActiveTable');
    if (mostActiveTableEl) {
        mostActiveTableEl.textContent = data.mostActiveTable || 'Нет данных';
    }
    
    // Рассчитываем процент успешности
    const total = data.approvedUpdates + data.rejectedUpdates;
    const successRate = total > 0 ? Math.round((data.approvedUpdates / total) * 100) : 0;
    const avgCycleTimeEl = document.getElementById('avgCycleTime');
    if (avgCycleTimeEl) {
        avgCycleTimeEl.textContent = successRate + '%';
    }
    
    // График эффективности - используем efficiencyChart
    const efficiencyCanvas = document.getElementById('efficiencyChart');
    if (efficiencyCanvas && data.dailyStats) {
        const ctx = efficiencyCanvas.getContext('2d');
        
        // Уничтожаем старый график если есть
        if (window.analyticsChartInstance) {
            window.analyticsChartInstance.destroy();
        }
        
        window.analyticsChartInstance = new Chart(ctx, {
    type: 'bar',
    data: {
        labels: data.dailyStats.map(d => translateDay(d.date)),
                datasets: [
                    {
                        label: t('monitoring.charts.approved'),
                        data: data.dailyStats.map(d => d.updates),
                        backgroundColor: 'rgba(74, 222, 128, 0.6)',
                        borderColor: '#4ade80',
                        borderWidth: 1
                    },
                    {
                        label: t('monitoring.charts.rejected'),
                        data: data.dailyStats.map(d => d.rejected),
                        backgroundColor: 'rgba(248, 113, 113, 0.6)',
                        borderColor: '#f87171',
                        borderWidth: 1
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                aspectRatio: window.innerWidth < 768 ? 1.5 : 2,
                plugins: {
                    legend: {
                        labels: { color: '#94a3b8' }
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        grid: { color: 'rgba(148, 163, 184, 0.1)' },
                        ticks: { color: '#94a3b8' }
                    },
                    x: {
                        grid: { display: false },
                        ticks: { color: '#94a3b8' }
                    }
                }
            }
        });
    }
    
    // Тепловая карта
    const heatmapCanvas = document.getElementById('heatmapChart');
    if (heatmapCanvas && data.recentUpdates) {
        const ctx = heatmapCanvas.getContext('2d');
        
        // Подсчитываем активность по часам
        const hourlyActivity = new Array(24).fill(0);
        data.recentUpdates.forEach(update => {
            const hour = new Date(update.time).getHours();
            hourlyActivity[hour]++;
        });
        
        // Уничтожаем старый график
        if (window.heatmapChartInstance) {
            window.heatmapChartInstance.destroy();
        }
        
        // Создаем барный график
        window.heatmapChartInstance = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: Array.from({length: 24}, (_, i) => `${i}:00`),
                datasets: [{
                    label: 'Активность',
                    data: hourlyActivity,
                    backgroundColor: hourlyActivity.map(val => {
                        const intensity = Math.min(val / 5, 1);
                        return `rgba(102, 126, 234, ${0.2 + intensity * 0.8})`;
                    }),
                    borderColor: '#667eea',
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        grid: { color: 'rgba(148, 163, 184, 0.1)' },
                        ticks: { color: '#94a3b8', stepSize: 1 }
                    },
                    x: {
                        grid: { display: false },
                        ticks: { 
                            color: '#94a3b8',
                            maxRotation: 45,
                            minRotation: 45
                        }
                    }
                }
            }
        });
    }
    // Обновляем название наиболее активной таблицы с переводом
    if (data.recentUpdates && data.recentUpdates.length > 0) {
        const tableCounts = {};
        data.recentUpdates.forEach(update => {
            tableCounts[update.table] = (tableCounts[update.table] || 0) + 1;
        });
        
        const mostActive = Object.entries(tableCounts)
            .sort((a, b) => b[1] - a[1])[0];
        
        if (mostActive) {
            const mostActiveTableEl = document.getElementById('mostActiveTable');
            if (mostActiveTableEl) {
                mostActiveTableEl.textContent = t(`databases.${mostActive[0]}`);
            }
        }
    }
} 
    

// Создание графиков
function createCharts(data) {
    // График активности
const activityCtx = document.getElementById('activityChart');
if (activityCtx) {
    // Устанавливаем фиксированную высоту для canvas
    activityCtx.style.height = '300px';
    activityCtx.style.maxHeight = '300px';
    
    if (charts.activity) charts.activity.destroy();
    
    charts.activity = new Chart(activityCtx, {
    type: 'line',
    data: {
        labels: data.dailyStats ? data.dailyStats.map(d => translateDay(d.date)) : [],
            datasets: [{
                label: t('monitoring.charts.approved'),
                data: data.dailyStats ? data.dailyStats.map(d => d.updates) : [],
                borderColor: '#10b981',
                backgroundColor: 'rgba(16, 185, 129, 0.1)',
                tension: 0.4
            }, {
                label: t('monitoring.charts.rejected'),
                data: data.dailyStats ? data.dailyStats.map(d => d.rejected) : [],
                borderColor: '#ef4444',
                backgroundColor: 'rgba(239, 68, 68, 0.1)',
                tension: 0.4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            interaction: {
                intersect: false,
                mode: 'index'
            },
            plugins: {
                legend: {
                    labels: {
                        color: '#E2E8F0'
                    }
                }
            },
            scales: {
                x: {
                    ticks: { color: '#94A3B8' },
                    grid: { color: 'rgba(255, 255, 255, 0.1)' }
                },
                y: {
                    beginAtZero: true,
                    ticks: { 
                        color: '#94A3B8',
                        stepSize: 1,
                        precision: 0
                    },
                   grid: { color: 'rgba(255, 255, 255, 0.1)' }
                }
            }
        }
    });
}

// Настройка tooltip'ов для всех графиков
const tooltipConfig = {
    callbacks: {
        title: function(tooltipItems) {
            return tooltipItems[0].label;
        },
        label: function(context) {
            let label = context.dataset.label || '';
            if (label) {
                label += ': ';
            }
            label += context.parsed.y;
            return label;
        }
    }
};

// Применяем к графикам
if (charts.activity) {
    charts.activity.options.plugins.tooltip = tooltipConfig;
    charts.activity.update();
}
if (charts.type) {
    charts.type.options.plugins.tooltip = tooltipConfig;
    charts.type.update();
}
    
    // Круговая диаграмма статусов
const statusCtx = document.getElementById('statusChart');
if (statusCtx) {
    // Устанавливаем фиксированную высоту
    statusCtx.style.height = '200px';
    statusCtx.style.maxHeight = '200px';
    
    if (charts.status) charts.status.destroy();
    
    charts.status = new Chart(statusCtx, {
        type: 'doughnut',
        data: {
            labels: [t('monitoring.charts.approved'), t('monitoring.charts.rejected')],
            datasets: [{
                data: [data.approvedUpdates || 0, data.rejectedUpdates || 0],
                backgroundColor: ['#10b981', '#ef4444']
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    labels: {
                        color: '#E2E8F0'
                    }
                }
            }
        }
    });
}
    // График типов изменений
const typeCtx = document.getElementById('typeChart');
if (typeCtx) {
    // Устанавливаем фиксированную высоту
    typeCtx.style.height = '200px';
    typeCtx.style.maxHeight = '200px';
    
    if (charts.type) charts.type.destroy();
    
    const typeStats = calculateTypeStats(data.recentUpdates || []);
    
    charts.type = new Chart(typeCtx, {
    type: 'bar',
    data: {
        labels: Object.keys(typeStats),
        datasets: [{
            label: t('monitoring.charts.changeCount'),
            data: Object.values(typeStats),
            backgroundColor: '#667eea'
        }]
    },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: false
                }
            },
            scales: {
                x: {
                    ticks: { color: '#94A3B8' },
                    grid: { color: 'rgba(255, 255, 255, 0.1)' }
                },
                y: {
                    beginAtZero: true,
                    ticks: { 
                        color: '#94A3B8',
                        stepSize: 1,
                        precision: 0
                    },
                    grid: { color: 'rgba(255, 255, 255, 0.1)' }
                }
            }
        }
    });
  }
}

// Расчет статистики по типам
function calculateTypeStats(updates) {
    const stats = {
        'append': 0,
        'edit': 0,
        'delete': 0
    };
    
    updates.forEach(update => {
        if (stats[update.action] !== undefined) {
            stats[update.action]++;
        }
    });
    
   return {
        [t('monitoring.charts.addAction')]: stats.append,
        [t('monitoring.charts.editAction')]: stats.edit,
        [t('monitoring.charts.deleteAction')]: stats.delete
    };
}

// Обновление Timeline
function updateTimeline(updates) {
    const timeline = document.getElementById('currentTimeline');
    if (!timeline) return;
    
    const recentUpdates = updates.slice(0, 5);
    
    timeline.innerHTML = recentUpdates.map(update => {
        const statusClass = update.status === 'applied' ? 'success' : 'error';
        const actionText = {
            'append': t('monitoring.charts.addAction'),
            'edit': t('monitoring.charts.editAction'),
            'delete': t('monitoring.charts.deleteAction')
        }[update.action] || update.action;
        
        return `
            <div class="timeline-item ${statusClass}">
                <div class="timeline-marker"></div>
                <div class="timeline-time">${new Date(update.time).toLocaleTimeString('ru-RU')}</div>
                <div class="timeline-title">${actionText}</div>
                <div class="timeline-description">
    ${t('monitoring.current.table')} ${update.table}<br>
    ${t('monitoring.history.columns.status')}: <span class="status-badge ${update.status}">${
        update.status === 'applied' ? t('monitoring.history.statusApplied') : t('monitoring.history.statusRejected')
    }</span>
</div>
            </div>
        `;
    }).join('');
    
    // Анимируем новые элементы после рендеринга
    requestAnimationFrame(() => {
        const items = timeline.querySelectorAll('.timeline-item');
        items.forEach((item, index) => {
            setTimeout(() => {
                item.classList.add('data-updated');
                setTimeout(() => {
                    item.classList.remove('data-updated');
                }, 600);
            }, index * 50);
        });
    });
}

// Переменные для сортировки
let sortColumn = 'time';
let sortDirection = 'desc';
let allUpdates = [];

// Обновление таблицы истории с сортировкой
function updateHistoryTable(updates) {
    const tbody = document.getElementById('historyTableBody');
    if (!tbody) return;
    
    // Сохраняем все обновления для сортировки
    if (updates) {
        allUpdates = updates;
    }
    
    // Сортируем данные
    const sortedUpdates = [...allUpdates].sort((a, b) => {
        let aVal = a[sortColumn];
        let bVal = b[sortColumn];
        
        // Для времени преобразуем в timestamp
        if (sortColumn === 'time') {
            aVal = new Date(aVal).getTime();
            bVal = new Date(bVal).getTime();
        }
        
        // Для чисел
        if (sortColumn === 'priority') {
            aVal = aVal || 0;
            bVal = bVal || 0;
        }
        
        // Сравнение
        if (aVal < bVal) return sortDirection === 'asc' ? -1 : 1;
        if (aVal > bVal) return sortDirection === 'asc' ? 1 : -1;
        return 0;
    });
    
    tbody.innerHTML = sortedUpdates.map((update, index) => {
        const statusBadge = update.status === 'applied' 
            ? `<span class="status-badge approved">${t('monitoring.history.statusApplied')}</span>`
            : `<span class="status-badge rejected">${t('monitoring.history.statusRejected')}</span>`;
        
        const hasContent = update.content && update.content !== 'null';
        // Подготовка дополнительной информации (УБРАЛИ history_check)
        const hasExtendedInfo = update.reason || update.problem_addressed;
        const reasonText = update.reason || t('formatting.unknown');
        const problemText = update.problem_addressed || t('formatting.unknown');
        const rowClass = (hasContent || hasExtendedInfo) ? 'clickable-row' : '';
        
        return `
            <tr class="${rowClass}" data-update-index="${index}" ${(hasContent || hasExtendedInfo) ? 'onclick="toggleContent(this, ' + index + ')"' : ''}>
                <td>${new Date(update.time).toLocaleString('ru-RU')}</td>
                <td>${update.type}</td>
                <td>${update.action}</td>
                <td>${update.table}</td>
                <td>${statusBadge}</td>
                <td>${update.priority || '-'}</td>
                <td>${(hasContent || hasExtendedInfo) ? `<span style="cursor: pointer;">${t('monitoring.history.viewContent')}</span>` : '-'}</td>
            </tr>
           ${hasContent || hasExtendedInfo ? `
            <tr class="content-row" id="content-row-${index}" style="display: none;">
                <td colspan="7">
                    <div class="content-preview">
                        ${hasExtendedInfo ? `
                        <div style="background: var(--secondary-bg); padding: 15px; border-radius: 8px; margin-bottom: 15px; border-left: 3px solid var(--accent-primary);">
                            <h4 style="color: var(--accent-primary); margin-bottom: 15px; font-size: 14px; font-weight: 600;">${t('monitoring.history.infoTitle')}</h4>
                            
                            <div style="margin-bottom: 15px;">
                                <div style="color: var(--text-secondary); font-size: 12px; font-weight: 600; text-transform: uppercase; margin-bottom: 5px;">${t('monitoring.history.reasonLabel')}</div>
                                <div style="color: var(--text-primary); line-height: 1.6; font-size: 14px; background: var(--primary-bg); padding: 10px; border-radius: 6px;">${escapeHtml(reasonText)}</div>
                            </div>
                            
                            <div>
                                <div style="color: var(--text-secondary); font-size: 12px; font-weight: 600; text-transform: uppercase; margin-bottom: 5px;">${t('monitoring.history.problemLabel')}</div>
                                <div style="color: var(--text-primary); line-height: 1.6; font-size: 14px; background: var(--primary-bg); padding: 10px; border-radius: 6px;">${escapeHtml(problemText)}</div>
                            </div>
                        </div>` : ''}
                        
                        ${hasContent ? `
                        <div class="content-header">
                            <strong>${t('monitoring.history.contentLabel')}</strong>
                            <button class="btn btn-sm" onclick="copyContent('${escape(update.content)}')">${t('monitoring.history.copyButton')}</button>
                        </div>
                        <pre class="content-text">${escapeHtml(update.content)}</pre>` : ''}
                    </div>
                </td>
            </tr>` : ''}
        `;
    }).join('');
    // Анимируем новые строки после рендеринга
    requestAnimationFrame(() => {
        const rows = tbody.querySelectorAll('tr:not(.content-row)');
        rows.forEach((row, index) => {
            setTimeout(() => {
                row.classList.add('data-updated');
                setTimeout(() => {
                    row.classList.remove('data-updated');
                }, 600);
            }, index * 30);
        });
    });
    
    // Применяем пагинацию к истории
    historyCurrentPage = 1;
    paginateHistory();
     document.querySelectorAll('.clickable-row').forEach(row => {
        row.style.minHeight = row.offsetHeight + 'px';
    });
}

// Функция сортировки таблицы
function sortTable(column) {
    if (sortColumn === column) {
        // Меняем направление
        sortDirection = sortDirection === 'asc' ? 'desc' : 'asc';
    } else {
        // Новая колонка
        sortColumn = column;
        sortDirection = 'asc';
    }
    
    // Обновляем индикаторы сортировки
    document.querySelectorAll('.sort-indicator').forEach(indicator => {
        indicator.textContent = '';
    });
    
    const indicator = document.querySelector(`[data-sort="${column}"] .sort-indicator`);
    if (indicator) {
        indicator.textContent = sortDirection === 'asc' ? ' ↑' : ' ↓';
    }
    
    // Обновляем таблицу
    updateHistoryTable();
}

// Функция для показа/скрытия содержимого
function toggleContent(row, index) {
    const contentRow = document.getElementById(`content-row-${index}`);
    if (!contentRow) return;
    
    const isCurrentlyVisible = contentRow.classList.contains('show');
    
    // Закрываем все открытые строки
    document.querySelectorAll('.content-row.show').forEach(r => {
        r.classList.remove('show');
        r.style.display = 'none';
    });
    
    document.querySelectorAll('.clickable-row.expanded').forEach(r => {
        r.classList.remove('expanded');
    });
    
    // Если текущая строка была закрыта, открываем её
    if (!isCurrentlyVisible) {
        // Небольшая задержка для плавности
        setTimeout(() => {
            contentRow.classList.add('show');
            contentRow.style.display = 'table-row';
            row.classList.add('expanded');
            
            // Прокручиваем к строке на мобильных (без скачков)
            if (window.innerWidth <= 768) {
                setTimeout(() => {
                    const rowRect = row.getBoundingClientRect();
                    const isVisible = (
                        rowRect.top >= 0 &&
                        rowRect.bottom <= window.innerHeight
                    );
                    
                    // Прокручиваем только если строка не полностью видна
                    if (!isVisible) {
                        row.scrollIntoView({ 
                            behavior: 'smooth', 
                            block: 'start',
                            inline: 'nearest'
                        });
                    }
                }, 50);
            }
        }, 10);
    }
}

// Функция для экранирования HTML
function escapeHtml(text) {
    const map = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#039;'
    };
    return text.replace(/[&<>"']/g, m => map[m]);
}

// Функция для копирования содержимого
function copyContent(content) {
    const unescaped = unescape(content);
    navigator.clipboard.writeText(unescaped).then(() => {
        showToast(t('notifications.copiedToClipboard'), 'success');
    });
}

// Функция unescape для копирования
function unescape(text) {
    const map = {
        '&amp;': '&',
        '&lt;': '<',
        '&gt;': '>',
        '&quot;': '"',
        '&#039;': "'"
    };
    return text.replace(/&amp;|&lt;|&gt;|&quot;|&#039;/g, m => map[m]);
}


// Фильтрация истории
function filterHistory() {
    const filter = document.getElementById('historyFilter').value;
    const rows = document.querySelectorAll('#historyTableBody tr');
    
    rows.forEach(row => {
        const statusCell = row.querySelector('.status-badge');
        if (!statusCell) return;
        
        if (filter === 'all') {
            row.style.display = '';
        } else if (filter === 'approved' && statusCell.classList.contains('approved')) {
            row.style.display = '';
        } else if (filter === 'rejected' && statusCell.classList.contains('rejected')) {
            row.style.display = '';
        } else {
            row.style.display = 'none';
        }
    });
}

// Расчет аналитики
function calculateAnalytics(data) {
    // Средний приоритет
    const priorities = data.recentUpdates
        .filter(u => u.priority)
        .map(u => u.priority);
    
    const avgPriority = priorities.length > 0 
        ? Math.round(priorities.reduce((a, b) => a + b, 0) / priorities.length)
        : 0;
    
    document.getElementById('avgPriority').textContent = avgPriority;
    
    // Среднее время цикла (демо)
    document.getElementById('avgCycleTime').textContent = '16м';
    
    // Наиболее активная таблица
    const tableCounts = {};
    data.recentUpdates.forEach(update => {
        tableCounts[update.table] = (tableCounts[update.table] || 0) + 1;
    });
    
    const mostActive = Object.entries(tableCounts)
        .sort((a, b) => b[1] - a[1])[0];
    
    if (mostActive) {
    // Используем полный перевод названия базы данных с эмодзи
    document.getElementById('mostActiveTable').textContent = t(`databases.${mostActive[0]}`);
}
}

// ============= ФУНКЦИИ ПАГИНАЦИИ =============
// Глобальные переменные для пагинации
let currentPage = 1;
let recordsPerPage = 15;
let historyCurrentPage = 1;
let historyPerPage = 15;

// Функция пагинации для записей
function paginateRecords() {
    const records = Array.from(document.querySelectorAll('.record-item'));
    const totalRecords = records.length;
    const totalPages = Math.ceil(totalRecords / recordsPerPage);
    
    // Скрываем все записи
    records.forEach(record => record.style.display = 'none');
    
    // Показываем только записи текущей страницы
    const start = (currentPage - 1) * recordsPerPage;
    const end = start + recordsPerPage;
    
    records.slice(start, end).forEach(record => {
        record.style.display = 'block';
    });
    
    // Обновляем контролы пагинации
    updatePaginationControls('records-pagination', currentPage, totalPages, totalRecords);
}

// Функция обновления контролов пагинации
function updatePaginationControls(containerId, page, totalPages, totalItems) {
    let container = document.getElementById(containerId);
    
    // Создаем контейнер если его нет
    if (!container) {
        container = document.createElement('div');
        container.id = containerId;
        container.className = 'pagination';
        
        if (containerId === 'records-pagination') {
            const recordsList = document.getElementById('records-list');
            if (recordsList && recordsList.parentNode) {
                recordsList.parentNode.appendChild(container);
            }
        } else if (containerId === 'history-pagination') {
            const historyTable = document.querySelector('#history .table-container');
            if (historyTable) {
                historyTable.appendChild(container);
            }
        }
    }
    
    // Формируем HTML пагинации
    let paginationHTML = `
        <button onclick="changePage('${containerId.replace('-pagination', '')}', 1)" ${page === 1 ? 'disabled' : ''}>
            ⏮️
        </button>
        <button onclick="changePage('${containerId.replace('-pagination', '')}', ${page - 1})" ${page === 1 ? 'disabled' : ''}>
            ◀️
        </button>
       <span class="pagination-info">
            ${t('pagination.page')} ${page} ${t('pagination.of')} ${totalPages} (${t('pagination.total')} ${totalItems})
        </span>
        <button onclick="changePage('${containerId.replace('-pagination', '')}', ${page + 1})" ${page === totalPages ? 'disabled' : ''}>
            ▶️
        </button>
        <button onclick="changePage('${containerId.replace('-pagination', '')}', ${totalPages})" ${page === totalPages ? 'disabled' : ''}>
            ⏭️
        </button>
    `;
    
    container.innerHTML = paginationHTML;
}

// Функция смены страницы
function changePage(type, newPage) {
    if (type === 'records') {
        currentPage = newPage;
        paginateRecords();
    } else if (type === 'history') {
        historyCurrentPage = newPage;
        paginateHistory();
    }
}

// Функция пагинации для истории
function paginateHistory() {
    const rows = Array.from(document.querySelectorAll('#historyTableBody tr'));
    const dataRows = rows.filter(row => !row.classList.contains('content-row'));
    const totalRows = dataRows.length;
    const totalPages = Math.ceil(totalRows / historyPerPage);
    
    // Скрываем все строки
    rows.forEach(row => row.style.display = 'none');
    
    // Показываем только строки текущей страницы
    const start = (historyCurrentPage - 1) * historyPerPage;
    const end = start + historyPerPage;
    
    dataRows.slice(start, end).forEach(row => {
        row.style.display = '';
    });
    
    // Обновляем контролы пагинации
    updatePaginationControls('history-pagination', historyCurrentPage, totalPages, totalRows);
}

// Остановка автообновления при закрытии страницы
window.addEventListener('beforeunload', () => {
    stopAutoRefresh();
});

// Остановка/запуск при переключении вкладок браузера
document.addEventListener('visibilitychange', () => {
    if (document.hidden && autoRefreshInterval) {
        stopAutoRefresh();
    } else if (!document.hidden && isMonitoringTabActive) {
        startAutoRefresh();
    }
});

// ===============================================
// ФУНКЦИИ ПЕРЕКЛЮЧАТЕЛЯ ЯЗЫКА
// ===============================================

// Переключение меню языков
function toggleLanguageMenu() {
    const menu = document.getElementById('languageMenu');
    const btn = document.querySelector('.language-btn');
    
    menu.classList.toggle('show');
    btn.classList.toggle('active');
    
    // Закрытие при клике вне меню
    if (menu.classList.contains('show')) {
        setTimeout(() => {
            document.addEventListener('click', closeLanguageMenuOutside);
        }, 0);
    } else {
        document.removeEventListener('click', closeLanguageMenuOutside);
    }
}

// Закрытие меню при клике вне его
function closeLanguageMenuOutside(e) {
    const menu = document.getElementById('languageMenu');
    const btn = document.querySelector('.language-btn');
    
    if (!menu.contains(e.target) && !btn.contains(e.target)) {
        menu.classList.remove('show');
        btn.classList.remove('active');
        document.removeEventListener('click', closeLanguageMenuOutside);
    }
}

// Выбор языка
function selectLanguage(langCode) {
    if (VectorBaseConfig.supportedLanguages[langCode]) {
        VectorBaseConfig.currentLanguage = langCode;
        localStorage.setItem('vectorbase_language', langCode);
        
        const langInfo = VectorBaseConfig.supportedLanguages[langCode];
        document.getElementById('currentLanguageFlag').textContent = langInfo.flag;
        document.getElementById('currentLanguageName').textContent = langInfo.name;
        
        // Обновляем активный элемент в меню
        document.querySelectorAll('.language-item').forEach(item => {
            item.classList.remove('active');
        });
        
        // Находим и отмечаем выбранный язык как активный
        const langs = Object.keys(VectorBaseConfig.supportedLanguages);
        const selectedIndex = langs.indexOf(langCode);
        if (selectedIndex !== -1) {
            const items = document.querySelectorAll('.language-item');
            if (items[selectedIndex]) {
                items[selectedIndex].classList.add('active');
            }
        }
        
        toggleLanguageMenu();
        updateUILanguage();
    }
}

// Функция обновления языка интерфейса
function updateUILanguage() {
    // Обновляем все элементы с data-i18n
    document.querySelectorAll('[data-i18n]').forEach(element => {
        const key = element.getAttribute('data-i18n');
        const translation = t(key);
        if (translation) {
            element.textContent = translation;
        }
    });
    
    // Обновляем placeholder'ы для форм
    document.querySelectorAll('[data-i18n-placeholder]').forEach(element => {
        const key = element.getAttribute('data-i18n-placeholder');
        const translation = t(key);
        if (translation) {
            element.placeholder = translation;
        }
    });
    
    // Обновляем текст кнопки выхода если она есть
    const logoutText = document.querySelector('.logout-text');
    if (logoutText) {
        logoutText.textContent = t('auth.logoutButton');
    }
    
    // Обновляем графики если они есть
    recreateCharts();
}

// Функция обновления переводов в графиках
function recreateCharts() {
    // Проверяем, что мы на вкладке мониторинга и есть данные
    if (!monitoringData) {
        return;
    }
    
    // Обновляем labels в существующих графиках вместо пересоздания
    if (charts.activity) {
        charts.activity.data.datasets[0].label = t('monitoring.charts.approved');
        charts.activity.data.datasets[1].label = t('monitoring.charts.rejected');
        charts.activity.update();
    }
    
    if (charts.status) {
        charts.status.data.labels = [
            t('monitoring.charts.approved'), 
            t('monitoring.charts.rejected')
        ];
        charts.status.update();
    }
    
    if (charts.type) {
    // ИСПРАВЛЕНИЕ: правильно обновляем labels для типов
    const typeStats = calculateTypeStats(monitoringData.recentUpdates || []);
    charts.type.data.labels = Object.keys(typeStats);
    charts.type.data.datasets[0].label = t('monitoring.charts.changeCount');
    charts.type.update();
}
    
    // Обновляем графики из вкладки Аналитика
    if (window.analyticsChartInstance) {
        window.analyticsChartInstance.data.datasets[0].label = t('monitoring.charts.approved');
        window.analyticsChartInstance.data.datasets[1].label = t('monitoring.charts.rejected');
        window.analyticsChartInstance.update();
    }
    
    if (window.heatmapChartInstance) {
        window.heatmapChartInstance.data.datasets[0].label = t('monitoring.charts.activity');
        window.heatmapChartInstance.update();
    }
}
