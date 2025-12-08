// webchat-config.js - Конфигурации с поддержкой выбора темы
// =====================================================================================
// УНИВЕРСАЛЬНАЯ СИСТЕМА ВЕБ-ЧАТА С НАСТРОЙКАМИ ТЕМЫ
// =====================================================================================

// ===============================================
// НАСТРОЙКА ОТЛАДОЧНЫХ ЛОГОВ
// ===============================================
const CONFIG_DEBUG = false; // Установите true для включения отладочных логов

// ===============================================
// ГЛОБАЛЬНЫЕ НАСТРОЙКИ СИСТЕМЫ ПЕРЕКЛЮЧЕНИЯ
// ===============================================
const GlobalConfigSettings = {
    showConfigSwitcher: true,
    languageSettings: {
        showLanguageSwitcher: true,
        autoDetectLanguage: true,
        rememberUserChoice: true,
        fallbackLanguage: "en",
        iconSettings: {
            type: "flags",
            showTooltips: true,
            customIcons: {
                ru: "🇷🇺",
                en: "🇺🇸",
                es: "🇪🇸",
                fr: "🇫🇷",
                de: "🇩🇪",
                it: "🇮🇹",
                pt: "🇵🇹",
                zh: "🇨🇳",
                ja: "🇯🇵",
                ko: "🇰🇷",
                ua: "🇺🇦"
            },
            languageNames: {
                ru: {
                    ru: "Русский",
                    en: "Russian",
                    ua: "Російська",
                    fr: "Russe"
                },
                en: {
                    ru: "Английский",
                    en: "English",
                    ua: "Англійська",
                    fr: "Anglais"
                },
                es: {
                    ru: "Испанский",
                    en: "Spanish",
                    ua: "Іспанська",
                    fr: "Espagnol"
                },
                fr: {
                    ru: "Французский",
                    en: "French",
                    ua: "Французька",
                    fr: "Français"
                },
                de: {
                    ru: "Немецкий",
                    en: "German",
                    ua: "Німецька",
                    fr: "Allemand"
                },
                it: {
                    ru: "Итальянский",
                    en: "Italian",
                    ua: "Італійська",
                    fr: "Italien"
                },
                pt: {
                    ru: "Португальский",
                    en: "Portuguese",
                    ua: "Португальська",
                    fr: "Portugais"
                },
                zh: {
                    ru: "Китайский",
                    en: "Chinese",
                    ua: "Китайська",
                    fr: "Chinois"
                },
                ja: {
                    ru: "Японский",
                    en: "Japanese",
                    ua: "Японська",
                    fr: "Japonais"
                },
                ko: {
                    ru: "Корейский",
                    en: "Korean",
                    ua: "Корейська",
                    fr: "Coréen"
                },
                ua: {
                    ru: "Украинский",
                    en: "Ukrainian",
                    ua: "Українська",
                    fr: "Ukrainien"
                }
            }
        }
    },
    configSwitcher: {
        position: "header",
        title: "Сменить специалиста",
        showLabels: true,
        defaultConfig: "financeConfig"
    },
    availableConfigs: {
    financeConfig: {
        enabled: true,
        order: 1
    },
    ecommerceConfig: {
        enabled: true,
        order: 2,
        labels: {
            ru: "🛍️ Магазин",
            en: "🛍️ Shop",
            es: "🛒 Tienda",
            fr: "🛍️ Boutique",
            de: "🛒 Shop",
            it: "🛒 Negozio",
            pt: "🛒 Loja",
            zh: "🛒 商店",
            ja: "🛒 ショップ",
            ko: "🛒 상점",
            ua: "🛍️ Магазин"
        },
        descriptions: {
            ru: "Помощник по покупкам",
            en: "Shopping Assistant",
            es: "Asistente de compras",
            fr: "Assistant shopping",
            de: "Einkaufsassistent",
            it: "Assistente acquisti",
            pt: "Assistente de compras",
            zh: "购物助手",
            ja: "ショッピングアシスタント",
            ko: "쇼핑 도우미",
            ua: "Помічник з покупок"
        }
    },
    techConfig: {
        enabled: true,
        order: 3
    },
    educationConfig: {
        enabled: true,
        order: 4
    }
},
    themeSettings: {
        globalTheme: "auto",
        allowPerConfigTheme: true,
        userCanChange: false
    },
    prioritySettings: {
        useIndividualSettings: false,
        allowPartialOverride: true
    },
    streamingAnimation: {
        enabled: true,
        speed: 70,
        chunkType: "word"
    },
    gdpr: {
        enabled: true,
        mode: "strict",
        privacyPolicyUrl: "https://cryptomator.pro/legal/privacy-policy-ru.html",
        privacyPolicyVersion: 1,
        termsOfServiceUrl: "https://cryptomator.pro/legal/terms-ru.html",
        cookiePolicyUrl: "https://cryptomator.pro/legal/disclaimer-ru.html",
        consentBanner: {
            enabled: true,
            blockChat: true,
            position: "bottom",
            expireDays: 365,
            showDeclineButton: true,
            showPrivacyLink: true,
            showCookieLink: true,
            showTermsLink: true,
            showMonitoringInConsent: true,
            customText: null,
            animation: "slide"
        },
        preChatForm: {
            enabled: true,
            showAfterConsent: true,
            skipIfDataExists: true,
            displayMode: "inline",
            fields: [
                {
                    id: "name",
                    type: "text",
                    required: true,
                    isPII: true,
                    minLength: 2,
                    maxLength: 100,
                    pattern: null,
                    validation: {
                        minLength: 2,
                        maxLength: 100,
                        pattern: "^[a-zA-Zа-яА-ЯёЁіІїЇєЄ\\s\\-]+$",
                        errorMessage: {
                            ru: "Введите корректное имя (минимум 2 символа)",
                            en: "Please enter a valid name (minimum 2 characters)"
                        }
                    },
                    enabled: true
                },
                {
                    id: "email",
                    type: "email",
                    required: true,
                    isPII: true,
                    validation: {
                        errorMessage: {
                            ru: "Введите корректный email адрес",
                            en: "Please enter a valid email address"
                        }
                    }
                },
                {
                    id: "phone",
                    type: "tel",
                    required: false,
                    isPII: true,
                    validation: {
                        minLength: 10,
                        maxLength: 20,
                        errorMessage: {
                            ru: "Введите корректный номер телефона (10-20 символов)",
                            en: "Please enter a valid phone number (10-20 characters)"
                        }
                    }
                },
                {
                    id: "company",
                    type: "text",
                    required: false,
                    isPII: false,
                    validation: {
                        maxLength: 200
                    },
                    enabled: true
                }
            ],
            gdprCheckbox: {
                enabled: true,
                required: true,
                linkToPrivacy: true
            },
            submitToWebhook: true,
            webhookOnEveryField: false
        },
        aiDisclosure: {
            enabled: true,
            showInWelcome: true,
            showInConsent: true
        },
        privacyControls: {
            enabled: true,
            options: {
                viewData: true,
                editData: true,
                exportData: true,
                deleteHistory: true,
                revokeConsent: true,
                deleteAllData: true
            }
        },
        dataMinimization: {
            enabled: true,
            collectOnlyNecessary: true,
            anonymizeAfterDays: 90,
            autoDeleteInactiveDays: 365,
            piiMasking: {
                enabled: true,
                maskInLogs: true,
                maskInExports: false
            },
            collectIP: false
        },
        cookieManagement: {
            enabled: true,
            strictMode: true,
            categories: {
                necessary: {
                    enabled: true,
                    required: true,
                    cookies: [
                        "session_id",
                        "gdpr_consent",
                        "language"
                    ]
                },
                functional: {
                    enabled: true,
                    required: false,
                    cookies: [
                        "theme",
                        "preferences",
                        "chat_history_local"
                    ]
                },
                analytics: {
                    enabled: false,
                    required: false,
                    cookies: [
                        "_ga",
                        "_gid",
                        "analytics_session"
                    ]
                },
                marketing: {
                    enabled: false,
                    required: false,
                    cookies: {

                    }
                }
            }
        },
        chatHistory: {
            enabled: true,
            storeLocally: true,
            maxLocalMessages: 100,
            encryptLocal: true,
            autoExpireDays: 30,
            allowUserDelete: true
        },
        dataRetention: {
            enabled: true,
            consentRecords: {
                retentionDays: 1825,
                archiveAfterDays: 365
            },
            chatHistory: {
                retentionDays: 365,
                archiveAfterDays: 90
            },
            userData: {
                retentionDays: 730,
                anonymizeAfterDays: 365
            },
            logs: {
                retentionDays: 90,
                archiveAfterDays: 30
            }
        },
        webhooks: {
            consent: "https://n8n.cryptomator.pro/webhook/gdpr-consent",
            preChatForm: "https://n8n.cryptomator.pro/webhook/prechat-form",
            dataAccess: "https://n8n.cryptomator.pro/webhook/gdpr-data-access",
            dataExport: "https://n8n.cryptomator.pro/webhook/gdpr-data-export",
            dataDelete: "https://n8n.cryptomator.pro/webhook/delete-session-gdrp",
            consentRevoke: "https://n8n.cryptomator.pro/webhook/consent-revoke",
            timeout: 10000,
            retryAttempts: 3,
            retryDelay: 1000,
            headers: {
                "Content-Type": "application/json",
                "X-GDPR-Source": "nexusmind-webchat"
            },
            logRequests: true
        },
        advanced: {
            httpsOnly: true,
            debugMode: true,
            storagePrefix: "nexusmind_gdpr_",
            geoLocation: {
                enabled: true,
                detectionMode: "hybrid",
                detectCountry: true,
                apiUrl: "https://ipapi.co/json/",
                euCountries: [
                    "AT",
                    "BE",
                    "BG",
                    "HR",
                    "CY",
                    "CZ",
                    "DK",
                    "EE",
                    "FI",
                    "FR",
                    "DE",
                    "GR",
                    "HU",
                    "IE",
                    "IT",
                    "LV",
                    "LT",
                    "LU",
                    "MT",
                    "NL",
                    "PL",
                    "PT",
                    "RO",
                    "SK",
                    "SI",
                    "ES",
                    "SE"
                ],
                strictForEU: true
            },
            auditLog: {
                enabled: true,
                logConsent: true,
                logDataAccess: true,
                logDataModification: true,
                retentionDays: 1825
            }
        }
    }
};

// ===============================================
// БАЗОВЫЕ МЕТОДЫ ДЛЯ ВСЕХ КОНФИГУРАЦИЙ
// ===============================================
const configMethods = {
    // Получение текстов для текущего языка
    // ✅ ИСПРАВЛЕННЫЙ МЕТОД getTexts в configMethods
getTexts() {
    // ✅ ИСПРАВЛЕНИЕ: Получаем текущий язык из чата, а не из конфига
    const currentLanguage = (window.webChat && window.webChat.currentLanguage) || this.language || 'ru';
    const configTexts = this.texts[currentLanguage] || this.texts[this.language] || this.texts.ru;
    const baseTexts = getBaseInterfaceTexts(currentLanguage);
    
    // Объединяем тексты конфигурации с базовыми интерфейсными текстами
    return {
        ...configTexts,
        interface: {
            ...baseTexts.interface,
            ...(configTexts.interface || {})
        },
        errors: {
            ...baseTexts.errors,
            ...(configTexts.errors || {})
        },
        system: {
            ...baseTexts.system,
            ...(configTexts.system || {})
        },
        contacts: {
            ...baseTexts.contacts,
            ...(configTexts.contacts || {})
        },
        switcher: {
            ...baseTexts.switcher,
            ...(configTexts.switcher || {})
        },
        quickButtons: {
            ...baseTexts.quickButtons,
            ...(configTexts.quickButtons || {})
        },
        datetime: {
            ...baseTexts.datetime,
            ...(configTexts.datetime || {})
        },
        // 🔐 GDPR тексты
        gdpr: {
            ...baseTexts.gdpr,
            ...(configTexts.gdpr || {})
        }
    };
},
    
    // Получение быстрых кнопок
    // ✅ ИСПРАВЛЕННОЕ: Получение быстрых кнопок с проверкой
getQuickButtons() {
    try {
        const texts = this.getTexts();
        
        // Проверяем что texts существует и имеет quickButtons
        if (texts && texts.quickButtons && Array.isArray(texts.quickButtons)) {
            return texts.quickButtons;
        }
        
        // Fallback: пытаемся получить из исходных текстов конфигурации
        const originalTexts = this.texts[this.language] || this.texts.ru || {};
        if (originalTexts.quickButtons && Array.isArray(originalTexts.quickButtons)) {
            return originalTexts.quickButtons;
        }
        
        // Если ничего не найдено - возвращаем пустой массив
        console.warn('⚠️ Быстрые кнопки не найдены в конфигурации:', this.configId);
        return [];
        
    } catch (error) {
        console.error('❌ Ошибка получения быстрых кнопок:', error);
        return [];
    }
},
    
    // Получение настроек внешнего вида
    getAppearance() {
        return this.appearance;
    },
    
    // Получение настроек поведения
    getBehavior() {
        return this.behavior;
    },
    
    // Получение технических настроек
    getTechnical() {
        return this.technical;
    },
    
    // ✅ НОВОЕ: Получение настроек темы
    getTheme() {
        return this.theme || {};
    },
    
    // ✅ НОВОЕ: Получение эффективной темы (с учетом глобальных настроек)
    getEffectiveTheme() {
        const globalTheme = GlobalConfigSettings.themeSettings.globalTheme;
        const allowPerConfig = GlobalConfigSettings.themeSettings.allowPerConfigTheme;
        const configTheme = this.theme ? this.theme.mode : null;
        
        // Если глобальная тема установлена и не разрешены индивидуальные темы
        if (globalTheme !== 'auto' && !allowPerConfig) {
            return globalTheme;
        }
        
        // Если у конфигурации есть своя тема и это разрешено
        if (configTheme && allowPerConfig) {
            return configTheme;
        }
        
        // Иначе используем глобальную настройку
        return globalTheme || 'auto';
    },
    
    // Смена языка
setLanguage(lang) {
 
    if (this.texts && this.texts[lang]) {
        this.language = lang;
        
        // ✅ НОВОЕ: Синхронизируем с чатом если он существует
        if (window.webChat && window.webChat.currentLanguage !== lang) {
            window.webChat.currentLanguage = lang;
        }
        
        return true;
    }
    
    console.warn('⚠️ Язык не поддерживается конфигурацией:', lang);
    return false;
},
    
    // Обновление конфигурации
    updateConfig(newConfig) {
        Object.assign(this, newConfig);
    },
    
    // Проверка доступности в переключателе
    isAvailableInSwitcher() {
        const configName = this.configId || this.internalConfigName;
        const setting = GlobalConfigSettings.availableConfigs[configName];
        return setting && setting.enabled;
    },
    
    // Получение порядка в переключателе
    getSwitcherOrder() {
        const configName = this.configId || this.internalConfigName;
        const setting = GlobalConfigSettings.availableConfigs[configName];
        return setting ? setting.order : 999;
    }
};

// ===============================================
// МНОГОЯЗЫЧНЫЕ БАЗОВЫЕ ТЕКСТЫ ИНТЕРФЕЙСА (ПОЛНАЯ ВЕРСИЯ)
// ===============================================
const baseInterfaceTexts = {
    // 🇷🇺 РУССКИЙ ЯЗЫК
    ru: {
        interface: {
            minimize: "Свернуть",              
            expand: "Развернуть",              
            placeholder: "Введите сообщение...", 
            voiceTooltip: "Голосовое сообщение", 
            sendTooltip: "Отправить сообщение",  
            typingIndicator: "Отвечаю",
            fileTooltip: "Прикрепить файл",
            pasteImageHint: "Вставьте изображение (Ctrl+V)",
            fileUploading: "Отправляем файл...",
            fileTooLarge: "Файл слишком большой",
            fileTypeNotAllowed: "Тип файла не поддерживается",
            fileError: "Ошибка при обработке файла",
            // ✅ НОВЫЕ ПОДСКАЗКИ:
            selectLanguage: "Выбрать язык",
            switchSpecialist: "Сменить специалиста", 
            contactUs: "Связаться с нами",
            popoutTooltip: "Открыть в отдельном окне",
            selectedFile: "Выбранный файл:",
            removeFile: "Убрать файл"
        },

commands: {
            voiceEnabled: "🎤 Голосовые сообщения включены",
            voiceDisabled: "🔇 Голосовые сообщения отключены",
            //connectingManager: "🔄 Соединяю с менеджером...",
            //managerConnected: "✅ Менеджер подключен",
            historyCleared: "🗑️ История чата очищена",
            languageChanged: "🌍 Язык изменен на русский",
            configSwitched: "🔄 Переключено на",
            chatMinimized: "📌 Чат свернут",
            chatExpanded: "📖 Чат развернут"
    },

        errors: {
            connectionError: "❌ Ошибка подключения к серверу",
            fallbackMessage: "Извините, возникла техническая проблема. Попробуйте позже.",
            microphoneAccess: "❌ Нет доступа к микрофону",
            voiceProcessing: "❌ Ошибка обработки голосового сообщения",
            // 🆕 Новые типы ошибок:
            timeoutError: "⏱️ Превышено время ожидания ответа. Попробуйте еще раз.",
            networkError: "🌐 Ошибка сети. Проверьте подключение к интернету.",
            licenseError: "🔒 Ошибка лицензии. Обновите страницу.",
            authError: "🔒 Ошибка авторизации. Проверьте лицензию.",
            dataSizeError: "📦 Размер данных слишком большой.",
            badRequest: "⚠️ Некорректный запрос. Проверьте введенные данные.",
            serviceUnavailable: "🔍 Сервис недоступен. Обратитесь к администратору.",
            rateLimitError: "⏳ Слишком много запросов. Подождите немного.",
            serverError: "🔧 Ошибка сервера. Попробуйте позже.",
            popupBlockedError: "Не удалось открыть окно. Проверьте настройки блокировщика всплывающих окон.",
            dateError: "Ошибка даты"
        },

        system: {
            connecting: "Подключаюсь...",         
            voiceMessage: "🎤 Голосовое сообщение",
            switching: "Переключаюсь на",
            nowServing: "Теперь вас обслуживает",
            voiceMessageUnavailable: "🎤 Голосовое сообщение (недоступно)",
            voiceMessageExpired: "🎤 Голосовое сообщение (срок хранения истёк)",
            voiceMessageError: "🎤 Голосовое сообщение (ошибка загрузки)",
            videoMessage: "🎥 Видеосообщение",
            videoMessageError: "🎥 Видеосообщение (ошибка загрузки)",
            videoMessageUnavailable: "🎥 Видеосообщение (недоступно)"
        },

        contacts: {
            title: "Связаться с нами",
            tooltip: "Контакты"
        },

        switcher: {
            tooltip: "Сменить специалиста"
        },

        quickButtons: {
            toggleShow: "Показать быстрые команды",
            toggleHide: "Скрыть быстрые команды",
            title: "Быстрые команды"
        },

        datetime: {
            today: "Сегодня",
            yesterday: "Вчера",
            timeFormat: "24h",
            months: [
                "янв", "фев", "мар", "апр", "май", "июн",
                "июл", "авг", "сен", "окт", "ноя", "дек"
            ],
            monthsFull: [
                "января", "февраля", "марта", "апреля", "мая", "июня",
                "июля", "августа", "сентября", "октября", "ноября", "декабря"
            ],
            weekdays: [
                "Вс", "Пн", "Вт", "Ср", "Чт", "Пт", "Сб"
            ],
            weekdaysFull: [
                "воскресенье", "понедельник", "вторник", "среда",
                "четверг", "пятница", "суббота"
            ]
        },

        // 🆕 Новая секция для rate limiting
        rateLimiting: {
            tooManyMessages: "⏳ Слишком много сообщений. Максимум {max} сообщений в минуту."
        },

        // 🆕 Новая секция для fallback текстов
        fallback: {
            assistant: "Помощник",
            welcome: "Добро пожаловать!",
            defaultUserName: "Пользователь"
        },

        // 🔐 GDPR & Конфиденциальность
        gdpr: {
            // Consent Banner
            consentTitle: "🔒 Конфиденциальность и Cookies",
            consentText: "Мы используем этот чат для обработки ваших запросов. Ваши данные будут обработаны согласно нашей политике конфиденциальности.",
            consentTextAI: "Вы будете общаться с AI-ассистентом. Ваши сообщения обрабатываются с помощью искусственного интеллекта.",
            consentTextMonitoring: "Диалоги могут анализироваться для улучшения качества сервиса.",
            acceptButton: "Принять и продолжить",
            declineButton: "Отклонить",
            privacyLinkText: "Политика конфиденциальности",
            cookieLinkText: "Политика Cookies",
            termsLinkText: "Условия использования",

            // Standard mode UI
            continueWithoutAcceptButton: "Продолжить без принятия",
            standardModeNote: "Вы можете управлять настройками конфиденциальности в любое время через иконку 🔒.",
            dismissBannerTooltip: "Закрыть (настройки доступны позже)",

            // Pre-Chat Form
            formTitle: "Начать разговор",
            formSubtitle: "Пожалуйста, заполните форму перед началом чата",
            nameLabel: "Ваше имя",
            namePlaceholder: "Введите ваше имя",
            emailLabel: "Email",
            emailPlaceholder: "Введите ваш email",
            phoneLabel: "Телефон",
            phonePlaceholder: "Введите номер телефона",
            companyLabel: "Компания",
            companyPlaceholder: "Название компании",
            requiredFieldMark: "* - обязательное поле",
            gdprCheckboxText: "Я согласен на обработку моих персональных данных",
            startChatButton: "Начать чат",
            piiIndicator: "🔒 Персональные данные",

            // AI Disclosure
            aiDisclosureTitle: "AI Ассистент",
            aiDisclosureMessage: "🤖 Вы общаетесь с AI-ассистентом. Наш AI разработан для быстрой и эффективной помощи. Хотя мы стремимся к точности, иногда могут быть ошибки.",
            aiDisclosureBadge: "AI",

            // Privacy Controls Menu
            privacyMenuTitle: "🔐 Настройки конфиденциальности",
            viewDataButton: "👁️ Просмотреть мои данные",
            editDataButton: "✏️ Редактировать данные",
            exportDataButton: "📥 Экспортировать данные",
            deleteDataButton: "🗑️ Удалить все данные",
            revokeConsentButton: "⛔ Отозвать согласие",
            downloadTranscriptButton: "💬 Скачать переписку",
            clearHistoryButton: "🧹 Очистить историю",
            // Редактирование данных
            editFormTitle: "✏️ Редактирование данных",
            editFormSubtitle: "Обновите вашу персональную информацию",
            editingData: "Открываем редактор данных...",
            saveChangesButton: "💾 Сохранить изменения",
            cancelButton: "Отмена",
            dataUpdatedSuccess: "✅ Ваши данные успешно обновлены",

            // Confirmations
            deleteConfirmTitle: "Удаление данных",
            deleteConfirmText: "Вы уверены, что хотите удалить все ваши данные? Это действие необратимо.",
            revokeConfirmTitle: "Отзыв согласия",
            revokeConfirmText: "После отзыва согласия чат будет недоступен. Вы уверены?",
            confirmButton: "Да, подтверждаю",
            cancelButton: "Отмена",

            // Success Messages
            consentSavedSuccess: "✓ Согласие сохранено",
            dataDeletedSuccess: "✓ Ваши данные успешно удалены",
            consentRevokedSuccess: "✓ Согласие отозвано. Чат отключен.",
            dataExportedSuccess: "✓ Данные экспортированы",
            historyCleared: "✓ История чата очищена",
            formSubmittedSuccess: "✓ Форма отправлена",

            // Error Messages
            consentRequired: "Необходимо согласие для использования чата",
            formValidationError: "Пожалуйста, заполните все обязательные поля",
            webhookError: "Ошибка при обработке запроса. Попробуйте позже.",
            networkError: "Ошибка сети. Проверьте подключение к интернету.",
            emailRequired: "Email обязателен для этого действия",
            emailInvalid: "Введите корректный email адрес",

            // Declined State
            declinedTitle: "Согласие отклонено",
            declinedMessage: "Вы отклонили согласие на обработку данных. Чат недоступен.",
            declinedReconsiderButton: "Пересмотреть решение",
            inputDisabledPlaceholder: "Чат недоступен без согласия",

            // Data View Modal
            dataViewTitle: "Ваши данные",
            dataViewEmpty: "Нет сохраненных данных",
            dataViewLoading: "Загрузка данных...",
            dataViewError: "Не удалось загрузить данные",
            yourDataTitle: "Ваши данные",
            contactDataTitle: "Контактные данные",
            createdAtLabel: "Дата создания",
            consentDataTitle: "Согласие на обработку",
            consentGivenLabel: "Согласие дано",
            consentYes: "Да",
            consentNo: "Нет",
            consentDateLabel: "Дата согласия",
            expiresAtLabel: "Истекает",
            domainLabel: "Домен",
            chatHistoryTitle: "История чата",
            totalMessagesLabel: "Сообщений",
            noChatHistory: "История чата пуста",
            you: "Вы",
            assistant: "Ассистент",
            sessionInfoTitle: "Информация о сессии",
            closeButton: "Закрыть",

            // Security Indicators
            securedBadge: "Защищено",
            gdprBadge: "GDPR",
            encryptedBadge: "Зашифровано",
            aiBadge: "AI",

            // Data Retention Info
            retentionInfo: "Ваши данные хранятся в соответствии с нашей политикой конфиденциальности",
            retentionDaysText: "Срок хранения данных: {days} дней",

            // HTTPS Warning
            httpsWarning: "⚠️ Для безопасности рекомендуется использовать HTTPS соединение",

            // Processing
            processingRequest: "Обрабатываем запрос...",
            pleaseWait: "Пожалуйста, подождите...",

            // Advanced GDPR features
            confirmDeleteAllDataSecond: "Это ОКОНЧАТЕЛЬНОЕ подтверждение. Введите 'DELETE' для продолжения.",
            finalDeleteTitle: "⚠️ Финальное подтверждение",
            deleteInputPlaceholder: "Введите DELETE",
            deleteInputError: "Введите DELETE для подтверждения",
            deletionCancelled: "Удаление отменено",
            deletingIn: "Удаление через {seconds} секунд...",
            cooldownActive: "Пожалуйста, подождите {hours} час(ов) перед повторным запросом на удаление.",
            exportLimitReached: "Достигнут лимит экспортов ({max} в день). Попробуйте завтра.",
            exportingData: "Подготовка экспорта данных...",
            requestingData: "Запрос ваших данных...",
            dataExported: "Данные успешно экспортированы",
            allDataDeleted: "Все данные удалены",
            confirmDeleteHistory: "Вы уверены, что хотите удалить историю чата?",
            confirmDeleteAllData: "Вы уверены, что хотите удалить ВСЕ ваши данные? Это действие необратимо.",
            historyDeleted: "История чата удалена",
            confirmRevokeConsent: "Вы уверены, что хотите отозвать согласие? Чат станет недоступен.",
            consentRevoked: "Согласие отозвано",
            consentDeclined: "Согласие отклонено",
            consentActiveLabel: "Согласие активно",
            revokedAtLabel: "Дата отзыва",
            revokeReasonLabel: "Причина отзыва",

            // Заголовки диалогов подтверждения
            confirmTitle: "Подтверждение",
            deleteHistoryTitle: "Удаление истории",
            revokeConsentTitle: "Отзыв согласия",
            deleteAllDataTitle: "Удаление всех данных",
            deleteHistoryButton: "🗑️ Удалить историю чата",
            deleteAllDataButton: "🗑️ Удалить все мои данные"
        }
    },

    // 🇺🇸 АНГЛИЙСКИЙ ЯЗЫК
    en: {
        interface: {
            minimize: "Minimize",              
            expand: "Expand",              
            placeholder: "Type a message...", 
            voiceTooltip: "Voice message", 
            sendTooltip: "Send message",  
            typingIndicator: "Typing",
            fileTooltip: "Attach file",
            pasteImageHint: "Paste image (Ctrl+V)",
            fileUploading: "Uploading file...",
            fileTooLarge: "File too large",
            fileTypeNotAllowed: "File type not supported",
            fileError: "File processing error",
            // ✅ НОВЫЕ ПОДСКАЗКИ:
            selectLanguage: "Select language",
            switchSpecialist: "Switch specialist",
            contactUs: "Contact us",
            popoutTooltip: "Open in separate window",
            selectedFile: "Selected file:",
            removeFile: "Remove file"
        },

commands: {
            voiceEnabled: "🎤 Voice messages enabled",
            voiceDisabled: "🔇 Voice messages disabled",
            //connectingManager: "🔄 Connecting to manager...",
            //managerConnected: "✅ Manager connected",
            historyCleared: "🗑️ Chat history cleared",
            languageChanged: "🌍 Language changed to English",
            configSwitched: "🔄 Switched to",
            chatMinimized: "📌 Chat minimized",
            chatExpanded: "📖 Chat expanded"
    
    },

        errors: {
            connectionError: "❌ Server connection error",
            fallbackMessage: "Sorry, there was a technical issue. Please try again later.",
            microphoneAccess: "❌ No microphone access",
            voiceProcessing: "❌ Voice processing error",
            // 🆕 New error types:
            timeoutError: "⏱️ Response timeout exceeded. Please try again.",
            networkError: "🌐 Network error. Please check your internet connection.",
            licenseError: "🔒 License error. Please refresh the page.",
            authError: "🔒 Authorization error. Please check your license.",
            dataSizeError: "📦 Data size is too large.",
            badRequest: "⚠️ Invalid request. Please check your input.",
            serviceUnavailable: "🔍 Service unavailable. Contact administrator.",
            rateLimitError: "⏳ Too many requests. Please wait.",
            serverError: "🔧 Server error. Please try again later.",
            popupBlockedError: "Failed to open window. Please check popup blocker settings.",
            dateError: "Date error"
        },

        system: {
            connecting: "Connecting...",         
            voiceMessage: "🎤 Voice message",
            switching: "Switching to",
            nowServing: "Now serving you",
            voiceMessageUnavailable: "🎤 Voice message (unavailable)",
            voiceMessageExpired: "🎤 Voice message (expired)",
            voiceMessageError: "🎤 Voice message (loading error)",
            videoMessage: "🎥 Video message",
            videoMessageError: "🎥 Video message (loading error)",
            videoMessageUnavailable: "🎥 Video message (unavailable)"
        },

        contacts: {
            title: "Contact us",
            tooltip: "Contacts"
        },

        switcher: {
            tooltip: "Switch specialist"
        },

        quickButtons: {
            toggleShow: "Show quick actions",
            toggleHide: "Hide quick actions", 
            title: "Quick actions"
        },

        datetime: {
            today: "Today",
            yesterday: "Yesterday",
            timeFormat: "12h",
            months: [
                "Jan", "Feb", "Mar", "Apr", "May", "Jun",
                "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
            ],
            monthsFull: [
                "January", "February", "March", "April", "May", "June",
                "July", "August", "September", "October", "November", "December"
            ],
            weekdays: [
                "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"
            ],
            weekdaysFull: [
                "Sunday", "Monday", "Tuesday", "Wednesday",
                "Thursday", "Friday", "Saturday"
            ],
            ampm: {
                am: "AM",
                pm: "PM"
            }
        },

        // 🆕 New section for rate limiting
        rateLimiting: {
            tooManyMessages: "⏳ Too many messages. Maximum {max} messages per minute."
        },

        // 🆕 New section for fallback texts
        fallback: {
            assistant: "Assistant",
            welcome: "Welcome!",
            defaultUserName: "User"
        },

        // 🔐 GDPR & Privacy
        gdpr: {
            // Consent Banner
            consentTitle: "🔒 Privacy & Cookies",
            consentText: "We use this chat to process your requests. Your data will be processed according to our privacy policy.",
            consentTextAI: "You will be chatting with an AI assistant. Your messages are processed using artificial intelligence.",
            consentTextMonitoring: "Conversations may be analyzed to improve service quality.",
            acceptButton: "Accept & Continue",
            declineButton: "Decline",
            privacyLinkText: "Privacy Policy",
            cookieLinkText: "Cookie Policy",
            termsLinkText: "Terms of Service",

            // Standard mode UI
            continueWithoutAcceptButton: "Continue without accepting",
            standardModeNote: "You can manage your privacy preferences at any time via the 🔒 icon.",
            dismissBannerTooltip: "Dismiss (you can manage preferences later)",

            // Pre-Chat Form
            formTitle: "Start a Conversation",
            formSubtitle: "Please fill out the form before starting the chat",
            nameLabel: "Your Name",
            namePlaceholder: "Enter your name",
            emailLabel: "Email",
            emailPlaceholder: "Enter your email",
            phoneLabel: "Phone",
            phonePlaceholder: "Enter your phone number",
            companyLabel: "Company",
            companyPlaceholder: "Company name",
            requiredFieldMark: "* - required field",
            gdprCheckboxText: "I agree to the processing of my personal data",
            startChatButton: "Start Chat",
            piiIndicator: "🔒 Personal data",

            // AI Disclosure
            aiDisclosureTitle: "AI Assistant",
            aiDisclosureMessage: "🤖 You are chatting with an AI assistant. Our AI is designed for fast and efficient assistance. While we strive for accuracy, errors may sometimes occur.",
            aiDisclosureBadge: "AI",

            // Privacy Controls Menu
            privacyMenuTitle: "🔐 Privacy Settings",
            viewDataButton: "👁️ View My Data",
            editDataButton: "✏️ Edit Data",
            exportDataButton: "📥 Export Data",
            deleteDataButton: "🗑️ Delete All Data",
            revokeConsentButton: "⛔ Revoke Consent",
            downloadTranscriptButton: "💬 Download Transcript",
            clearHistoryButton: "🧹 Clear History",
            // Edit Data
            editFormTitle: "✏️ Edit Your Data",
            editFormSubtitle: "Update your personal information",
            editingData: "Opening data editor...",
            saveChangesButton: "💾 Save Changes",
            cancelButton: "Cancel",
            dataUpdatedSuccess: "✅ Your data has been updated successfully",

            // Confirmations
            deleteConfirmTitle: "Delete Data",
            deleteConfirmText: "Are you sure you want to delete all your data? This action cannot be undone.",
            revokeConfirmTitle: "Revoke Consent",
            revokeConfirmText: "After revoking consent, the chat will be unavailable. Are you sure?",
            confirmButton: "Yes, Confirm",
            cancelButton: "Cancel",

            // Success Messages
            consentSavedSuccess: "✓ Consent saved",
            dataDeletedSuccess: "✓ Your data has been successfully deleted",
            consentRevokedSuccess: "✓ Consent revoked. Chat disabled.",
            dataExportedSuccess: "✓ Data exported",
            historyCleared: "✓ Chat history cleared",
            formSubmittedSuccess: "✓ Form submitted",

            // Error Messages
            consentRequired: "Consent is required to use the chat",
            formValidationError: "Please fill in all required fields",
            webhookError: "Error processing request. Please try again later.",
            networkError: "Network error. Please check your internet connection.",
            emailRequired: "Email is required for this action",
            emailInvalid: "Please enter a valid email address",

            // Declined State
            declinedTitle: "Consent Declined",
            declinedMessage: "You have declined consent to data processing. Chat is unavailable.",
            declinedReconsiderButton: "Reconsider",
            inputDisabledPlaceholder: "Chat is unavailable without consent",

            // Data View Modal
            dataViewTitle: "Your Data",
            dataViewEmpty: "No saved data",
            dataViewLoading: "Loading data...",
            dataViewError: "Failed to load data",
            yourDataTitle: "Your Data",
            contactDataTitle: "Contact Information",
            createdAtLabel: "Created",
            consentDataTitle: "Consent Information",
            consentGivenLabel: "Consent given",
            consentYes: "Yes",
            consentNo: "No",
            consentDateLabel: "Consent date",
            expiresAtLabel: "Expires",
            domainLabel: "Domain",
            chatHistoryTitle: "Chat History",
            totalMessagesLabel: "Messages",
            noChatHistory: "Chat history is empty",
            you: "You",
            assistant: "Assistant",
            sessionInfoTitle: "Session Information",
            closeButton: "Close",

            // Security Indicators
            securedBadge: "Secured",
            gdprBadge: "GDPR",
            encryptedBadge: "Encrypted",
            aiBadge: "AI",

            // Data Retention Info
            retentionInfo: "Your data is stored in accordance with our privacy policy",
            retentionDaysText: "Data retention period: {days} days",

            // HTTPS Warning
            httpsWarning: "⚠️ For security, it is recommended to use an HTTPS connection",

            // Processing
            processingRequest: "Processing request...",
            pleaseWait: "Please wait...",

            // Advanced GDPR features
            confirmDeleteAllDataSecond: "This is your FINAL confirmation. Type 'DELETE' to proceed.",
            finalDeleteTitle: "⚠️ Final Confirmation",
            deleteInputPlaceholder: "Type DELETE",
            deleteInputError: "Please type DELETE to confirm",
            deletionCancelled: "Deletion cancelled",
            deletingIn: "Deleting in {seconds} seconds...",
            cooldownActive: "Please wait {hours} hour(s) before requesting deletion again.",
            exportLimitReached: "Export limit reached ({max} per day). Try again tomorrow.",
            exportingData: "Preparing data export...",
            requestingData: "Requesting your data...",
            dataExported: "Data exported successfully",
            allDataDeleted: "All data deleted",
            confirmDeleteHistory: "Are you sure you want to delete your chat history?",
            confirmDeleteAllData: "Are you sure you want to delete ALL your data? This action cannot be undone.",
            historyDeleted: "Chat history deleted",
            confirmRevokeConsent: "Are you sure you want to revoke your consent? Chat will become unavailable.",
            consentRevoked: "Consent revoked",
            consentDeclined: "Consent declined",
            consentActiveLabel: "Consent active",
            revokedAtLabel: "Revoked at",
            revokeReasonLabel: "Revoke reason",

            // Confirmation dialog titles
            confirmTitle: "Confirmation",
            deleteHistoryTitle: "Delete History",
            revokeConsentTitle: "Revoke Consent",
            deleteAllDataTitle: "Delete All Data",

            deleteHistoryButton: "🗑️ Delete Chat History",
            deleteAllDataButton: "🗑️ Delete All My Data"
        }
    },

    // 🇪🇸 ИСПАНСКИЙ ЯЗЫК
    es: {
        interface: {
            minimize: "Minimizar",              
            expand: "Expandir",              
            placeholder: "Escribe un mensaje...", 
            voiceTooltip: "Mensaje de voz", 
            sendTooltip: "Enviar mensaje",  
            typingIndicator: "Escribiendo",
            fileTooltip: "Adjuntar archivo",
            pasteImageHint: "Pegar imagen (Ctrl+V)",
            fileUploading: "Subiendo archivo...",
            fileTooLarge: "Archivo demasiado grande",
            fileTypeNotAllowed: "Tipo de archivo no compatible",
            fileError: "Error al procesar archivo",
            selectLanguage: "Seleccionar idioma",
            switchSpecialist: "Cambiar especialista",
            contactUs: "Contáctanos",
            popoutTooltip: "Abrir en una ventana separada",
            selectedFile: "Archivo seleccionado:",
            removeFile: "Quitar archivo"
        },

commands: {
            voiceEnabled: "🎤 Mensajes de voz activados",
            voiceDisabled: "🔇 Mensajes de voz desactivados",
            //connectingManager: "🔄 Conectando con el gerente...",
           // managerConnected: "✅ Gerente conectado",
            historyCleared: "🗑️ Historial del chat borrado",
            languageChanged: "🌍 Idioma cambiado a español",
            configSwitched: "🔄 Cambiado a",
            chatMinimized: "📌 Chat minimizado",
            chatExpanded: "📖 Chat expandido"
        
    },

        errors: {
            connectionError: "❌ Error de conexión al servidor",
            fallbackMessage: "Lo siento, hubo un problema técnico. Inténtalo más tarde.",
            microphoneAccess: "❌ Sin acceso al micrófono",
            voiceProcessing: "❌ Error al procesar el mensaje de voz",
            // 🆕 Nuevos tipos de errores:
            timeoutError: "⏱️ Tiempo de espera excedido. Inténtalo de nuevo.",
            networkError: "🌐 Error de red. Verifique su conexión a internet.",
            licenseError: "🔒 Error de licencia. Actualice la página.",
            authError: "🔒 Error de autorización. Verifique su licencia.",
            dataSizeError: "📦 El tamaño de los datos es demasiado grande.",
            badRequest: "⚠️ Solicitud inválida. Verifique su entrada.",
            serviceUnavailable: "🔍 Servicio no disponible. Contacte al administrador.",
            rateLimitError: "⏳ Demasiadas solicitudes. Por favor espere.",
            serverError: "🔧 Error del servidor. Inténtalo más tarde.",
            popupBlockedError: "No se pudo abrir la ventana. Verifique la configuración del bloqueador de ventanas emergentes.",
            dateError: "Error de fecha"
        },

        system: {
            connecting: "Conectando...",         
            voiceMessage: "🎤 Mensaje de voz",
            switching: "Cambiando a",
            nowServing: "Ahora te atiende",
            voiceMessageUnavailable: "🎤 Mensaje de voz (no disponible)",
            voiceMessageExpired: "🎤 Mensaje de voz (expirado)",
            voiceMessageError: "🎤 Mensaje de voz (error de carga)",
            videoMessage: "🎥 Mensaje de vídeo",
            videoMessageError: "🎥 Mensaje de vídeo (error de carga)",
            videoMessageUnavailable: "🎥 Mensaje de vídeo (no disponible)"
        },

        contacts: {
            title: "Contáctanos",
            tooltip: "Contactos"
        },

        switcher: {
            tooltip: "Cambiar especialista"
        },

        quickButtons: {
            toggleShow: "Mostrar acciones rápidas",
            toggleHide: "Ocultar acciones rápidas",
            title: "Acciones rápidas"
        },

        datetime: {
            today: "Hoy",
            yesterday: "Ayer",
            timeFormat: "24h",
            months: [
                "ene", "feb", "mar", "abr", "may", "jun",
                "jul", "ago", "sep", "oct", "nov", "dic"
            ],
            monthsFull: [
                "enero", "febrero", "marzo", "abril", "mayo", "junio",
                "julio", "agosto", "septiembre", "octubre", "noviembre", "diciembre"
            ],
            weekdays: [
                "Dom", "Lun", "Mar", "Mié", "Jue", "Vie", "Sáb"
            ],
            weekdaysFull: [
                "domingo", "lunes", "martes", "miércoles",
                "jueves", "viernes", "sábado"
            ]
        },

        // 🆕 Nueva sección para limitación de velocidad
        rateLimiting: {
            tooManyMessages: "⏳ Demasiados mensajes. Máximo {max} mensajes por minuto."
        },

        // 🆕 Nueva sección para textos de respaldo
        fallback: {
            assistant: "Asistente",
            welcome: "¡Bienvenido!",
            defaultUserName: "Usuario"
        },

        // 🔐 GDPR y Privacidad
        gdpr: {
            // Consent Banner
            consentTitle: "🔒 Privacidad y Cookies",
            consentText: "Utilizamos este chat para procesar sus solicitudes. Sus datos serán procesados de acuerdo con nuestra política de privacidad.",
            consentTextAI: "Estará chateando con un asistente de IA. Sus mensajes se procesan mediante inteligencia artificial.",
            consentTextMonitoring: "Las conversaciones pueden ser analizadas para mejorar la calidad del servicio.",
            acceptButton: "Aceptar y Continuar",
            declineButton: "Rechazar",
            privacyLinkText: "Política de Privacidad",
            cookieLinkText: "Política de Cookies",
            termsLinkText: "Términos de Servicio",

            // Standard mode UI
            continueWithoutAcceptButton: "Continuar sin aceptar",
            standardModeNote: "Puede gestionar sus preferencias de privacidad en cualquier momento a través del icono 🔒.",
            dismissBannerTooltip: "Cerrar (puede gestionar preferencias después)",

            // Pre-Chat Form
            formTitle: "Iniciar Conversación",
            formSubtitle: "Por favor complete el formulario antes de iniciar el chat",
            nameLabel: "Su Nombre",
            namePlaceholder: "Ingrese su nombre",
            emailLabel: "Correo Electrónico",
            emailPlaceholder: "Ingrese su correo electrónico",
            phoneLabel: "Teléfono",
            phonePlaceholder: "Ingrese su número de teléfono",
            companyLabel: "Empresa",
            companyPlaceholder: "Nombre de la empresa",
            requiredFieldMark: "* - campo obligatorio",
            gdprCheckboxText: "Acepto el procesamiento de mis datos personales",
            startChatButton: "Iniciar Chat",
            piiIndicator: "🔒 Datos personales",

            // AI Disclosure
            aiDisclosureTitle: "Asistente de IA",
            aiDisclosureMessage: "🤖 Está chateando con un asistente de IA. Nuestra IA está diseñada para una asistencia rápida y eficiente. Aunque nos esforzamos por la precisión, a veces pueden ocurrir errores.",
            aiDisclosureBadge: "IA",

            // Privacy Controls Menu
            privacyMenuTitle: "🔐 Configuración de Privacidad",
            viewDataButton: "👁️ Ver Mis Datos",
            editDataButton: "✏️ Editar Datos",
            exportDataButton: "📥 Exportar Datos",
            deleteDataButton: "🗑️ Eliminar Todos los Datos",
            revokeConsentButton: "⛔ Revocar Consentimiento",
            downloadTranscriptButton: "💬 Descargar Conversación",
            clearHistoryButton: "🧹 Limpiar Historial",
            // Editar Datos
            editFormTitle: "✏️ Editar Tus Datos",
            editFormSubtitle: "Actualiza tu información personal",
            editingData: "Abriendo editor de datos...",
            saveChangesButton: "💾 Guardar Cambios",
            cancelButton: "Cancelar",
            dataUpdatedSuccess: "✅ Tus datos han sido actualizados correctamente",

            // Confirmations
            deleteConfirmTitle: "Eliminar Datos",
            deleteConfirmText: "¿Está seguro de que desea eliminar todos sus datos? Esta acción no se puede deshacer.",
            revokeConfirmTitle: "Revocar Consentimiento",
            revokeConfirmText: "Después de revocar el consentimiento, el chat no estará disponible. ¿Está seguro?",
            confirmButton: "Sí, Confirmar",
            cancelButton: "Cancelar",

            // Success Messages
            consentSavedSuccess: "✓ Consentimiento guardado",
            dataDeletedSuccess: "✓ Sus datos han sido eliminados exitosamente",
            consentRevokedSuccess: "✓ Consentimiento revocado. Chat deshabilitado.",
            dataExportedSuccess: "✓ Datos exportados",
            historyCleared: "✓ Historial de chat limpiado",
            formSubmittedSuccess: "✓ Formulario enviado",

            // Error Messages
            consentRequired: "Se requiere consentimiento para usar el chat",
            formValidationError: "Por favor complete todos los campos obligatorios",
            webhookError: "Error al procesar la solicitud. Por favor intente más tarde.",
            networkError: "Error de red. Por favor verifique su conexión a internet.",
            emailRequired: "El correo electrónico es requerido para esta acción",
            emailInvalid: "Por favor ingrese una dirección de correo electrónico válida",

            // Declined State
            declinedTitle: "Consentimiento Rechazado",
            declinedMessage: "Ha rechazado el consentimiento para el procesamiento de datos. El chat no está disponible.",
            declinedReconsiderButton: "Reconsiderar",
            inputDisabledPlaceholder: "Chat no disponible sin consentimiento",

            // Data View Modal
            dataViewTitle: "Sus Datos",
            dataViewEmpty: "No hay datos guardados",
            dataViewLoading: "Cargando datos...",
            dataViewError: "No se pudieron cargar los datos",
            yourDataTitle: "Sus Datos",
            contactDataTitle: "Información de Contacto",
            createdAtLabel: "Fecha de creación",
            consentDataTitle: "Información de Consentimiento",
            consentGivenLabel: "Consentimiento dado",
            consentYes: "Sí",
            consentNo: "No",
            consentDateLabel: "Fecha del consentimiento",
            expiresAtLabel: "Expira",
            domainLabel: "Dominio",
            chatHistoryTitle: "Historial del Chat",
            totalMessagesLabel: "Mensajes",
            noChatHistory: "El historial del chat está vacío",
            you: "Tú",
            assistant: "Asistente",
            sessionInfoTitle: "Información de Sesión",
            closeButton: "Cerrar",

            // Security Indicators
            securedBadge: "Seguro",
            gdprBadge: "GDPR",
            encryptedBadge: "Cifrado",
            aiBadge: "IA",

            // Data Retention Info
            retentionInfo: "Sus datos se almacenan de acuerdo con nuestra política de privacidad",
            retentionDaysText: "Período de retención de datos: {days} días",

            // HTTPS Warning
            httpsWarning: "⚠️ Por seguridad, se recomienda usar una conexión HTTPS",

            // Processing
            processingRequest: "Procesando solicitud...",
            pleaseWait: "Por favor espere...",

            // Advanced GDPR features
            confirmDeleteAllDataSecond: "Esta es su confirmación FINAL. Escriba 'DELETE' para continuar.",
            finalDeleteTitle: "⚠️ Confirmación Final",
            deleteInputPlaceholder: "Escriba DELETE",
            deleteInputError: "Por favor escriba DELETE para confirmar",
            deletionCancelled: "Eliminación cancelada",
            deletingIn: "Eliminando en {seconds} segundos...",
            cooldownActive: "Por favor espere {hours} hora(s) antes de solicitar la eliminación nuevamente.",
            exportLimitReached: "Límite de exportación alcanzado ({max} por día). Intente mañana.",
            exportingData: "Preparando exportación de datos...",
            requestingData: "Solicitando tus datos...",
            dataExported: "Datos exportados exitosamente",
            allDataDeleted: "Todos los datos eliminados",
            confirmDeleteHistory: "¿Está seguro de que desea eliminar el historial del chat?",
            confirmDeleteAllData: "¿Está seguro de que desea eliminar TODOS sus datos? Esta acción no se puede deshacer.",
            historyDeleted: "Historial del chat eliminado",
            confirmRevokeConsent: "¿Está seguro de que desea revocar su consentimiento? El chat dejará de estar disponible.",
            consentRevoked: "Consentimiento revocado",
            consentDeclined: "Consentimiento rechazado",
            consentActiveLabel: "Consentimiento activo",
            revokedAtLabel: "Fecha de revocación",
            revokeReasonLabel: "Motivo de revocación",
            confirmTitle: "Confirmación",
            deleteHistoryTitle: "Eliminar Historial",
            revokeConsentTitle: "Revocar Consentimiento",
            deleteAllDataTitle: "Eliminar Todos los Datos",
            deleteHistoryButton: "🗑️ Eliminar Historial del Chat",
            deleteAllDataButton: "🗑️ Eliminar Todos Mis Datos"
        }
    },

    // 🇫🇷 ФРАНЦУЗСКИЙ ЯЗЫК
    fr: {
        interface: {
            minimize: "Réduire",              
            expand: "Développer",              
            placeholder: "Tapez un message...", 
            voiceTooltip: "Message vocal", 
            sendTooltip: "Envoyer le message",  
            typingIndicator: "Écriture",
            fileTooltip: "Joindre un fichier",
            pasteImageHint: "Coller une image (Ctrl+V)",
            fileUploading: "Envoi du fichier...",
            fileTooLarge: "Fichier trop volumineux",
            fileTypeNotAllowed: "Type de fichier non pris en charge",
            fileError: "Erreur de traitement du fichier",
            selectLanguage: "Sélectionner la langue",
            switchSpecialist: "Changer de spécialiste",
            contactUs: "Nous contacter",
            popoutTooltip: "Ouvrir dans une fenêtre séparée",
            selectedFile: "Fichier sélectionné:",
            removeFile: "Supprimer le fichier"
        },

commands: {
            voiceEnabled: "🎤 Messages vocaux activés",
            voiceDisabled: "🔇 Messages vocaux désactivés",
            //connectingManager: "🔄 Connexion au manager...",
            //managerConnected: "✅ Manager connecté",
            historyCleared: "🗑️ Historique du chat effacé",
            languageChanged: "🌍 Langue changée en français",
            configSwitched: "🔄 Basculé vers",
            chatMinimized: "📌 Chat réduit",
            chatExpanded: "📖 Chat développé"
    
    },

        errors: {
            connectionError: "❌ Erreur de connexion au serveur",
            fallbackMessage: "Désolé, il y a eu un problème technique. Veuillez réessayer plus tard.",
            microphoneAccess: "❌ Pas d'accès au microphone",
            voiceProcessing: "❌ Erreur de traitement du message vocal",
            // 🆕 Nouveaux types d'erreurs:
            timeoutError: "⏱️ Délai d'attente dépassé. Veuillez réessayer.",
            networkError: "🌐 Erreur réseau. Vérifiez votre connexion internet.",
            licenseError: "🔒 Erreur de licence. Veuillez actualiser la page.",
            authError: "🔒 Erreur d'autorisation. Vérifiez votre licence.",
            dataSizeError: "📦 La taille des données est trop importante.",
            badRequest: "⚠️ Demande invalide. Vérifiez votre saisie.",
            serviceUnavailable: "🔍 Service indisponible. Contactez l'administrateur.",
            rateLimitError: "⏳ Trop de demandes. Veuillez patienter.",
            serverError: "🔧 Erreur du serveur. Veuillez réessayer plus tard.",
            popupBlockedError: "Impossible d'ouvrir la fenêtre. Vérifiez les paramètres du bloqueur de fenêtres contextuelles.",
            dateError: "Erreur de date"
        },

        system: {
            connecting: "Connexion...",         
            voiceMessage: "🎤 Message vocal",
            switching: "Passage à",
            nowServing: "Vous sert maintenant",
            voiceMessageUnavailable: "🎤 Message vocal (indisponible)",
            voiceMessageExpired: "🎤 Message vocal (expiré)",
            voiceMessageError: "🎤 Message vocal (erreur de chargement)",
            videoMessage: "🎥 Message vidéo",
            videoMessageError: "🎥 Message vidéo (erreur de chargement)",
            videoMessageUnavailable: "🎥 Message vidéo (indisponible)"
        },

        contacts: {
            title: "Nous contacter",
            tooltip: "Contacts"
        },

        switcher: {
            tooltip: "Changer de spécialiste"
        },

        quickButtons: {
            toggleShow: "Afficher les actions rapides",
            toggleHide: "Masquer les actions rapides",
            title: "Actions rapides"
        },

        datetime: {
            today: "Aujourd'hui",
            yesterday: "Hier",
            timeFormat: "24h",
            months: [
                "jan", "fév", "mar", "avr", "mai", "jun",
                "jul", "aoû", "sep", "oct", "nov", "déc"
            ],
            monthsFull: [
                "janvier", "février", "mars", "avril", "mai", "juin",
                "juillet", "août", "septembre", "octobre", "novembre", "décembre"
            ],
            weekdays: [
                "Dim", "Lun", "Mar", "Mer", "Jeu", "Ven", "Sam"
            ],
            weekdaysFull: [
                "dimanche", "lundi", "mardi", "mercredi",
                "jeudi", "vendredi", "samedi"
            ]
        },

        // 🆕 Nouvelle section pour la limitation de débit
        rateLimiting: {
            tooManyMessages: "⏳ Trop de messages. Maximum {max} messages par minute."
        },

        // 🆕 Nouvelle section pour les textes de secours
        fallback: {
            assistant: "Assistant",
            welcome: "Bienvenue !",
            defaultUserName: "Utilisateur"
        },

        // 🔐 RGPD et Confidentialité
        gdpr: {
            // Consent Banner
            consentTitle: "🔒 Confidentialité et Cookies",
            consentText: "Nous utilisons ce chat pour traiter vos demandes. Vos données seront traitées conformément à notre politique de confidentialité.",
            consentTextAI: "Vous allez discuter avec un assistant IA. Vos messages sont traités par intelligence artificielle.",
            consentTextMonitoring: "Les conversations peuvent être analysées pour améliorer la qualité du service.",
            acceptButton: "Accepter et Continuer",
            declineButton: "Refuser",
            privacyLinkText: "Politique de Confidentialité",
            cookieLinkText: "Politique des Cookies",
            termsLinkText: "Conditions d'Utilisation",

            // Standard mode UI
            continueWithoutAcceptButton: "Continuer sans accepter",
            standardModeNote: "Vous pouvez gérer vos préférences de confidentialité à tout moment via l'icône 🔒.",
            dismissBannerTooltip: "Fermer (gérer les préférences plus tard)",

            // Pre-Chat Form
            formTitle: "Démarrer une Conversation",
            formSubtitle: "Veuillez remplir le formulaire avant de commencer le chat",
            nameLabel: "Votre Nom",
            namePlaceholder: "Entrez votre nom",
            emailLabel: "Email",
            emailPlaceholder: "Entrez votre email",
            phoneLabel: "Téléphone",
            phonePlaceholder: "Entrez votre numéro de téléphone",
            companyLabel: "Entreprise",
            companyPlaceholder: "Nom de l'entreprise",
            requiredFieldMark: "* - champ obligatoire",
            gdprCheckboxText: "J'accepte le traitement de mes données personnelles",
            startChatButton: "Démarrer le Chat",
            piiIndicator: "🔒 Données personnelles",

            // AI Disclosure
            aiDisclosureTitle: "Assistant IA",
            aiDisclosureMessage: "🤖 Vous discutez avec un assistant IA. Notre IA est conçue pour une assistance rapide et efficace. Bien que nous visions la précision, des erreurs peuvent parfois survenir.",
            aiDisclosureBadge: "IA",

            // Privacy Controls Menu
            privacyMenuTitle: "🔐 Paramètres de Confidentialité",
            viewDataButton: "👁️ Voir Mes Données",
            editDataButton: "✏️ Modifier les Données",
            exportDataButton: "📥 Exporter les Données",
            deleteDataButton: "🗑️ Supprimer Toutes les Données",
            revokeConsentButton: "⛔ Révoquer le Consentement",
            downloadTranscriptButton: "💬 Télécharger la Conversation",
            clearHistoryButton: "🧹 Effacer l'Historique",
            // Modifier les Données
            editFormTitle: "✏️ Modifier Vos Données",
            editFormSubtitle: "Mettez à jour vos informations personnelles",
            editingData: "Ouverture de l'éditeur de données...",
            saveChangesButton: "💾 Enregistrer les Modifications",
            cancelButton: "Annuler",
            dataUpdatedSuccess: "✅ Vos données ont été mises à jour avec succès",

            // Confirmations
            deleteConfirmTitle: "Supprimer les Données",
            deleteConfirmText: "Êtes-vous sûr de vouloir supprimer toutes vos données ? Cette action est irréversible.",
            revokeConfirmTitle: "Révoquer le Consentement",
            revokeConfirmText: "Après révocation du consentement, le chat sera indisponible. Êtes-vous sûr ?",
            confirmButton: "Oui, Confirmer",
            cancelButton: "Annuler",

            // Success Messages
            consentSavedSuccess: "✓ Consentement enregistré",
            dataDeletedSuccess: "✓ Vos données ont été supprimées avec succès",
            consentRevokedSuccess: "✓ Consentement révoqué. Chat désactivé.",
            dataExportedSuccess: "✓ Données exportées",
            historyCleared: "✓ Historique du chat effacé",
            formSubmittedSuccess: "✓ Formulaire envoyé",

            // Error Messages
            consentRequired: "Le consentement est requis pour utiliser le chat",
            formValidationError: "Veuillez remplir tous les champs obligatoires",
            webhookError: "Erreur lors du traitement de la demande. Veuillez réessayer plus tard.",
            networkError: "Erreur réseau. Veuillez vérifier votre connexion internet.",
            emailRequired: "L'email est requis pour cette action",
            emailInvalid: "Veuillez entrer une adresse email valide",

            // Declined State
            declinedTitle: "Consentement Refusé",
            declinedMessage: "Vous avez refusé le consentement au traitement des données. Le chat n'est pas disponible.",
            declinedReconsiderButton: "Reconsidérer",
            inputDisabledPlaceholder: "Chat indisponible sans consentement",

            // Data View Modal
            dataViewTitle: "Vos Données",
            dataViewEmpty: "Aucune donnée enregistrée",
            dataViewLoading: "Chargement des données...",
            dataViewError: "Impossible de charger les données",
            yourDataTitle: "Vos Données",
            contactDataTitle: "Coordonnées",
            createdAtLabel: "Date de création",
            consentDataTitle: "Informations sur le consentement",
            consentGivenLabel: "Consentement donné",
            consentYes: "Oui",
            consentNo: "Non",
            consentDateLabel: "Date du consentement",
            expiresAtLabel: "Expire",
            domainLabel: "Domaine",
            chatHistoryTitle: "Historique du chat",
            totalMessagesLabel: "Messages",
            noChatHistory: "L'historique du chat est vide",
            you: "Vous",
            assistant: "Assistant",
            sessionInfoTitle: "Informations de session",
            closeButton: "Fermer",

            // Security Indicators
            securedBadge: "Sécurisé",
            gdprBadge: "RGPD",
            encryptedBadge: "Chiffré",
            aiBadge: "IA",

            // Data Retention Info
            retentionInfo: "Vos données sont stockées conformément à notre politique de confidentialité",
            retentionDaysText: "Période de conservation des données : {days} jours",

            // HTTPS Warning
            httpsWarning: "⚠️ Pour la sécurité, il est recommandé d'utiliser une connexion HTTPS",

            // Processing
            processingRequest: "Traitement de la demande...",
            pleaseWait: "Veuillez patienter...",

            // Advanced GDPR features
            confirmDeleteAllDataSecond: "Ceci est votre confirmation FINALE. Tapez 'DELETE' pour continuer.",
            finalDeleteTitle: "⚠️ Confirmation Finale",
            deleteInputPlaceholder: "Tapez DELETE",
            deleteInputError: "Veuillez taper DELETE pour confirmer",
            deletionCancelled: "Suppression annulée",
            deletingIn: "Suppression dans {seconds} secondes...",
            cooldownActive: "Veuillez attendre {hours} heure(s) avant de demander une nouvelle suppression.",
            exportLimitReached: "Limite d'exportation atteinte ({max} par jour). Réessayez demain.",
            exportingData: "Préparation de l'exportation des données...",
            requestingData: "Demande de vos données...",
            dataExported: "Données exportées avec succès",
            allDataDeleted: "Toutes les données supprimées",
            confirmDeleteHistory: "Êtes-vous sûr de vouloir supprimer l'historique du chat ?",
            confirmDeleteAllData: "Êtes-vous sûr de vouloir supprimer TOUTES vos données ? Cette action est irréversible.",
            historyDeleted: "Historique du chat supprimé",
            confirmRevokeConsent: "Êtes-vous sûr de vouloir révoquer votre consentement ? Le chat ne sera plus disponible.",
            consentRevoked: "Consentement révoqué",
            consentDeclined: "Consentement refusé",
            consentActiveLabel: "Consentement actif",
            revokedAtLabel: "Date de révocation",
            revokeReasonLabel: "Motif de révocation",
            confirmTitle: "Confirmation",
            deleteHistoryTitle: "Supprimer l'Historique",
            revokeConsentTitle: "Révoquer le Consentement",
            deleteAllDataTitle: "Supprimer Toutes les Données",
            deleteHistoryButton: "🗑️ Supprimer l'Historique du Chat",
            deleteAllDataButton: "🗑️ Supprimer Toutes Mes Données"
        }
    },

    // 🇩🇪 НЕМЕЦКИЙ ЯЗЫК
    de: {
        interface: {
            minimize: "Minimieren",              
            expand: "Erweitern",              
            placeholder: "Nachricht eingeben...", 
            voiceTooltip: "Sprachnachricht", 
            sendTooltip: "Nachricht senden",  
            typingIndicator: "Tippt",
            fileTooltip: "Datei anhängen",
            pasteImageHint: "Bild einfügen (Strg+V)",
            fileUploading: "Datei wird hochgeladen...",
            fileTooLarge: "Datei zu groß",
            fileTypeNotAllowed: "Dateityp nicht unterstützt",
            fileError: "Fehler beim Verarbeiten der Datei",
            selectLanguage: "Sprache auswählen",
            switchSpecialist: "Spezialist wechseln",
            contactUs: "Kontaktieren Sie uns",
            popoutTooltip: "In einem separaten Fenster öffnen",
            selectedFile: "Ausgewählte Datei:",
            removeFile: "Datei entfernen"
        },

commands: {
            voiceEnabled: "🎤 Sprachnachrichten aktiviert",
            voiceDisabled: "🔇 Sprachnachrichten deaktiviert",
            //connectingManager: "🔄 Verbinde mit Manager...",
            //managerConnected: "✅ Manager verbunden",
            historyCleared: "🗑️ Chat-Verlauf gelöscht",
            languageChanged: "🌍 Sprache geändert zu Deutsch",
            configSwitched: "🔄 Gewechselt zu",
            chatMinimized: "📌 Chat minimiert",
            chatExpanded: "📖 Chat erweitert"
        
    },

        errors: {
            connectionError: "❌ Serververbindungsfehler",
            fallbackMessage: "Entschuldigung, es gab ein technisches Problem. Versuchen Sie es später noch einmal.",
            microphoneAccess: "❌ Kein Mikrofonzugriff",
            voiceProcessing: "❌ Fehler bei der Sprachverarbeitung",
            // 🆕 Neue Fehlertypen:
            timeoutError: "⏱️ Zeitüberschreitung. Bitte versuchen Sie es erneut.",
            networkError: "🌐 Netzwerkfehler. Überprüfen Sie Ihre Internetverbindung.",
            licenseError: "🔒 Lizenzfehler. Bitte laden Sie die Seite neu.",
            authError: "🔒 Autorisierungsfehler. Bitte überprüfen Sie Ihre Lizenz.",
            dataSizeError: "📦 Die Datengröße ist zu groß.",
            badRequest: "⚠️ Ungültige Anfrage. Bitte überprüfen Sie Ihre Eingabe.",
            serviceUnavailable: "🔍 Service nicht verfügbar. Kontaktieren Sie den Administrator.",
            rateLimitError: "⏳ Zu viele Anfragen. Bitte warten Sie.",
            serverError: "🔧 Serverfehler. Bitte versuchen Sie es später noch einmal.",
            popupBlockedError: "Fenster konnte nicht geöffnet werden. Bitte überprüfen Sie die Popup-Blocker-Einstellungen.",
            dateError: "Datumsfehler"
        },

        system: {
            connecting: "Verbinde...",         
            voiceMessage: "🎤 Sprachnachricht",
            switching: "Wechsle zu",
            nowServing: "Bedient Sie jetzt",
            voiceMessageUnavailable: "🎤 Sprachnachricht (nicht verfügbar)",
            voiceMessageExpired: "🎤 Sprachnachricht (abgelaufen)",
            voiceMessageError: "🎤 Sprachnachricht (Ladefehler)",
            videoMessage: "🎥 Videonachricht",
            videoMessageError: "🎥 Videonachricht (Ladefehler)",
            videoMessageUnavailable: "🎥 Videonachricht (nicht verfügbar)"
        },

        contacts: {
            title: "Kontaktieren Sie uns",
            tooltip: "Kontakte"
        },

        switcher: {
            tooltip: "Spezialist wechseln"
        },

        quickButtons: {
            toggleShow: "Schnellaktionen anzeigen",
            toggleHide: "Schnellaktionen ausblenden",
            title: "Schnellaktionen"
        },

        datetime: {
            today: "Heute",
            yesterday: "Gestern",
            timeFormat: "24h",
            months: [
                "Jan", "Feb", "Mär", "Apr", "Mai", "Jun",
                "Jul", "Aug", "Sep", "Okt", "Nov", "Dez"
            ],
            monthsFull: [
                "Januar", "Februar", "März", "April", "Mai", "Juni",
                "Juli", "August", "September", "Oktober", "November", "Dezember"
            ],
            weekdays: [
                "So", "Mo", "Di", "Mi", "Do", "Fr", "Sa"
            ],
            weekdaysFull: [
                "Sonntag", "Montag", "Dienstag", "Mittwoch",
                "Donnerstag", "Freitag", "Samstag"
            ]
        },

        // 🆕 Neuer Abschnitt für Ratenbegrenzung
        rateLimiting: {
            tooManyMessages: "⏳ Zu viele Nachrichten. Maximal {max} Nachrichten pro Minute."
        },

        // 🆕 Neuer Abschnitt für Fallback-Texte
        fallback: {
            assistant: "Assistent",
            welcome: "Willkommen!",
            defaultUserName: "Benutzer"
        },

        // 🔐 DSGVO & Datenschutz
        gdpr: {
            // Consent Banner
            consentTitle: "🔒 Datenschutz & Cookies",
            consentText: "Wir nutzen diesen Chat zur Bearbeitung Ihrer Anfragen. Ihre Daten werden gemäß unserer Datenschutzrichtlinie verarbeitet.",
            consentTextAI: "Sie werden mit einem KI-Assistenten chatten. Ihre Nachrichten werden mittels künstlicher Intelligenz verarbeitet.",
            consentTextMonitoring: "Gespräche können zur Verbesserung der Servicequalität analysiert werden.",
            acceptButton: "Akzeptieren & Fortfahren",
            declineButton: "Ablehnen",
            privacyLinkText: "Datenschutzrichtlinie",
            cookieLinkText: "Cookie-Richtlinie",
            termsLinkText: "Nutzungsbedingungen",

            // Standard mode UI
            continueWithoutAcceptButton: "Ohne Zustimmung fortfahren",
            standardModeNote: "Sie können Ihre Datenschutzeinstellungen jederzeit über das 🔒-Symbol verwalten.",
            dismissBannerTooltip: "Schließen (Einstellungen später verwalten)",

            // Pre-Chat Form
            formTitle: "Gespräch Starten",
            formSubtitle: "Bitte füllen Sie das Formular aus, bevor Sie den Chat starten",
            nameLabel: "Ihr Name",
            namePlaceholder: "Geben Sie Ihren Namen ein",
            emailLabel: "E-Mail",
            emailPlaceholder: "Geben Sie Ihre E-Mail ein",
            phoneLabel: "Telefon",
            phonePlaceholder: "Geben Sie Ihre Telefonnummer ein",
            companyLabel: "Unternehmen",
            companyPlaceholder: "Unternehmensname",
            requiredFieldMark: "* - Pflichtfeld",
            gdprCheckboxText: "Ich stimme der Verarbeitung meiner personenbezogenen Daten zu",
            startChatButton: "Chat Starten",
            piiIndicator: "🔒 Personenbezogene Daten",

            // AI Disclosure
            aiDisclosureTitle: "KI-Assistent",
            aiDisclosureMessage: "🤖 Sie chatten mit einem KI-Assistenten. Unsere KI wurde für schnelle und effiziente Hilfe entwickelt. Obwohl wir nach Genauigkeit streben, können manchmal Fehler auftreten.",
            aiDisclosureBadge: "KI",

            // Privacy Controls Menu
            privacyMenuTitle: "🔐 Datenschutzeinstellungen",
            viewDataButton: "👁️ Meine Daten Anzeigen",
            editDataButton: "✏️ Daten Bearbeiten",
            exportDataButton: "📥 Daten Exportieren",
            deleteDataButton: "🗑️ Alle Daten Löschen",
            revokeConsentButton: "⛔ Einwilligung Widerrufen",
            downloadTranscriptButton: "💬 Gespräch Herunterladen",
            clearHistoryButton: "🧹 Verlauf Löschen",
            // Daten Bearbeiten
            editFormTitle: "✏️ Ihre Daten Bearbeiten",
            editFormSubtitle: "Aktualisieren Sie Ihre persönlichen Informationen",
            editingData: "Dateneditor wird geöffnet...",
            saveChangesButton: "💾 Änderungen Speichern",
            cancelButton: "Abbrechen",
            dataUpdatedSuccess: "✅ Ihre Daten wurden erfolgreich aktualisiert",

            // Confirmations
            deleteConfirmTitle: "Daten Löschen",
            deleteConfirmText: "Sind Sie sicher, dass Sie alle Ihre Daten löschen möchten? Diese Aktion kann nicht rückgängig gemacht werden.",
            revokeConfirmTitle: "Einwilligung Widerrufen",
            revokeConfirmText: "Nach dem Widerruf der Einwilligung ist der Chat nicht mehr verfügbar. Sind Sie sicher?",
            confirmButton: "Ja, Bestätigen",
            cancelButton: "Abbrechen",

            // Success Messages
            consentSavedSuccess: "✓ Einwilligung gespeichert",
            dataDeletedSuccess: "✓ Ihre Daten wurden erfolgreich gelöscht",
            consentRevokedSuccess: "✓ Einwilligung widerrufen. Chat deaktiviert.",
            dataExportedSuccess: "✓ Daten exportiert",
            historyCleared: "✓ Chat-Verlauf gelöscht",
            formSubmittedSuccess: "✓ Formular gesendet",

            // Error Messages
            consentRequired: "Für die Nutzung des Chats ist eine Einwilligung erforderlich",
            formValidationError: "Bitte füllen Sie alle Pflichtfelder aus",
            webhookError: "Fehler bei der Verarbeitung der Anfrage. Bitte versuchen Sie es später erneut.",
            networkError: "Netzwerkfehler. Bitte überprüfen Sie Ihre Internetverbindung.",
            emailRequired: "E-Mail ist für diese Aktion erforderlich",
            emailInvalid: "Bitte geben Sie eine gültige E-Mail-Adresse ein",

            // Declined State
            declinedTitle: "Einwilligung Abgelehnt",
            declinedMessage: "Sie haben die Einwilligung zur Datenverarbeitung abgelehnt. Der Chat ist nicht verfügbar.",
            declinedReconsiderButton: "Überdenken",
            inputDisabledPlaceholder: "Chat ohne Einwilligung nicht verfügbar",

            // Data View Modal
            dataViewTitle: "Ihre Daten",
            dataViewEmpty: "Keine gespeicherten Daten",
            dataViewLoading: "Daten werden geladen...",
            dataViewError: "Daten konnten nicht geladen werden",
            yourDataTitle: "Ihre Daten",
            contactDataTitle: "Kontaktdaten",
            createdAtLabel: "Erstellt am",
            consentDataTitle: "Einwilligungsinformationen",
            consentGivenLabel: "Einwilligung erteilt",
            consentYes: "Ja",
            consentNo: "Nein",
            consentDateLabel: "Einwilligungsdatum",
            expiresAtLabel: "Läuft ab",
            domainLabel: "Domain",
            chatHistoryTitle: "Chat-Verlauf",
            totalMessagesLabel: "Nachrichten",
            noChatHistory: "Der Chat-Verlauf ist leer",
            you: "Sie",
            assistant: "Assistent",
            sessionInfoTitle: "Sitzungsinformationen",
            closeButton: "Schließen",

            // Security Indicators
            securedBadge: "Gesichert",
            gdprBadge: "DSGVO",
            encryptedBadge: "Verschlüsselt",
            aiBadge: "KI",

            // Data Retention Info
            retentionInfo: "Ihre Daten werden gemäß unserer Datenschutzrichtlinie gespeichert",
            retentionDaysText: "Datenspeicherungszeitraum: {days} Tage",

            // HTTPS Warning
            httpsWarning: "⚠️ Aus Sicherheitsgründen wird eine HTTPS-Verbindung empfohlen",

            // Processing
            processingRequest: "Anfrage wird verarbeitet...",
            pleaseWait: "Bitte warten...",

            // Advanced GDPR features
            confirmDeleteAllDataSecond: "Dies ist Ihre ENDGÜLTIGE Bestätigung. Geben Sie 'DELETE' ein, um fortzufahren.",
            finalDeleteTitle: "⚠️ Endgültige Bestätigung",
            deleteInputPlaceholder: "DELETE eingeben",
            deleteInputError: "Bitte geben Sie DELETE zur Bestätigung ein",
            deletionCancelled: "Löschung abgebrochen",
            deletingIn: "Löschen in {seconds} Sekunden...",
            cooldownActive: "Bitte warten Sie {hours} Stunde(n), bevor Sie erneut eine Löschung anfordern.",
            exportLimitReached: "Export-Limit erreicht ({max} pro Tag). Versuchen Sie es morgen erneut.",
            exportingData: "Datenexport wird vorbereitet...",
            requestingData: "Ihre Daten werden angefordert...",
            dataExported: "Daten erfolgreich exportiert",
            allDataDeleted: "Alle Daten gelöscht",
            confirmDeleteHistory: "Sind Sie sicher, dass Sie den Chatverlauf löschen möchten?",
            confirmDeleteAllData: "Sind Sie sicher, dass Sie ALLE Ihre Daten löschen möchten? Diese Aktion kann nicht rückgängig gemacht werden.",
            historyDeleted: "Chatverlauf gelöscht",
            confirmRevokeConsent: "Sind Sie sicher, dass Sie Ihre Einwilligung widerrufen möchten? Der Chat wird nicht mehr verfügbar sein.",
            consentRevoked: "Einwilligung widerrufen",
            consentDeclined: "Einwilligung abgelehnt",
            consentActiveLabel: "Einwilligung aktiv",
            revokedAtLabel: "Widerrufsdatum",
            revokeReasonLabel: "Widerrufsgrund",
            confirmTitle: "Bestätigung",
            deleteHistoryTitle: "Verlauf Löschen",
            revokeConsentTitle: "Einwilligung Widerrufen",
            deleteAllDataTitle: "Alle Daten Löschen",
            deleteHistoryButton: "🗑️ Chatverlauf Löschen",
            deleteAllDataButton: "🗑️ Alle Meine Daten Löschen"
        }
    },

    // 🇮🇹 ИТАЛЬЯНСКИЙ ЯЗЫК
    it: {
        interface: {
            minimize: "Riduci",              
            expand: "Espandi",              
            placeholder: "Scrivi un messaggio...", 
            voiceTooltip: "Messaggio vocale", 
            sendTooltip: "Invia messaggio",  
            typingIndicator: "Digitando",
            fileTooltip: "Allega file",
            pasteImageHint: "Incolla immagine (Ctrl+V)",
            fileUploading: "Caricamento file...",
            fileTooLarge: "File troppo grande",
            fileTypeNotAllowed: "Tipo di file non supportato",
            fileError: "Errore nell'elaborazione del file",
            selectLanguage: "Seleziona lingua",
            switchSpecialist: "Cambia specialista",
            contactUs: "Contattaci",
            popoutTooltip: "Apri in una finestra separata",
            selectedFile: "File selezionato:",
            removeFile: "Rimuovi file"
        },

commands: {
            voiceEnabled: "🎤 Messaggi vocali attivati",
            voiceDisabled: "🔇 Messaggi vocali disattivati",
            //connectingManager: "🔄 Connessione al manager...",
            //managerConnected: "✅ Manager connesso",
            historyCleared: "🗑️ Cronologia chat cancellata",
            languageChanged: "🌍 Lingua cambiata in italiano",
            configSwitched: "🔄 Passato a",
            chatMinimized: "📌 Chat ridotta",
            chatExpanded: "📖 Chat espansa"
        
    },

        errors: {
            connectionError: "❌ Errore di connessione al server",
            fallbackMessage: "Spiacenti, si è verificato un problema tecnico. Riprova più tardi.",
            microphoneAccess: "❌ Nessun accesso al microfono",
            voiceProcessing: "❌ Errore nell'elaborazione del messaggio vocale",
            // 🆕 Nuovi tipi di errori:
            timeoutError: "⏱️ Timeout superato. Riprova di nuovo.",
            networkError: "🌐 Errore di rete. Controlla la tua connessione internet.",
            licenseError: "🔒 Errore di licenza. Aggiorna la pagina.",
            authError: "🔒 Errore di autorizzazione. Controlla la tua licenza.",
            dataSizeError: "📦 La dimensione dei dati è troppo grande.",
            badRequest: "⚠️ Richiesta non valida. Controlla il tuo input.",
            serviceUnavailable: "🔍 Servizio non disponibile. Contatta l'amministratore.",
            rateLimitError: "⏳ Troppe richieste. Attendere prego.",
            serverError: "🔧 Errore del server. Riprova più tardi.",
            popupBlockedError: "Impossibile aprire la finestra. Controlla le impostazioni del blocco popup.",
            dateError: "Errore di data"
        },

        system: {
            connecting: "Connessione...",         
            voiceMessage: "🎤 Messaggio vocale",
            switching: "Passaggio a",
            nowServing: "Ora ti serve",
            voiceMessageUnavailable: "🎤 Messaggio vocale (non disponibile)",
            voiceMessageExpired: "🎤 Messaggio vocale (scaduto)",
            voiceMessageError: "🎤 Messaggio vocale (errore di caricamento)",
            videoMessage: "🎥 Messaggio video",
            videoMessageError: "🎥 Messaggio video (errore di caricamento)",
            videoMessageUnavailable: "🎥 Messaggio video (non disponibile)"
        },

        contacts: {
            title: "Contattaci",
            tooltip: "Contatti"
        },

        switcher: {
            tooltip: "Cambia specialista"
        },

        quickButtons: {
            toggleShow: "Mostra azioni rapide",
            toggleHide: "Nascondi azioni rapide",
            title: "Azioni rapide"
        },

        datetime: {
            today: "Oggi",
            yesterday: "Ieri",
            timeFormat: "24h",
            months: [
                "gen", "feb", "mar", "apr", "mag", "giu",
                "lug", "ago", "set", "ott", "nov", "dic"
            ],
            monthsFull: [
                "gennaio", "febbraio", "marzo", "aprile", "maggio", "giugno",
                "luglio", "agosto", "settembre", "ottobre", "novembre", "dicembre"
            ],
            weekdays: [
                "Dom", "Lun", "Mar", "Mer", "Gio", "Ven", "Sab"
            ],
            weekdaysFull: [
                "domenica", "lunedì", "martedì", "mercoledì",
                "giovedì", "venerdì", "sabato"
            ]
        },

        // 🆕 Nuova sezione per la limitazione della velocità
        rateLimiting: {
            tooManyMessages: "⏳ Troppi messaggi. Massimo {max} messaggi al minuto."
        },

        // 🆕 Nuova sezione per i testi di riserva
        fallback: {
            assistant: "Assistente",
            welcome: "Benvenuto!",
            defaultUserName: "Utente"
        },

        // 🔐 GDPR e Privacy
        gdpr: {
            // Consent Banner
            consentTitle: "🔒 Privacy e Cookie",
            consentText: "Utilizziamo questa chat per elaborare le tue richieste. I tuoi dati saranno trattati secondo la nostra politica sulla privacy.",
            consentTextAI: "Comunicherai con un assistente AI. I tuoi messaggi vengono elaborati tramite intelligenza artificiale.",
            consentTextMonitoring: "Le conversazioni possono essere analizzate per migliorare la qualità del servizio.",
            acceptButton: "Accetta e Continua",
            declineButton: "Rifiuta",
            privacyLinkText: "Informativa sulla Privacy",
            cookieLinkText: "Informativa sui Cookie",
            termsLinkText: "Termini di Servizio",

            // Standard mode UI
            continueWithoutAcceptButton: "Continua senza accettare",
            standardModeNote: "Puoi gestire le tue preferenze sulla privacy in qualsiasi momento tramite l'icona 🔒.",
            dismissBannerTooltip: "Chiudi (gestisci le preferenze dopo)",

            // Pre-Chat Form
            formTitle: "Inizia una Conversazione",
            formSubtitle: "Compila il modulo prima di iniziare la chat",
            nameLabel: "Il Tuo Nome",
            namePlaceholder: "Inserisci il tuo nome",
            emailLabel: "Email",
            emailPlaceholder: "Inserisci la tua email",
            phoneLabel: "Telefono",
            phonePlaceholder: "Inserisci il tuo numero di telefono",
            companyLabel: "Azienda",
            companyPlaceholder: "Nome dell'azienda",
            requiredFieldMark: "* - campo obbligatorio",
            gdprCheckboxText: "Acconsento al trattamento dei miei dati personali",
            startChatButton: "Inizia Chat",
            piiIndicator: "🔒 Dati personali",

            // AI Disclosure
            aiDisclosureTitle: "Assistente AI",
            aiDisclosureMessage: "🤖 Stai chattando con un assistente AI. La nostra AI è progettata per un'assistenza rapida ed efficiente. Pur mirando alla precisione, possono verificarsi errori.",
            aiDisclosureBadge: "AI",

            // Privacy Controls Menu
            privacyMenuTitle: "🔐 Impostazioni Privacy",
            viewDataButton: "👁️ Visualizza i Miei Dati",
            editDataButton: "✏️ Modifica Dati",
            exportDataButton: "📥 Esporta Dati",
            deleteDataButton: "🗑️ Elimina Tutti i Dati",
            revokeConsentButton: "⛔ Revoca Consenso",
            downloadTranscriptButton: "💬 Scarica Conversazione",
            clearHistoryButton: "🧹 Cancella Cronologia",
            // Modifica Dati
            editFormTitle: "✏️ Modifica i Tuoi Dati",
            editFormSubtitle: "Aggiorna le tue informazioni personali",
            editingData: "Apertura editor dati...",
            saveChangesButton: "💾 Salva Modifiche",
            cancelButton: "Annulla",
            dataUpdatedSuccess: "✅ I tuoi dati sono stati aggiornati con successo",

            // Confirmations
            deleteConfirmTitle: "Elimina Dati",
            deleteConfirmText: "Sei sicuro di voler eliminare tutti i tuoi dati? Questa azione non può essere annullata.",
            revokeConfirmTitle: "Revoca Consenso",
            revokeConfirmText: "Dopo la revoca del consenso, la chat non sarà disponibile. Sei sicuro?",
            confirmButton: "Sì, Conferma",
            cancelButton: "Annulla",

            // Success Messages
            consentSavedSuccess: "✓ Consenso salvato",
            dataDeletedSuccess: "✓ I tuoi dati sono stati eliminati con successo",
            consentRevokedSuccess: "✓ Consenso revocato. Chat disabilitata.",
            dataExportedSuccess: "✓ Dati esportati",
            historyCleared: "✓ Cronologia chat cancellata",
            formSubmittedSuccess: "✓ Modulo inviato",

            // Error Messages
            consentRequired: "Il consenso è richiesto per utilizzare la chat",
            formValidationError: "Compila tutti i campi obbligatori",
            webhookError: "Errore nell'elaborazione della richiesta. Riprova più tardi.",
            networkError: "Errore di rete. Verifica la tua connessione internet.",
            emailRequired: "L'email è richiesta per questa azione",
            emailInvalid: "Inserisci un indirizzo email valido",

            // Declined State
            declinedTitle: "Consenso Rifiutato",
            declinedMessage: "Hai rifiutato il consenso al trattamento dei dati. La chat non è disponibile.",
            declinedReconsiderButton: "Riconsiderare",
            inputDisabledPlaceholder: "Chat non disponibile senza consenso",

            // Data View Modal
            dataViewTitle: "I Tuoi Dati",
            dataViewEmpty: "Nessun dato salvato",
            dataViewLoading: "Caricamento dati...",
            dataViewError: "Impossibile caricare i dati",
            yourDataTitle: "I Tuoi Dati",
            contactDataTitle: "Informazioni di Contatto",
            createdAtLabel: "Data di creazione",
            consentDataTitle: "Informazioni sul consenso",
            consentGivenLabel: "Consenso dato",
            consentYes: "Sì",
            consentNo: "No",
            consentDateLabel: "Data del consenso",
            expiresAtLabel: "Scade",
            domainLabel: "Dominio",
            chatHistoryTitle: "Cronologia Chat",
            totalMessagesLabel: "Messaggi",
            noChatHistory: "La cronologia chat è vuota",
            you: "Tu",
            assistant: "Assistente",
            sessionInfoTitle: "Informazioni Sessione",
            closeButton: "Chiudi",

            // Security Indicators
            securedBadge: "Protetto",
            gdprBadge: "GDPR",
            encryptedBadge: "Crittografato",
            aiBadge: "AI",

            // Data Retention Info
            retentionInfo: "I tuoi dati sono conservati secondo la nostra politica sulla privacy",
            retentionDaysText: "Periodo di conservazione dati: {days} giorni",

            // HTTPS Warning
            httpsWarning: "⚠️ Per sicurezza, si consiglia di utilizzare una connessione HTTPS",

            // Processing
            processingRequest: "Elaborazione richiesta...",
            pleaseWait: "Attendere prego...",

            // Advanced GDPR features
            confirmDeleteAllDataSecond: "Questa è la tua conferma FINALE. Digita 'DELETE' per procedere.",
            finalDeleteTitle: "⚠️ Conferma Finale",
            deleteInputPlaceholder: "Digita DELETE",
            deleteInputError: "Per favore digita DELETE per confermare",
            deletionCancelled: "Eliminazione annullata",
            deletingIn: "Eliminazione tra {seconds} secondi...",
            cooldownActive: "Attendere {hours} ora/e prima di richiedere nuovamente l'eliminazione.",
            exportLimitReached: "Limite di esportazione raggiunto ({max} al giorno). Riprova domani.",
            exportingData: "Preparazione esportazione dati...",
            requestingData: "Richiesta dei tuoi dati...",
            dataExported: "Dati esportati con successo",
            allDataDeleted: "Tutti i dati eliminati",
            confirmDeleteHistory: "Sei sicuro di voler eliminare la cronologia della chat?",
            confirmDeleteAllData: "Sei sicuro di voler eliminare TUTTI i tuoi dati? Questa azione non può essere annullata.",
            historyDeleted: "Cronologia chat eliminata",
            confirmRevokeConsent: "Sei sicuro di voler revocare il consenso? La chat non sarà più disponibile.",
            consentRevoked: "Consenso revocato",
            consentDeclined: "Consenso rifiutato",
            consentActiveLabel: "Consenso attivo",
            revokedAtLabel: "Data di revoca",
            revokeReasonLabel: "Motivo della revoca",
            confirmTitle: "Conferma",
            deleteHistoryTitle: "Elimina Cronologia",
            revokeConsentTitle: "Revoca Consenso",
            deleteAllDataTitle: "Elimina Tutti i Dati",
            deleteHistoryButton: "🗑️ Elimina Cronologia Chat",
            deleteAllDataButton: "🗑️ Elimina Tutti i Miei Dati"
        }
    },

    // 🇵🇹 ПОРТУГАЛЬСКИЙ ЯЗЫК
    pt: {
        interface: {
            minimize: "Minimizar",              
            expand: "Expandir",              
            placeholder: "Digite uma mensagem...", 
            voiceTooltip: "Mensagem de voz", 
            sendTooltip: "Enviar mensagem",  
            typingIndicator: "Digitando",
            fileTooltip: "Anexar arquivo",
            pasteImageHint: "Colar imagem (Ctrl+V)",
            fileUploading: "Enviando arquivo...",
            fileTooLarge: "Arquivo muito grande",
            fileTypeNotAllowed: "Tipo de arquivo não suportado",
            fileError: "Erro ao processar arquivo",
            selectLanguage: "Selecionar idioma",
            switchSpecialist: "Trocar especialista",
            contactUs: "Entre em contato",
            popoutTooltip: "Abrir em uma janela separada",
            selectedFile: "Arquivo selecionado:",
            removeFile: "Remover arquivo"
        },

commands: {
            voiceEnabled: "🎤 Mensagens de voz ativadas",
            voiceDisabled: "🔇 Mensagens de voz desativadas",
            //connectingManager: "🔄 Conectando ao gerente...",
            //managerConnected: "✅ Gerente conectado",
            historyCleared: "🗑️ Histórico do chat limpo",
            languageChanged: "🌍 Idioma alterado para português",
            configSwitched: "🔄 Mudado para",
            chatMinimized: "📌 Chat minimizado",
            chatExpanded: "📖 Chat expandido"
        
    },

        errors: {
            connectionError: "❌ Erro de conexão com o servidor",
            fallbackMessage: "Desculpe, houve um problema técnico. Tente novamente mais tarde.",
            microphoneAccess: "❌ Sem acesso ao microfone",
            voiceProcessing: "❌ Erro no processamento da mensagem de voz",
            // 🆕 Novos tipos de erros:
            timeoutError: "⏱️ Tempo limite excedido. Tente novamente.",
            networkError: "🌐 Erro de rede. Verifique sua conexão com a internet.",
            licenseError: "🔒 Erro de licença. Atualize a página.",
            authError: "🔒 Erro de autorização. Verifique sua licença.",
            dataSizeError: "📦 O tamanho dos dados é muito grande.",
            badRequest: "⚠️ Solicitação inválida. Verifique sua entrada.",
            serviceUnavailable: "🔍 Serviço indisponível. Entre em contato com o administrador.",
            rateLimitError: "⏳ Muitas solicitações. Por favor, aguarde.",
            serverError: "🔧 Erro do servidor. Tente novamente mais tarde.",
            popupBlockedError: "Falha ao abrir a janela. Verifique as configurações do bloqueador de pop-up.",
            dateError: "Erro de data"
        },

        system: {
            connecting: "Conectando...",         
            voiceMessage: "🎤 Mensagem de voz",
            switching: "Mudando para",
            nowServing: "Agora atendendo você",
            voiceMessageUnavailable: "🎤 Mensagem de voz (indisponível)",
            voiceMessageExpired: "🎤 Mensagem de voz (expirada)",
            voiceMessageError: "🎤 Mensagem de voz (erro ao carregar)",
            videoMessage: "🎥 Mensagem de vídeo",
            videoMessageError: "🎥 Mensagem de vídeo (erro de carregamento)",
            videoMessageUnavailable: "🎥 Mensagem de vídeo (indisponível)"
        },

        contacts: {
            title: "Entre em contato",
            tooltip: "Contatos"
        },

        switcher: {
            tooltip: "Trocar especialista"
        },

        quickButtons: {
            toggleShow: "Mostrar ações rápidas",
            toggleHide: "Ocultar ações rápidas",
            title: "Ações rápidas"
        },

        datetime: {
            today: "Hoje",
            yesterday: "Ontem",
            timeFormat: "24h",
            months: [
                "jan", "fev", "mar", "abr", "mai", "jun",
                "jul", "ago", "set", "out", "nov", "dez"
            ],
            monthsFull: [
                "janeiro", "fevereiro", "março", "abril", "maio", "junho",
                "julho", "agosto", "setembro", "outubro", "novembro", "dezembro"
            ],
            weekdays: [
                "Dom", "Seg", "Ter", "Qua", "Qui", "Sex", "Sáb"
            ],
            weekdaysFull: [
                "domingo", "segunda-feira", "terça-feira", "quarta-feira",
                "quinta-feira", "sexta-feira", "sábado"
            ]
        },

        // 🆕 Nova seção para limitação de taxa
        rateLimiting: {
            tooManyMessages: "⏳ Muitas mensagens. Máximo {max} mensagens por minuto."
        },

        // 🆕 Nova seção para textos de fallback
        fallback: {
            assistant: "Assistente",
            welcome: "Bem-vindo!",
            defaultUserName: "Usuário"
        },

        // 🔐 RGPD e Privacidade
        gdpr: {
            // Consent Banner
            consentTitle: "🔒 Privacidade e Cookies",
            consentText: "Utilizamos este chat para processar suas solicitações. Seus dados serão processados de acordo com nossa política de privacidade.",
            consentTextAI: "Você conversará com um assistente de IA. Suas mensagens são processadas por inteligência artificial.",
            consentTextMonitoring: "As conversas podem ser analisadas para melhorar a qualidade do serviço.",
            acceptButton: "Aceitar e Continuar",
            declineButton: "Recusar",
            privacyLinkText: "Política de Privacidade",
            cookieLinkText: "Política de Cookies",
            termsLinkText: "Termos de Serviço",

            // Standard mode UI
            continueWithoutAcceptButton: "Continuar sem aceitar",
            standardModeNote: "Você pode gerenciar suas preferências de privacidade a qualquer momento através do ícone 🔒.",
            dismissBannerTooltip: "Fechar (gerenciar preferências depois)",

            // Pre-Chat Form
            formTitle: "Iniciar Conversa",
            formSubtitle: "Por favor preencha o formulário antes de iniciar o chat",
            nameLabel: "Seu Nome",
            namePlaceholder: "Digite seu nome",
            emailLabel: "Email",
            emailPlaceholder: "Digite seu email",
            phoneLabel: "Telefone",
            phonePlaceholder: "Digite seu número de telefone",
            companyLabel: "Empresa",
            companyPlaceholder: "Nome da empresa",
            requiredFieldMark: "* - campo obrigatório",
            gdprCheckboxText: "Concordo com o processamento dos meus dados pessoais",
            startChatButton: "Iniciar Chat",
            piiIndicator: "🔒 Dados pessoais",

            // AI Disclosure
            aiDisclosureTitle: "Assistente de IA",
            aiDisclosureMessage: "🤖 Você está conversando com um assistente de IA. Nossa IA foi projetada para assistência rápida e eficiente. Embora busquemos precisão, erros podem ocorrer.",
            aiDisclosureBadge: "IA",

            // Privacy Controls Menu
            privacyMenuTitle: "🔐 Configurações de Privacidade",
            viewDataButton: "👁️ Ver Meus Dados",
            editDataButton: "✏️ Editar Dados",
            exportDataButton: "📥 Exportar Dados",
            deleteDataButton: "🗑️ Excluir Todos os Dados",
            revokeConsentButton: "⛔ Revogar Consentimento",
            downloadTranscriptButton: "💬 Baixar Conversa",
            clearHistoryButton: "🧹 Limpar Histórico",
            // Editar Dados
            editFormTitle: "✏️ Editar Seus Dados",
            editFormSubtitle: "Atualize suas informações pessoais",
            editingData: "Abrindo editor de dados...",
            saveChangesButton: "💾 Salvar Alterações",
            cancelButton: "Cancelar",
            dataUpdatedSuccess: "✅ Seus dados foram atualizados com sucesso",

            // Confirmations
            deleteConfirmTitle: "Excluir Dados",
            deleteConfirmText: "Tem certeza que deseja excluir todos os seus dados? Esta ação não pode ser desfeita.",
            revokeConfirmTitle: "Revogar Consentimento",
            revokeConfirmText: "Após revogar o consentimento, o chat ficará indisponível. Tem certeza?",
            confirmButton: "Sim, Confirmar",
            cancelButton: "Cancelar",

            // Success Messages
            consentSavedSuccess: "✓ Consentimento salvo",
            dataDeletedSuccess: "✓ Seus dados foram excluídos com sucesso",
            consentRevokedSuccess: "✓ Consentimento revogado. Chat desabilitado.",
            dataExportedSuccess: "✓ Dados exportados",
            historyCleared: "✓ Histórico do chat limpo",
            formSubmittedSuccess: "✓ Formulário enviado",

            // Error Messages
            consentRequired: "O consentimento é necessário para usar o chat",
            formValidationError: "Por favor preencha todos os campos obrigatórios",
            webhookError: "Erro ao processar solicitação. Por favor tente novamente mais tarde.",
            networkError: "Erro de rede. Por favor verifique sua conexão com a internet.",
            emailRequired: "Email é obrigatório para esta ação",
            emailInvalid: "Por favor digite um endereço de email válido",

            // Declined State
            declinedTitle: "Consentimento Recusado",
            declinedMessage: "Você recusou o consentimento para o processamento de dados. O chat não está disponível.",
            declinedReconsiderButton: "Reconsiderar",
            inputDisabledPlaceholder: "Chat indisponível sem consentimento",

            // Data View Modal
            dataViewTitle: "Seus Dados",
            dataViewEmpty: "Nenhum dado salvo",
            dataViewLoading: "Carregando dados...",
            dataViewError: "Não foi possível carregar os dados",
            yourDataTitle: "Seus Dados",
            contactDataTitle: "Informações de Contato",
            createdAtLabel: "Data de criação",
            consentDataTitle: "Informações de Consentimento",
            consentGivenLabel: "Consentimento dado",
            consentYes: "Sim",
            consentNo: "Não",
            consentDateLabel: "Data do consentimento",
            expiresAtLabel: "Expira",
            domainLabel: "Domínio",
            chatHistoryTitle: "Histórico do Chat",
            totalMessagesLabel: "Mensagens",
            noChatHistory: "O histórico do chat está vazio",
            you: "Você",
            assistant: "Assistente",
            sessionInfoTitle: "Informações da Sessão",
            closeButton: "Fechar",

            // Security Indicators
            securedBadge: "Seguro",
            gdprBadge: "RGPD",
            encryptedBadge: "Criptografado",
            aiBadge: "IA",

            // Data Retention Info
            retentionInfo: "Seus dados são armazenados de acordo com nossa política de privacidade",
            retentionDaysText: "Período de retenção de dados: {days} dias",

            // HTTPS Warning
            httpsWarning: "⚠️ Por segurança, é recomendado usar uma conexão HTTPS",

            // Processing
            processingRequest: "Processando solicitação...",
            pleaseWait: "Por favor aguarde...",

            // Advanced GDPR features
            confirmDeleteAllDataSecond: "Esta é sua confirmação FINAL. Digite 'DELETE' para continuar.",
            finalDeleteTitle: "⚠️ Confirmação Final",
            deleteInputPlaceholder: "Digite DELETE",
            deleteInputError: "Por favor digite DELETE para confirmar",
            deletionCancelled: "Exclusão cancelada",
            deletingIn: "Excluindo em {seconds} segundos...",
            cooldownActive: "Aguarde {hours} hora(s) antes de solicitar exclusão novamente.",
            exportLimitReached: "Limite de exportação atingido ({max} por dia). Tente novamente amanhã.",
            exportingData: "Preparando exportação de dados...",
            requestingData: "Solicitando seus dados...",
            dataExported: "Dados exportados com sucesso",
            allDataDeleted: "Todos os dados excluídos",
            confirmDeleteHistory: "Tem certeza de que deseja excluir o histórico do chat?",
            confirmDeleteAllData: "Tem certeza de que deseja excluir TODOS os seus dados? Esta ação não pode ser desfeita.",
            historyDeleted: "Histórico do chat excluído",
            confirmRevokeConsent: "Tem certeza de que deseja revogar seu consentimento? O chat não estará mais disponível.",
            consentRevoked: "Consentimento revogado",
            consentDeclined: "Consentimento recusado",
            consentActiveLabel: "Consentimento ativo",
            revokedAtLabel: "Data de revogação",
            revokeReasonLabel: "Motivo da revogação",
            confirmTitle: "Confirmação",
            deleteHistoryTitle: "Excluir Histórico",
            revokeConsentTitle: "Revogar Consentimento",
            deleteAllDataTitle: "Excluir Todos os Dados",
            deleteHistoryButton: "🗑️ Excluir Histórico do Chat",
            deleteAllDataButton: "🗑️ Excluir Todos os Meus Dados"
        }
    },

    // 🇨🇳 КИТАЙСКИЙ ЯЗЫК
    zh: {
        interface: {
            minimize: "最小化",              
            expand: "展开",              
            placeholder: "输入消息...", 
            voiceTooltip: "语音消息", 
            sendTooltip: "发送消息",  
            typingIndicator: "正在输入",
            fileTooltip: "附加文件",
            pasteImageHint: "粘贴图片 (Ctrl+V)",
            fileUploading: "正在上传文件...",
            fileTooLarge: "文件太大",
            fileTypeNotAllowed: "不支持的文件类型",
            fileError: "文件处理错误",
            selectLanguage: "选择语言",
            switchSpecialist: "切换专家",
            contactUs: "联系我们",
            popoutTooltip: "在单独窗口中打开",
            selectedFile: "已选文件：",
            removeFile: "删除文件"
        },

commands: {
            voiceEnabled: "🎤 语音消息已启用",
            voiceDisabled: "🔇 语音消息已禁用",
            //connectingManager: "🔄 正在连接管理员...",
            //managerConnected: "✅ 管理员已连接",
            historyCleared: "🗑️ 聊天记录已清除",
            languageChanged: "🌍 语言已更改为中文",
            configSwitched: "🔄 已切换到",
            chatMinimized: "📌 聊天已最小化",
            chatExpanded: "📖 聊天已展开"
        
    },

        errors: {
            connectionError: "❌ 服务器连接错误",
            fallbackMessage: "抱歉，出现了技术问题。请稍后再试。",
            microphoneAccess: "❌ 无法访问麦克风",
            voiceProcessing: "❌ 语音处理错误",
            // 🆕 新的错误类型:
            timeoutError: "⏱️ 响应超时。请重试。",
            networkError: "🌐 网络错误。请检查您的互联网连接。",
            licenseError: "🔒 许可证错误。请刷新页面。",
            authError: "🔒 授权错误。请检查您的许可证。",
            dataSizeError: "📦 数据大小太大。",
            badRequest: "⚠️ 无效请求。请检查您的输入。",
            serviceUnavailable: "🔍 服务不可用。请联系管理员。",
            rateLimitError: "⏳ 请求过多。请稍候。",
            serverError: "🔧 服务器错误。请稍后再试。",
            popupBlockedError: "无法打开窗口。请检查弹出窗口阻止程序设置。",
            dateError: "日期错误"
        },

        system: {
            connecting: "正在连接...",         
            voiceMessage: "🎤 语音消息",
            switching: "切换到",
            nowServing: "现在为您服务",
            voiceMessageUnavailable: "🎤 语音消息（不可用）",
            voiceMessageExpired: "🎤 语音消息（已过期）",
            voiceMessageError: "🎤 语音消息（加载错误）",
            videoMessage: "🎥 视频消息",
            videoMessageError: "🎥 视频消息（加载错误）",
            videoMessageUnavailable: "🎥 视频消息（不可用）"
        },

        contacts: {
            title: "联系我们",
            tooltip: "联系方式"
        },

        switcher: {
            tooltip: "切换专家"
        },

        quickButtons: {
            toggleShow: "显示快速操作",
            toggleHide: "隐藏快速操作",
            title: "快速操作"
        },

        datetime: {
            today: "今天",
            yesterday: "昨天",
            timeFormat: "24h",
            months: [
                "1月", "2月", "3月", "4月", "5月", "6月",
                "7月", "8月", "9月", "10月", "11月", "12月"
            ],
            monthsFull: [
                "一月", "二月", "三月", "四月", "五月", "六月",
                "七月", "八月", "九月", "十月", "十一月", "十二月"
            ],
            weekdays: [
                "日", "一", "二", "三", "四", "五", "六"
            ],
            weekdaysFull: [
                "星期日", "星期一", "星期二", "星期三",
                "星期四", "星期五", "星期六"
            ]
        },

        // 🆕 速率限制新部分
        rateLimiting: {
            tooManyMessages: "⏳ 消息过多。每分钟最多 {max} 条消息。"
        },

        // 🆕 后备文本新部分
        fallback: {
            assistant: "助手",
            welcome: "欢迎！",
            defaultUserName: "用户"
        },

        // 🔐 GDPR和隐私
        gdpr: {
            // Consent Banner
            consentTitle: "🔒 隐私与Cookie",
            consentText: "我们使用此聊天处理您的请求。您的数据将根据我们的隐私政策进行处理。",
            consentTextAI: "您将与AI助手交流。您的消息由人工智能处理。",
            consentTextMonitoring: "对话可能会被分析以提高服务质量。",
            acceptButton: "接受并继续",
            declineButton: "拒绝",
            privacyLinkText: "隐私政策",
            cookieLinkText: "Cookie政策",
            termsLinkText: "服务条款",

            // Standard mode UI
            continueWithoutAcceptButton: "不接受继续",
            standardModeNote: "您可以随时通过🔒图标管理您的隐私偏好设置。",
            dismissBannerTooltip: "关闭（稍后管理偏好设置）",

            // Pre-Chat Form
            formTitle: "开始对话",
            formSubtitle: "请在开始聊天前填写表格",
            nameLabel: "您的姓名",
            namePlaceholder: "输入您的姓名",
            emailLabel: "电子邮件",
            emailPlaceholder: "输入您的电子邮件",
            phoneLabel: "电话",
            phonePlaceholder: "输入您的电话号码",
            companyLabel: "公司",
            companyPlaceholder: "公司名称",
            requiredFieldMark: "* - 必填字段",
            gdprCheckboxText: "我同意处理我的个人数据",
            startChatButton: "开始聊天",
            piiIndicator: "🔒 个人数据",

            // AI Disclosure
            aiDisclosureTitle: "AI助手",
            aiDisclosureMessage: "🤖 您正在与AI助手交流。我们的AI旨在提供快速高效的帮助。虽然我们力求准确，但有时可能会出现错误。",
            aiDisclosureBadge: "AI",

            // Privacy Controls Menu
            privacyMenuTitle: "🔐 隐私设置",
            viewDataButton: "👁️ 查看我的数据",
            editDataButton: "✏️ 编辑数据",
            exportDataButton: "📥 导出数据",
            deleteDataButton: "🗑️ 删除所有数据",
            revokeConsentButton: "⛔ 撤销同意",
            downloadTranscriptButton: "💬 下载对话记录",
            clearHistoryButton: "🧹 清除历史",
            // 编辑数据
            editFormTitle: "✏️ 编辑您的数据",
            editFormSubtitle: "更新您的个人信息",
            editingData: "正在打开数据编辑器...",
            saveChangesButton: "💾 保存更改",
            cancelButton: "取消",
            dataUpdatedSuccess: "✅ 您的数据已成功更新",

            // Confirmations
            deleteConfirmTitle: "删除数据",
            deleteConfirmText: "您确定要删除所有数据吗？此操作无法撤销。",
            revokeConfirmTitle: "撤销同意",
            revokeConfirmText: "撤销同意后，聊天将不可用。您确定吗？",
            confirmButton: "是的，确认",
            cancelButton: "取消",

            // Success Messages
            consentSavedSuccess: "✓ 同意已保存",
            dataDeletedSuccess: "✓ 您的数据已成功删除",
            consentRevokedSuccess: "✓ 同意已撤销。聊天已禁用。",
            dataExportedSuccess: "✓ 数据已导出",
            historyCleared: "✓ 聊天历史已清除",
            formSubmittedSuccess: "✓ 表格已提交",

            // Error Messages
            consentRequired: "使用聊天需要同意",
            formValidationError: "请填写所有必填字段",
            webhookError: "处理请求时出错。请稍后重试。",
            networkError: "网络错误。请检查您的网络连接。",
            emailRequired: "此操作需要电子邮件",
            emailInvalid: "请输入有效的电子邮件地址",

            // Declined State
            declinedTitle: "同意已拒绝",
            declinedMessage: "您已拒绝数据处理同意。聊天不可用。",
            declinedReconsiderButton: "重新考虑",
            inputDisabledPlaceholder: "未经同意无法使用聊天",

            // Data View Modal
            dataViewTitle: "您的数据",
            dataViewEmpty: "没有保存的数据",
            dataViewLoading: "正在加载数据...",
            dataViewError: "无法加载数据",
            yourDataTitle: "您的数据",
            contactDataTitle: "联系信息",
            createdAtLabel: "创建日期",
            consentDataTitle: "同意信息",
            consentGivenLabel: "已给予同意",
            consentYes: "是",
            consentNo: "否",
            consentDateLabel: "同意日期",
            expiresAtLabel: "过期时间",
            domainLabel: "域名",
            chatHistoryTitle: "聊天记录",
            totalMessagesLabel: "消息数",
            noChatHistory: "聊天记录为空",
            you: "您",
            assistant: "助手",
            sessionInfoTitle: "会话信息",
            closeButton: "关闭",

            // Security Indicators
            securedBadge: "安全",
            gdprBadge: "GDPR",
            encryptedBadge: "已加密",
            aiBadge: "AI",

            // Data Retention Info
            retentionInfo: "您的数据按照我们的隐私政策存储",
            retentionDaysText: "数据保留期：{days}天",

            // HTTPS Warning
            httpsWarning: "⚠️ 为了安全，建议使用HTTPS连接",

            // Processing
            processingRequest: "正在处理请求...",
            pleaseWait: "请稍候...",

            // Advanced GDPR features
            confirmDeleteAllDataSecond: "这是您的最终确认。输入'DELETE'继续。",
            finalDeleteTitle: "⚠️ 最终确认",
            deleteInputPlaceholder: "输入DELETE",
            deleteInputError: "请输入DELETE以确认",
            deletionCancelled: "删除已取消",
            deletingIn: "将在{seconds}秒后删除...",
            cooldownActive: "请等待{hours}小时后再次请求删除。",
            exportLimitReached: "已达到导出限制（每天{max}次）。请明天再试。",
            exportingData: "正在准备数据导出...",
            requestingData: "正在请求您的数据...",
            dataExported: "数据导出成功",
            allDataDeleted: "所有数据已删除",
            confirmDeleteHistory: "您确定要删除聊天记录吗？",
            confirmDeleteAllData: "您确定要删除所有数据吗？此操作无法撤消。",
            historyDeleted: "聊天记录已删除",
            confirmRevokeConsent: "您确定要撤销同意吗？聊天将不再可用。",
            consentRevoked: "同意已撤销",
            consentDeclined: "同意已拒绝",
            consentActiveLabel: "同意有效",
            revokedAtLabel: "撤销日期",
            revokeReasonLabel: "撤销原因",
            confirmTitle: "确认",
            deleteHistoryTitle: "删除记录",
            revokeConsentTitle: "撤销同意",
            deleteAllDataTitle: "删除所有数据",
            deleteHistoryButton: "🗑️ 删除聊天记录",
            deleteAllDataButton: "🗑️ 删除我的所有数据"
        }
    },

    // 🇯🇵 ЯПОНСКИЙ ЯЗЫК
    ja: {
        interface: {
            minimize: "最小化",              
            expand: "展開",              
            placeholder: "メッセージを入力...", 
            voiceTooltip: "音声メッセージ", 
            sendTooltip: "メッセージを送信",  
            typingIndicator: "入力中",
            fileTooltip: "ファイルを添付",
            pasteImageHint: "画像を貼り付け (Ctrl+V)",
            fileUploading: "ファイルをアップロード中...",
            fileTooLarge: "ファイルが大きすぎます",
            fileTypeNotAllowed: "サポートされていないファイル形式",
            fileError: "ファイル処理エラー",
            selectLanguage: "言語を選択",
            switchSpecialist: "専門家を変更",
            contactUs: "お問い合わせ",
            popoutTooltip: "別のウィンドウで開く",
            selectedFile: "選択されたファイル：",
            removeFile: "ファイルを削除"
        },

commands: {
            voiceEnabled: "🎤 音声メッセージが有効になりました",
            voiceDisabled: "🔇 音声メッセージが無効になりました",
            //connectingManager: "🔄 マネージャーに接続中...",
           // managerConnected: "✅ マネージャーが接続されました",
            historyCleared: "🗑️ チャット履歴がクリアされました",
            languageChanged: "🌍 言語が日本語に変更されました",
            configSwitched: "🔄 切り替え先：",
            chatMinimized: "📌 チャットが最小化されました",
            chatExpanded: "📖 チャットが展開されました"
        
    },

        errors: {
            connectionError: "❌ サーバー接続エラー",
            fallbackMessage: "申し訳ございませんが、技術的な問題が発生しました。後でもう一度お試しください。",
            microphoneAccess: "❌ マイクへのアクセスなし",
            voiceProcessing: "❌ 音声処理エラー",
            // 🆕 新しいエラータイプ:
            timeoutError: "⏱️ タイムアウトしました。もう一度お試しください。",
            networkError: "🌐 ネットワークエラー。インターネット接続を確認してください。",
            licenseError: "🔒 ライセンスエラー。ページを更新してください。",
            authError: "🔒 認証エラー。ライセンスを確認してください。",
            dataSizeError: "📦 データサイズが大きすぎます。",
            badRequest: "⚠️ 無効なリクエスト。入力を確認してください。",
            serviceUnavailable: "🔍 サービスが利用できません。管理者に連絡してください。",
            rateLimitError: "⏳ リクエストが多すぎます。お待ちください。",
            serverError: "🔧 サーバーエラー。後でもう一度お試しください。",
            popupBlockedError: "ウィンドウを開けませんでした。ポップアップブロッカーの設定を確認してください。",
            dateError: "日付エラー"
        },

        system: {
            connecting: "接続中...",         
            voiceMessage: "🎤 音声メッセージ",
            switching: "切り替え中",
            nowServing: "現在サービス中",
            voiceMessageUnavailable: "🎤 音声メッセージ（利用不可）",
            voiceMessageExpired: "🎤 音声メッセージ（期限切れ）",
            voiceMessageError: "🎤 音声メッセージ（読み込みエラー）",
            videoMessage: "🎥 ビデオメッセージ",
            videoMessageError: "🎥 ビデオメッセージ（読み込みエラー）",
            videoMessageUnavailable: "🎥 ビデオメッセージ（利用不可）"
        },

        contacts: {
            title: "お問い合わせ",
            tooltip: "連絡先"
        },

        switcher: {
            tooltip: "専門家を変更"
        },

        quickButtons: {
            toggleShow: "クイックアクションを表示",
            toggleHide: "クイックアクションを非表示",
            title: "クイックアクション"
        },

        datetime: {
            today: "今日",
            yesterday: "昨日",
            timeFormat: "24h",
            months: [
                "1月", "2月", "3月", "4月", "5月", "6月",
                "7月", "8月", "9月", "10月", "11月", "12月"
            ],
            monthsFull: [
                "一月", "二月", "三月", "四月", "五月", "六月",
                "七月", "八月", "九月", "十月", "十一月", "十二月"
            ],
            weekdays: [
                "日", "月", "火", "水", "木", "金", "土"
            ],
            weekdaysFull: [
                "日曜日", "月曜日", "火曜日", "水曜日",
                "木曜日", "金曜日", "土曜日"
            ]
        },

        // 🆕 レート制限の新しいセクション
        rateLimiting: {
            tooManyMessages: "⏳ メッセージが多すぎます。1分間に最大{max}件のメッセージ。"
        },

        // 🆕 フォールバックテキストの新しいセクション
        fallback: {
            assistant: "アシスタント",
            welcome: "ようこそ！",
            defaultUserName: "ユーザー"
        },

        // 🔐 GDPRとプライバシー
        gdpr: {
            // Consent Banner
            consentTitle: "🔒 プライバシーとCookie",
            consentText: "このチャットを使用してリクエストを処理します。お客様のデータはプライバシーポリシーに従って処理されます。",
            consentTextAI: "AIアシスタントとチャットします。メッセージは人工知能によって処理されます。",
            consentTextMonitoring: "会話はサービス品質向上のために分析される場合があります。",
            acceptButton: "同意して続行",
            declineButton: "拒否",
            privacyLinkText: "プライバシーポリシー",
            cookieLinkText: "Cookieポリシー",
            termsLinkText: "利用規約",

            // Standard mode UI
            continueWithoutAcceptButton: "同意せずに続行",
            standardModeNote: "🔒アイコンからいつでもプライバシー設定を管理できます。",
            dismissBannerTooltip: "閉じる（後で設定を管理）",

            // Pre-Chat Form
            formTitle: "会話を開始",
            formSubtitle: "チャットを開始する前にフォームに記入してください",
            nameLabel: "お名前",
            namePlaceholder: "お名前を入力",
            emailLabel: "メールアドレス",
            emailPlaceholder: "メールアドレスを入力",
            phoneLabel: "電話番号",
            phonePlaceholder: "電話番号を入力",
            companyLabel: "会社名",
            companyPlaceholder: "会社名",
            requiredFieldMark: "* - 必須項目",
            gdprCheckboxText: "個人データの処理に同意します",
            startChatButton: "チャットを開始",
            piiIndicator: "🔒 個人データ",

            // AI Disclosure
            aiDisclosureTitle: "AIアシスタント",
            aiDisclosureMessage: "🤖 AIアシスタントとチャットしています。当社のAIは迅速で効率的なサポートのために設計されています。正確性を目指していますが、エラーが発生する場合があります。",
            aiDisclosureBadge: "AI",

            // Privacy Controls Menu
            privacyMenuTitle: "🔐 プライバシー設定",
            viewDataButton: "👁️ マイデータを表示",
            editDataButton: "✏️ データを編集",
            exportDataButton: "📥 データをエクスポート",
            deleteDataButton: "🗑️ すべてのデータを削除",
            revokeConsentButton: "⛔ 同意を撤回",
            downloadTranscriptButton: "💬 会話をダウンロード",
            clearHistoryButton: "🧹 履歴をクリア",
            // データを編集
            editFormTitle: "✏️ データを編集",
            editFormSubtitle: "個人情報を更新する",
            editingData: "データエディタを開いています...",
            saveChangesButton: "💾 変更を保存",
            cancelButton: "キャンセル",
            dataUpdatedSuccess: "✅ データが正常に更新されました",

            // Confirmations
            deleteConfirmTitle: "データを削除",
            deleteConfirmText: "すべてのデータを削除してもよろしいですか？この操作は元に戻せません。",
            revokeConfirmTitle: "同意を撤回",
            revokeConfirmText: "同意を撤回すると、チャットは利用できなくなります。よろしいですか？",
            confirmButton: "はい、確認",
            cancelButton: "キャンセル",

            // Success Messages
            consentSavedSuccess: "✓ 同意が保存されました",
            dataDeletedSuccess: "✓ データが正常に削除されました",
            consentRevokedSuccess: "✓ 同意が撤回されました。チャットは無効です。",
            dataExportedSuccess: "✓ データがエクスポートされました",
            historyCleared: "✓ チャット履歴がクリアされました",
            formSubmittedSuccess: "✓ フォームが送信されました",

            // Error Messages
            consentRequired: "チャットを使用するには同意が必要です",
            formValidationError: "すべての必須項目を入力してください",
            webhookError: "リクエストの処理中にエラーが発生しました。後でもう一度お試しください。",
            networkError: "ネットワークエラー。インターネット接続を確認してください。",
            emailRequired: "このアクションにはメールアドレスが必要です",
            emailInvalid: "有効なメールアドレスを入力してください",

            // Declined State
            declinedTitle: "同意が拒否されました",
            declinedMessage: "データ処理への同意を拒否しました。チャットは利用できません。",
            declinedReconsiderButton: "再考する",
            inputDisabledPlaceholder: "同意なしではチャットを利用できません",

            // Data View Modal
            dataViewTitle: "お客様のデータ",
            dataViewEmpty: "保存されているデータはありません",
            dataViewLoading: "データを読み込み中...",
            dataViewError: "データを読み込めませんでした",
            yourDataTitle: "お客様のデータ",
            contactDataTitle: "連絡先情報",
            createdAtLabel: "作成日",
            consentDataTitle: "同意情報",
            consentGivenLabel: "同意済み",
            consentYes: "はい",
            consentNo: "いいえ",
            consentDateLabel: "同意日",
            expiresAtLabel: "有効期限",
            domainLabel: "ドメイン",
            chatHistoryTitle: "チャット履歴",
            totalMessagesLabel: "メッセージ数",
            noChatHistory: "チャット履歴は空です",
            you: "あなた",
            assistant: "アシスタント",
            sessionInfoTitle: "セッション情報",
            closeButton: "閉じる",

            // Security Indicators
            securedBadge: "保護",
            gdprBadge: "GDPR",
            encryptedBadge: "暗号化",
            aiBadge: "AI",

            // Data Retention Info
            retentionInfo: "お客様のデータはプライバシーポリシーに従って保存されます",
            retentionDaysText: "データ保持期間：{days}日",

            // HTTPS Warning
            httpsWarning: "⚠️ セキュリティのため、HTTPS接続の使用をお勧めします",

            // Processing
            processingRequest: "リクエストを処理中...",
            pleaseWait: "お待ちください...",

            // Advanced GDPR features
            confirmDeleteAllDataSecond: "これは最終確認です。続行するには'DELETE'と入力してください。",
            finalDeleteTitle: "⚠️ 最終確認",
            deleteInputPlaceholder: "DELETEと入力",
            deleteInputError: "確認のためDELETEと入力してください",
            deletionCancelled: "削除がキャンセルされました",
            deletingIn: "{seconds}秒後に削除します...",
            cooldownActive: "再度削除をリクエストする前に{hours}時間お待ちください。",
            exportLimitReached: "エクスポート上限に達しました（1日{max}回）。明日再度お試しください。",
            exportingData: "データエクスポートを準備中...",
            requestingData: "データをリクエスト中...",
            dataExported: "データが正常にエクスポートされました",
            allDataDeleted: "すべてのデータが削除されました",
            confirmDeleteHistory: "チャット履歴を削除してもよろしいですか？",
            confirmDeleteAllData: "すべてのデータを削除してもよろしいですか？この操作は元に戻せません。",
            historyDeleted: "チャット履歴が削除されました",
            confirmRevokeConsent: "同意を撤回してもよろしいですか？チャットは利用できなくなります。",
            consentRevoked: "同意が撤回されました",
            consentDeclined: "同意が拒否されました",
            consentActiveLabel: "同意が有効",
            revokedAtLabel: "撤回日",
            revokeReasonLabel: "撤回理由",
            confirmTitle: "確認",
            deleteHistoryTitle: "履歴を削除",
            revokeConsentTitle: "同意を撤回",
            deleteAllDataTitle: "すべてのデータを削除",
            deleteHistoryButton: "🗑️ チャット履歴を削除",
            deleteAllDataButton: "🗑️ すべてのデータを削除"
        }
    },

    // 🇰🇷 КОРЕЙСКИЙ ЯЗЫК
    ko: {
        interface: {
            minimize: "최소화",              
            expand: "확장",              
            placeholder: "메시지 입력...", 
            voiceTooltip: "음성 메시지", 
            sendTooltip: "메시지 전송",  
            typingIndicator: "입력 중",
            fileTooltip: "파일 첨부",
            pasteImageHint: "이미지 붙여넣기 (Ctrl+V)",
            fileUploading: "파일 업로드 중...",
            fileTooLarge: "파일이 너무 큽니다",
            fileTypeNotAllowed: "지원되지 않는 파일 형식",
            fileError: "파일 처리 오류",
            selectLanguage: "언어 선택",
            switchSpecialist: "전문가 변경",
            contactUs: "문의하기",
            popoutTooltip: "별도의 창에서 열기",
            selectedFile: "선택된 파일:",
             removeFile: "파일 제거"
        },

commands: {
            voiceEnabled: "🎤 음성 메시지 활성화됨",
            voiceDisabled: "🔇 음성 메시지 비활성화됨",
           // connectingManager: "🔄 매니저에 연결 중...",
            //managerConnected: "✅ 매니저 연결됨",
            historyCleared: "🗑️ 채팅 기록이 삭제되었습니다",
            languageChanged: "🌍 언어가 한국어로 변경되었습니다",
            configSwitched: "🔄 전환됨:",
            chatMinimized: "📌 채팅 최소화됨",
            chatExpanded: "📖 채팅 확장됨"
        
    },

        errors: {
            connectionError: "❌ 서버 연결 오류",
            fallbackMessage: "죄송합니다. 기술적인 문제가 발생했습니다. 나중에 다시 시도해 주세요.",
            microphoneAccess: "❌ 마이크 액세스 없음",
            voiceProcessing: "❌ 음성 처리 오류",
            // 🆕 새로운 오류 유형:
            timeoutError: "⏱️ 시간 초과. 다시 시도하세요.",
            networkError: "🌐 네트워크 오류. 인터넷 연결을 확인하세요.",
            licenseError: "🔒 라이선스 오류. 페이지를 새로 고침하세요.",
            authError: "🔒 인증 오류. 라이선스를 확인하세요.",
            dataSizeError: "📦 데이터 크기가 너무 큽니다.",
            badRequest: "⚠️ 잘못된 요청. 입력을 확인하세요.",
            serviceUnavailable: "🔍 서비스를 사용할 수 없습니다. 관리자에게 문의하세요.",
            rateLimitError: "⏳ 요청이 너무 많습니다. 잠시 기다려 주세요.",
            serverError: "🔧 서버 오류. 나중에 다시 시도해 주세요.",
            popupBlockedError: "창을 열 수 없습니다. 팝업 차단 설정을 확인하세요.",
            dateError: "날짜 오류"
        },

        system: {
            connecting: "연결 중...",         
            voiceMessage: "🎤 음성 메시지",
            switching: "전환 중",
            nowServing: "현재 서비스 중",
            voiceMessageUnavailable: "🎤 음성 메시지 (사용 불가)",
            voiceMessageExpired: "🎤 음성 메시지 (만료됨)",
            voiceMessageError: "🎤 음성 메시지 (로드 오류)",
            videoMessage: "🎥 영상 메시지",
            videoMessageError: "🎥 영상 메시지 (로딩 오류)",
            videoMessageUnavailable: "🎥 영상 메시지 (사용 불가)"
        },

        contacts: {
            title: "문의하기",
            tooltip: "연락처"
        },

        switcher: {
            tooltip: "전문가 변경"
        },

        quickButtons: {
            toggleShow: "빠른 작업 표시",
            toggleHide: "빠른 작업 숨기기",
            title: "빠른 작업"
        },

        datetime: {
            today: "오늘",
            yesterday: "어제",
            timeFormat: "24h",
            months: [
                "1월", "2월", "3월", "4월", "5월", "6월",
                "7월", "8월", "9월", "10월", "11월", "12월"
            ],
            monthsFull: [
                "1월", "2월", "3월", "4월", "5월", "6월",
                "7월", "8월", "9월", "10월", "11월", "12월"
            ],
            weekdays: [
                "일", "월", "화", "수", "목", "금", "토"
            ],
            weekdaysFull: [
                "일요일", "월요일", "화요일", "수요일",
                "목요일", "금요일", "토요일"
            ]
        },

        // 🆕 속도 제한을 위한 새로운 섹션
        rateLimiting: {
            tooManyMessages: "⏳ 메시지가 너무 많습니다. 분당 최대 {max}개 메시지."
        },

        // 🆕 대체 텍스트를 위한 새로운 섹션
        fallback: {
            assistant: "어시스턴트",
            welcome: "환영합니다!",
            defaultUserName: "사용자"
        },

        // 🔐 GDPR 및 개인정보 보호
        gdpr: {
            // Consent Banner
            consentTitle: "🔒 개인정보 보호 및 쿠키",
            consentText: "이 채팅을 통해 귀하의 요청을 처리합니다. 귀하의 데이터는 개인정보 보호정책에 따라 처리됩니다.",
            consentTextAI: "AI 어시스턴트와 채팅하게 됩니다. 귀하의 메시지는 인공지능으로 처리됩니다.",
            consentTextMonitoring: "대화는 서비스 품질 향상을 위해 분석될 수 있습니다.",
            acceptButton: "동의 및 계속",
            declineButton: "거부",
            privacyLinkText: "개인정보 보호정책",
            cookieLinkText: "쿠키 정책",
            termsLinkText: "서비스 약관",

            // Standard mode UI
            continueWithoutAcceptButton: "동의 없이 계속",
            standardModeNote: "🔒 아이콘을 통해 언제든지 개인정보 설정을 관리할 수 있습니다.",
            dismissBannerTooltip: "닫기 (나중에 설정 관리)",

            // Pre-Chat Form
            formTitle: "대화 시작",
            formSubtitle: "채팅을 시작하기 전에 양식을 작성해 주세요",
            nameLabel: "이름",
            namePlaceholder: "이름을 입력하세요",
            emailLabel: "이메일",
            emailPlaceholder: "이메일을 입력하세요",
            phoneLabel: "전화번호",
            phonePlaceholder: "전화번호를 입력하세요",
            companyLabel: "회사",
            companyPlaceholder: "회사명",
            requiredFieldMark: "* - 필수 항목",
            gdprCheckboxText: "개인 데이터 처리에 동의합니다",
            startChatButton: "채팅 시작",
            piiIndicator: "🔒 개인 데이터",

            // AI Disclosure
            aiDisclosureTitle: "AI 어시스턴트",
            aiDisclosureMessage: "🤖 AI 어시스턴트와 채팅 중입니다. 저희 AI는 빠르고 효율적인 지원을 위해 설계되었습니다. 정확성을 위해 노력하지만 때때로 오류가 발생할 수 있습니다.",
            aiDisclosureBadge: "AI",

            // Privacy Controls Menu
            privacyMenuTitle: "🔐 개인정보 설정",
            viewDataButton: "👁️ 내 데이터 보기",
            editDataButton: "✏️ 데이터 편집",
            exportDataButton: "📥 데이터 내보내기",
            deleteDataButton: "🗑️ 모든 데이터 삭제",
            revokeConsentButton: "⛔ 동의 철회",
            downloadTranscriptButton: "💬 대화 다운로드",
            clearHistoryButton: "🧹 기록 삭제",
            // 데이터 편집
            editFormTitle: "✏️ 데이터 편집",
            editFormSubtitle: "개인 정보를 업데이트하세요",
            editingData: "데이터 편집기를 여는 중...",
            saveChangesButton: "💾 변경 사항 저장",
            cancelButton: "취소",
            dataUpdatedSuccess: "✅ 데이터가 성공적으로 업데이트되었습니다",

            // Confirmations
            deleteConfirmTitle: "데이터 삭제",
            deleteConfirmText: "모든 데이터를 삭제하시겠습니까? 이 작업은 되돌릴 수 없습니다.",
            revokeConfirmTitle: "동의 철회",
            revokeConfirmText: "동의를 철회하면 채팅을 사용할 수 없습니다. 확실합니까?",
            confirmButton: "예, 확인",
            cancelButton: "취소",

            // Success Messages
            consentSavedSuccess: "✓ 동의가 저장되었습니다",
            dataDeletedSuccess: "✓ 데이터가 성공적으로 삭제되었습니다",
            consentRevokedSuccess: "✓ 동의가 철회되었습니다. 채팅이 비활성화되었습니다.",
            dataExportedSuccess: "✓ 데이터가 내보내졌습니다",
            historyCleared: "✓ 채팅 기록이 삭제되었습니다",
            formSubmittedSuccess: "✓ 양식이 제출되었습니다",

            // Error Messages
            consentRequired: "채팅을 사용하려면 동의가 필요합니다",
            formValidationError: "모든 필수 항목을 입력해 주세요",
            webhookError: "요청 처리 중 오류가 발생했습니다. 나중에 다시 시도해 주세요.",
            networkError: "네트워크 오류입니다. 인터넷 연결을 확인해 주세요.",
            emailRequired: "이 작업에는 이메일이 필요합니다",
            emailInvalid: "유효한 이메일 주소를 입력해 주세요",

            // Declined State
            declinedTitle: "동의 거부됨",
            declinedMessage: "데이터 처리에 대한 동의를 거부했습니다. 채팅을 사용할 수 없습니다.",
            declinedReconsiderButton: "다시 고려",
            inputDisabledPlaceholder: "동의 없이 채팅을 사용할 수 없습니다",

            // Data View Modal
            dataViewTitle: "귀하의 데이터",
            dataViewEmpty: "저장된 데이터가 없습니다",
            dataViewLoading: "데이터 로딩 중...",
            dataViewError: "데이터를 로드할 수 없습니다",
            yourDataTitle: "귀하의 데이터",
            contactDataTitle: "연락처 정보",
            createdAtLabel: "생성일",
            consentDataTitle: "동의 정보",
            consentGivenLabel: "동의 완료",
            consentYes: "예",
            consentNo: "아니오",
            consentDateLabel: "동의 날짜",
            expiresAtLabel: "만료",
            domainLabel: "도메인",
            chatHistoryTitle: "채팅 기록",
            totalMessagesLabel: "메시지 수",
            noChatHistory: "채팅 기록이 비어 있습니다",
            you: "당신",
            assistant: "어시스턴트",
            sessionInfoTitle: "세션 정보",
            closeButton: "닫기",

            // Security Indicators
            securedBadge: "보안",
            gdprBadge: "GDPR",
            encryptedBadge: "암호화",
            aiBadge: "AI",

            // Data Retention Info
            retentionInfo: "귀하의 데이터는 개인정보 보호정책에 따라 저장됩니다",
            retentionDaysText: "데이터 보존 기간: {days}일",

            // HTTPS Warning
            httpsWarning: "⚠️ 보안을 위해 HTTPS 연결 사용을 권장합니다",

            // Processing
            processingRequest: "요청 처리 중...",
            pleaseWait: "잠시 기다려 주세요...",

            // Advanced GDPR features
            confirmDeleteAllDataSecond: "최종 확인입니다. 계속하려면 'DELETE'를 입력하세요.",
            finalDeleteTitle: "⚠️ 최종 확인",
            deleteInputPlaceholder: "DELETE 입력",
            deleteInputError: "확인을 위해 DELETE를 입력하세요",
            deletionCancelled: "삭제가 취소되었습니다",
            deletingIn: "{seconds}초 후 삭제됩니다...",
            cooldownActive: "다시 삭제를 요청하려면 {hours}시간을 기다려 주세요.",
            exportLimitReached: "내보내기 한도에 도달했습니다(하루 {max}회). 내일 다시 시도하세요.",
            exportingData: "데이터 내보내기 준비 중...",
            requestingData: "데이터를 요청 중...",
            dataExported: "데이터가 성공적으로 내보내졌습니다",
            allDataDeleted: "모든 데이터가 삭제되었습니다",
            confirmDeleteHistory: "채팅 기록을 삭제하시겠습니까?",
            confirmDeleteAllData: "모든 데이터를 삭제하시겠습니까? 이 작업은 취소할 수 없습니다.",
            historyDeleted: "채팅 기록이 삭제되었습니다",
            confirmRevokeConsent: "동의를 철회하시겠습니까? 채팅을 더 이상 사용할 수 없습니다.",
            consentRevoked: "동의가 철회되었습니다",
            consentDeclined: "동의가 거부되었습니다",
            consentActiveLabel: "동의 활성화됨",
            revokedAtLabel: "철회 날짜",
            revokeReasonLabel: "철회 사유",
            confirmTitle: "확인",
            deleteHistoryTitle: "기록 삭제",
            revokeConsentTitle: "동의 철회",
            deleteAllDataTitle: "모든 데이터 삭제",
            deleteHistoryButton: "🗑️ 채팅 기록 삭제",
            deleteAllDataButton: "🗑️ 내 모든 데이터 삭제"
        }
    },

    // 🇺🇦 УКРАИНСКИЙ ЯЗЫК
    ua: {
        interface: {
            minimize: "Згорнути",              
            expand: "Розгорнути",              
            placeholder: "Введіть повідомлення...", 
            voiceTooltip: "Голосове повідомлення", 
            sendTooltip: "Надіслати повідомлення",  
            typingIndicator: "Відповідаю",
            fileTooltip: "Прикріпити файл",
            pasteImageHint: "Вставте зображення (Ctrl+V)",
            fileUploading: "Надсилаємо файл...",
            fileTooLarge: "Файл занадто великий",
            fileTypeNotAllowed: "Тип файлу не підтримується",
            fileError: "Помилка обробки файлу",
            selectLanguage: "Вибрати мову",
            switchSpecialist: "Змінити спеціаліста",
            contactUs: "Зв'язатися з нами",
            popoutTooltip: "Відкрити в окремому вікні",
            selectedFile: "Вибраний файл:",
            removeFile: "Прибрати файл"
        },

commands: {
            voiceEnabled: "🎤 Голосові повідомлення увімкнено",
            voiceDisabled: "🔇 Голосові повідомлення вимкнено",
            //connectingManager: "🔄 З'єдную з менеджером...",
           //managerConnected: "✅ Менеджер підключений",
            historyCleared: "🗑️ Історію чату очищено",
            languageChanged: "🌍 Мову змінено на українську",
            configSwitched: "🔄 Переключено на",
            chatMinimized: "📌 Чат згорнуто",
            chatExpanded: "📖 Чат розгорнуто"
        },

        errors: {
            connectionError: "❌ Помилка підключення до сервера",
            fallbackMessage: "Вибачте, виникла технічна проблема. Спробуйте пізніше.",
            microphoneAccess: "❌ Немає доступу до мікрофона",
            voiceProcessing: "❌ Помилка обробки голосового повідомлення",
            // 🆕 Нові типи помилок:
            timeoutError: "⏱️ Перевищено час очікування. Спробуйте ще раз.",
            networkError: "🌐 Помилка мережі. Перевірте підключення до інтернету.",
            licenseError: "🔒 Помилка ліцензії. Оновіть сторінку.",
            authError: "🔒 Помилка авторизації. Перевірте вашу ліцензію.",
            dataSizeError: "📦 Розмір даних занадто великий.",
            badRequest: "⚠️ Некоректний запит. Перевірте ваш ввід.",
            serviceUnavailable: "🔍 Сервіс недоступний. Зверніться до адміністратора.",
            rateLimitError: "⏳ Забагато запитів. Будь ласка, зачекайте.",
            serverError: "🔧 Помилка сервера. Спробуйте пізніше.",
            popupBlockedError: "Не вдалося відкрити вікно. Перевірте налаштування блокувальника спливаючих вікон.",
            dateError: "Помилка дати"
        },

        system: {
            connecting: "Підключаюся...",         
            voiceMessage: "🎤 Голосове повідомлення",
            switching: "Переключаюся на",
            nowServing: "Тепер вас обслуговує",
            voiceMessageUnavailable: "🎤 Голосове повідомлення (недоступне)",
            voiceMessageExpired: "🎤 Голосове повідомлення (термін зберігання закінчився)",
            voiceMessageError: "🎤 Голосове повідомлення (помилка завантаження)",
            videoMessage: "🎥 Відеоповідомлення",
            videoMessageError: "🎥 Відеоповідомлення (помилка завантаження)",
            videoMessageUnavailable: "🎥 Відеоповідомлення (недоступно)"
        },

        contacts: {
            title: "Зв'язатися з нами",
            tooltip: "Контакти"
        },

        switcher: {
            tooltip: "Змінити спеціаліста"
        },

        quickButtons: {
            toggleShow: "Показати швидкі команди",
            toggleHide: "Сховати швидкі команди",
            title: "Швидкі команди"
        },

        datetime: {
            today: "Сьогодні",
            yesterday: "Вчора",
            timeFormat: "24h",
            months: [
                "січ", "лют", "бер", "кві", "тра", "чер",
                "лип", "сер", "вер", "жов", "лис", "гру"
            ],
            monthsFull: [
                "січня", "лютого", "березня", "квітня", "травня", "червня",
                "липня", "серпня", "вересня", "жовтня", "листопада", "грудня"
            ],
            weekdays: [
                "Нд", "Пн", "Вт", "Ср", "Чт", "Пт", "Сб"
            ],
            weekdaysFull: [
                "неділя", "понеділок", "вівторок", "середа",
                "четвер", "п'ятниця", "субота"
            ]
        },

        // 🆕 Нова секція для обмеження швидкості
        rateLimiting: {
            tooManyMessages: "⏳ Забагато повідомлень. Максимум {max} повідомлень за хвилину."
        },

        // 🆕 Нова секція для резервних текстів
        fallback: {
            assistant: "Помічник",
            welcome: "Ласкаво просимо!",
            defaultUserName: "Користувач"
        },

        // 🔐 GDPR та Конфіденційність
        gdpr: {
            // Consent Banner
            consentTitle: "🔒 Конфіденційність та Cookies",
            consentText: "Ми використовуємо цей чат для обробки ваших запитів. Ваші дані будуть оброблені відповідно до нашої політики конфіденційності.",
            consentTextAI: "Ви будете спілкуватися з AI-асистентом. Ваші повідомлення обробляються за допомогою штучного інтелекту.",
            consentTextMonitoring: "Діалоги можуть аналізуватися для покращення якості сервісу.",
            acceptButton: "Прийняти та продовжити",
            declineButton: "Відхилити",
            privacyLinkText: "Політика конфіденційності",
            cookieLinkText: "Політика Cookies",
            termsLinkText: "Умови використання",

            // Standard mode UI
            continueWithoutAcceptButton: "Продовжити без прийняття",
            standardModeNote: "Ви можете керувати налаштуваннями конфіденційності у будь-який час через іконку 🔒.",
            dismissBannerTooltip: "Закрити (налаштувати пізніше)",

            // Pre-Chat Form
            formTitle: "Почати розмову",
            formSubtitle: "Будь ласка, заповніть форму перед початком чату",
            nameLabel: "Ваше ім'я",
            namePlaceholder: "Введіть ваше ім'я",
            emailLabel: "Email",
            emailPlaceholder: "Введіть ваш email",
            phoneLabel: "Телефон",
            phonePlaceholder: "Введіть номер телефону",
            companyLabel: "Компанія",
            companyPlaceholder: "Назва компанії",
            requiredFieldMark: "* - обов'язкове поле",
            gdprCheckboxText: "Я погоджуюсь на обробку моїх персональних даних",
            startChatButton: "Почати чат",
            piiIndicator: "🔒 Персональні дані",

            // AI Disclosure
            aiDisclosureTitle: "AI Асистент",
            aiDisclosureMessage: "🤖 Ви спілкуєтесь з AI-асистентом. Наш AI розроблений для швидкої та ефективної допомоги. Хоча ми прагнемо до точності, іноді можуть бути помилки.",
            aiDisclosureBadge: "AI",

            // Privacy Controls Menu
            privacyMenuTitle: "🔐 Налаштування конфіденційності",
            viewDataButton: "👁️ Переглянути мої дані",
            editDataButton: "✏️ Редагувати дані",
            exportDataButton: "📥 Експортувати дані",
            deleteDataButton: "🗑️ Видалити всі дані",
            revokeConsentButton: "⛔ Відкликати згоду",
            downloadTranscriptButton: "💬 Завантажити переписку",
            clearHistoryButton: "🧹 Очистити історію",
            // Редагування даних
            editFormTitle: "✏️ Редагування даних",
            editFormSubtitle: "Оновіть вашу персональну інформацію",
            editingData: "Відкриваємо редактор даних...",
            saveChangesButton: "💾 Зберегти зміни",
            cancelButton: "Скасувати",
            dataUpdatedSuccess: "✅ Ваші дані успішно оновлено",

            // Confirmations
            deleteConfirmTitle: "Видалення даних",
            deleteConfirmText: "Ви впевнені, що хочете видалити всі ваші дані? Ця дія незворотна.",
            revokeConfirmTitle: "Відкликання згоди",
            revokeConfirmText: "Після відкликання згоди чат буде недоступний. Ви впевнені?",
            confirmButton: "Так, підтверджую",
            cancelButton: "Скасувати",

            // Success Messages
            consentSavedSuccess: "✓ Згоду збережено",
            dataDeletedSuccess: "✓ Ваші дані успішно видалено",
            consentRevokedSuccess: "✓ Згоду відкликано. Чат вимкнено.",
            dataExportedSuccess: "✓ Дані експортовано",
            historyCleared: "✓ Історію чату очищено",
            formSubmittedSuccess: "✓ Форму надіслано",

            // Error Messages
            consentRequired: "Необхідна згода для використання чату",
            formValidationError: "Будь ласка, заповніть всі обов'язкові поля",
            webhookError: "Помилка при обробці запиту. Спробуйте пізніше.",
            networkError: "Помилка мережі. Перевірте підключення до інтернету.",
            emailRequired: "Email обов'язковий для цієї дії",
            emailInvalid: "Введіть коректну email адресу",

            // Declined State
            declinedTitle: "Згоду відхилено",
            declinedMessage: "Ви відхилили згоду на обробку даних. Чат недоступний.",
            declinedReconsiderButton: "Переглянути рішення",
            inputDisabledPlaceholder: "Чат недоступний без згоди",

            // Data View Modal
            dataViewTitle: "Ваші дані",
            dataViewEmpty: "Немає збережених даних",
            dataViewLoading: "Завантаження даних...",
            dataViewError: "Не вдалося завантажити дані",
            yourDataTitle: "Ваші дані",
            contactDataTitle: "Контактна інформація",
            createdAtLabel: "Дата створення",
            consentDataTitle: "Інформація про згоду",
            consentGivenLabel: "Згода надана",
            consentYes: "Так",
            consentNo: "Ні",
            consentDateLabel: "Дата згоди",
            expiresAtLabel: "Закінчується",
            domainLabel: "Домен",
            chatHistoryTitle: "Історія чату",
            totalMessagesLabel: "Повідомлень",
            noChatHistory: "Історія чату порожня",
            you: "Ви",
            assistant: "Асистент",
            sessionInfoTitle: "Інформація про сесію",
            closeButton: "Закрити",

            // Security Indicators
            securedBadge: "Захищено",
            gdprBadge: "GDPR",
            encryptedBadge: "Зашифровано",
            aiBadge: "AI",

            // Data Retention Info
            retentionInfo: "Ваші дані зберігаються відповідно до нашої політики конфіденційності",
            retentionDaysText: "Термін зберігання даних: {days} днів",

            // HTTPS Warning
            httpsWarning: "⚠️ Для безпеки рекомендується використовувати HTTPS з'єднання",

            // Processing
            processingRequest: "Обробляємо запит...",
            pleaseWait: "Будь ласка, зачекайте...",

            // Advanced GDPR features
            confirmDeleteAllDataSecond: "Це ОСТАТОЧНЕ підтвердження. Введіть 'DELETE' для продовження.",
            finalDeleteTitle: "⚠️ Остаточне підтвердження",
            deleteInputPlaceholder: "Введіть DELETE",
            deleteInputError: "Будь ласка, введіть DELETE для підтвердження",
            deletionCancelled: "Видалення скасовано",
            deletingIn: "Видалення через {seconds} секунд...",
            cooldownActive: "Будь ласка, зачекайте {hours} годин(и) перед повторним запитом на видалення.",
            exportLimitReached: "Досягнуто ліміту експорту ({max} на день). Спробуйте завтра.",
            exportingData: "Підготовка експорту даних...",
            requestingData: "Запит ваших даних...",
            dataExported: "Дані успішно експортовано",
            allDataDeleted: "Усі дані видалено",
            confirmDeleteHistory: "Ви впевнені, що хочете видалити історію чату?",
            confirmDeleteAllData: "Ви впевнені, що хочете видалити ВСІ ваші дані? Цю дію неможливо скасувати.",
            historyDeleted: "Історію чату видалено",
            confirmRevokeConsent: "Ви впевнені, що хочете відкликати згоду? Чат стане недоступним.",
            consentRevoked: "Згоду відкликано",
            consentDeclined: "Згоду відхилено",
            consentActiveLabel: "Згода активна",
            revokedAtLabel: "Дата відкликання",
            revokeReasonLabel: "Причина відкликання",
            confirmTitle: "Підтвердження",
            deleteHistoryTitle: "Видалити історію",
            revokeConsentTitle: "Відкликати згоду",
            deleteAllDataTitle: "Видалити всі дані",
            deleteHistoryButton: "🗑️ Видалити історію чату",
            deleteAllDataButton: "🗑️ Видалити всі мої дані"
        }
    }
};

// ===============================================
// ФУНКЦИЯ ПОЛУЧЕНИЯ БАЗОВЫХ ТЕКСТОВ ПО ЯЗЫКУ
// ===============================================
function getBaseInterfaceTexts(language = 'ru') {
    return baseInterfaceTexts[language] || baseInterfaceTexts.ru;
}

// ===============================================
// ФУНКЦИЯ ПРАВИЛЬНОГО СЛИЯНИЯ НАСТРОЕК
// ===============================================
function mergeConfigs(individualConfig, baseConfig, methods) {
    const prioritySettings = GlobalConfigSettings.prioritySettings;
    
    // ✅ НОВОЕ: Проверяем индивидуальную настройку конфигурации
    const useIndividual = individualConfig.useIndividualSettings !== undefined 
        ? individualConfig.useIndividualSettings 
        : prioritySettings.useIndividualSettings;
    
    // Если НЕ используем индивидуальные настройки для этой конфигурации
    if (!useIndividual) {
        // Заменяем behavior и appearance на базовые
        if (individualConfig.behavior) {
            individualConfig.behavior = baseConfig.behavior;
        }
        if (individualConfig.appearance) {
            individualConfig.appearance = baseConfig.appearance;
        }
        if (individualConfig.technical) {
            individualConfig.technical = baseConfig.technical;
        }
    }
    
    // Дальше обычное слияние
    if (prioritySettings.allowPartialOverride) {
        // Частичное переопределение - объединяем все через deepMerge
        return deepMerge(baseConfig, individualConfig, methods);
    } else {
        // Полное переопределение - берем только individualConfig,
        // НО критически важные параметры всегда наследуем из baseConfig
        const result = Object.assign({}, individualConfig, methods);

        // ✅ Критически важные параметры, которые должны быть всегда
        const criticalParams = ['monitoring', 'technical', 'userInfo'];

        // Вспомогательная функция для проверки корректности критического параметра
        function isValidCriticalParam(value, paramName) {
            if (!value || typeof value !== 'object') return false;

            // Специфичные проверки для каждого критического параметра
            if (paramName === 'monitoring') {
                // monitoring должен иметь endpoint
                return value.endpoint && value.endpoint.trim().length > 0;
            }
            if (paramName === 'technical') {
                // technical должен иметь хотя бы одно свойство
                return Object.keys(value).length > 0;
            }
            if (paramName === 'userInfo') {
                // userInfo должен иметь языковые настройки
                return Object.keys(value).length > 0;
            }

            return true;
        }

        criticalParams.forEach(param => {
            // ✅ ИСПРАВЛЕНИЕ: Проверяем не только наличие свойства, но и его корректность
            const hasParam = individualConfig.hasOwnProperty(param);
            const isValid = hasParam && isValidCriticalParam(individualConfig[param], param);

            if (!hasParam || !isValid) {
                if (baseConfig[param]) {
                    result[param] = baseConfig[param];
                }
            }
        });

        return result;
    }
}

// Вспомогательная функция глубокого слияния
function deepMerge(...objects) {
    const result = {};
    
    objects.forEach(obj => {
        if (obj) {
            Object.keys(obj).forEach(key => {
                if (obj[key] && typeof obj[key] === 'object' && !Array.isArray(obj[key])) {
                    result[key] = deepMerge(result[key] || {}, obj[key]);
                } else {
                    result[key] = obj[key];
                }
            });
        }
    });
    
    return result;
}

// ===============================================
// БАЗОВЫЕ НАСТРОЙКИ (ПЕРЕИСПОЛЬЗУЕМЫЕ)
// ===============================================
const baseConfig = {
    behavior: {
        autoOpen: false,
        autoOpenDelay: 10000,
        autoFocus: true,
        showWelcome: false,
        showQuickButtons: true,
        quickButtonsCollapsed: true,
        enableVoice: true,
        enableFileUpload: true,
        enablePasteImages: true,
        showInputArea: true,
        saveHistory: true,
        historyLifetime: 72,
        maxHistoryMessages: 50,
        enablePopoutMode: true,
        popoutWindowSize: {
            width: 500,
            height: 770
        }
    },
    appearance: {
        position: "bottom-right",
        dimensions: {
            width: 450,
            height: 700
        },
        margins: {
            top: 20,
            right: 60,
            bottom: 10,
            left: 20
        },
        fonts: {
            desktop: {
                family: "'Roboto', sans-serif",
                messageSize: "14px",
                headerSize: "18px",
                quickButtonSize: "13px"
            },
            mobile: {
                family: "'Roboto', sans-serif",
                messageSize: "16px",
                headerSize: "16px",
                quickButtonSize: "14px"
            }
        },
        colors: {
            header: {
                background: "linear-gradient(135deg, rgb(255, 84, 0) 0%, rgb(118, 75, 162) 100%)",
                textColor: "#ffffff"
            },
            buttons: {
                background: "#ff5400",
                hoverBackground: "#5a67d8",
                textColor: "#ffffff"
            },
            userMessage: {
                background: "#ff5400",
                textColor: "#ffffff"
            }
        },
        theme: {
            mode: "auto",
            preferredScheme: "auto"
        },
        widget: {
            type: "Expert Consulting",
            animationSpeed: 2,
            size: 70,
            primaryColor: "#667eea",
            icon: "🤖",
            position: "bottom-right",
            margins: {
                top: 20,
                right: 60,
                bottom: 10,
                left: 20
            }
        }
    },
    technical: {
        requestTimeout: 300000,
        maxMessageLength: 1000,
        debug: true,
        maxVoiceDuration: 600,
        maxFileSize: 10485760,
        allowedFileTypes: [
            "image/jpeg",
            "image/png",
            "image/gif",
            "image/webp",
            "image/bmp",
            "application/pdf",
            "text/plain",
            "text/csv",
            "application/msword",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            "application/vnd.ms-excel",
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        ],
        voiceSettings: {
            enableServerStorage: true,
            uploadEndpoint: "/upload-voice.php",
            downloadEndpoint: "/voices/",
            fileFormat: "ogg",
            filePrefix: "voice_message_",
            maxVoiceSize: 5242880,
            enableLocalFallback: true
        }
    },
    monitoring: {
        enabled: true,
        endpoint: "https://n8n.cryptomator.pro/webhook/chat-monitoring"
    },
    branding: {
        enabled: true,
        logoType: "svg",
        logoSvg: "<svg width=\"32\" height=\"32\" viewBox=\"0 0 32 32\" fill=\"none\" xmlns=\"http://www.w3.org/2000/svg\">\n            <circle cx=\"16\" cy=\"16\" r=\"15\" fill=\"url(#brandGrad1)\" opacity=\"0.12\"/>\n            <g transform=\"translate(8, 8)\">\n                <circle cx=\"8\" cy=\"8\" r=\"2.2\" fill=\"url(#brandGrad1)\"/>\n                <circle cx=\"2\" cy=\"4\" r=\"1.3\" fill=\"url(#brandGrad2)\"/>\n                <circle cx=\"14\" cy=\"4\" r=\"1.3\" fill=\"url(#brandGrad2)\"/>\n                <circle cx=\"2\" cy=\"12\" r=\"1.3\" fill=\"url(#brandGrad2)\"/>\n                <circle cx=\"14\" cy=\"12\" r=\"1.3\" fill=\"url(#brandGrad2)\"/>\n                <circle cx=\"8\" cy=\"1\" r=\"1.3\" fill=\"url(#brandGrad2)\"/>\n                <circle cx=\"8\" cy=\"15\" r=\"1.3\" fill=\"url(#brandGrad2)\"/>\n                <line x1=\"8\" y1=\"8\" x2=\"2\" y2=\"4\" stroke=\"url(#brandGrad1)\" stroke-width=\"0.8\" opacity=\"0.7\"/>\n                <line x1=\"8\" y1=\"8\" x2=\"14\" y2=\"4\" stroke=\"url(#brandGrad1)\" stroke-width=\"0.8\" opacity=\"0.7\"/>\n                <line x1=\"8\" y1=\"8\" x2=\"2\" y2=\"12\" stroke=\"url(#brandGrad1)\" stroke-width=\"0.8\" opacity=\"0.7\"/>\n                <line x1=\"8\" y1=\"8\" x2=\"14\" y2=\"12\" stroke=\"url(#brandGrad1)\" stroke-width=\"0.8\" opacity=\"0.7\"/>\n                <line x1=\"8\" y1=\"8\" x2=\"8\" y2=\"1\" stroke=\"url(#brandGrad1)\" stroke-width=\"0.8\" opacity=\"0.7\"/>\n                <line x1=\"8\" y1=\"8\" x2=\"8\" y2=\"15\" stroke=\"url(#brandGrad1)\" stroke-width=\"0.8\" opacity=\"0.7\"/>\n            </g>\n            <defs>\n                <linearGradient id=\"brandGrad1\" x1=\"0%\" y1=\"0%\" x2=\"100%\" y2=\"100%\">\n                    <stop offset=\"0%\" style=\"stop-color:#6366f1\"/>\n                    <stop offset=\"100%\" style=\"stop-color:#8b5cf6\"/>\n                </linearGradient>\n                <linearGradient id=\"brandGrad2\" x1=\"0%\" y1=\"0%\" x2=\"100%\" y2=\"100%\">\n                    <stop offset=\"0%\" style=\"stop-color:#3b82f6\"/>\n                    <stop offset=\"100%\" style=\"stop-color:#6366f1\"/>\n                </linearGradient>\n            </defs>\n        </svg>",
        icon: "🤖",
        imageUrl: "",
        companyName: "NexusMindAI",
        companyUrl: "",
        poweredByText: "Powered by",
        size: {
            logoWidth: 16,
            logoHeight: 15,
            fontSize: 10
        }
    }
    // ===============================================
    // GDPR НАСТРОЙКИ НАХОДЯТСЯ В GlobalConfigSettings
    // (убрано дублирование - используем единый источник)
    // ===============================================
};
// ✅ ЭКСПОРТ baseConfig в глобальную область
window.baseConfig = baseConfig;
// ===============================================
// КОНФИГУРАЦИЯ ДЛЯ ФИНАНСОВОГО САЙТА
// ===============================================
const financeConfig = mergeConfigs({
    configId: "financeConfig",
    internalConfigName: "financeConfig",
    useIndividualSettings: true,
    switcherSettings: {
        enabled: true,
        labels: {
            ru: "🏠 Финансы",
            en: "🏠 Finance",
            es: "💰 Finanzas",
            fr: "🏠 Finances",
            de: "💰 Finanzen",
            it: "💰 Finanza",
            pt: "💰 Finanças",
            zh: "💰 金融",
            ja: "💰 ファイナンス",
            ko: "💰 금융",
            ua: "🏠 Фінанси"
        },
        descriptions: {
            ru: "Финансовый консультант",
            en: "Financial Consultant",
            es: "Consultor financiero",
            fr: "Conseiller financier",
            de: "Finanzberater",
            it: "Consulente finanziario",
            pt: "Consultor financeiro",
            zh: "财务顾问",
            ja: "財務コンサルタント",
            ko: "재무 컨설턴트",
            ua: "Фінансовий консультант"
        },
        order: 1
    },
    supportedLanguages: [
        "ru",
        "en",
        "ua",
        "fr"
    ],
    defaultLanguage: "en",
    language: "ru",
    aiCoreUrl: "https://n8n.cryptomator.pro/webhook/webchat-api",
    botInfo: {
        avatar: "🏠",
        name: "FinBot",
        description: ""
    },
    theme: {
        mode: "dark",
        preferredScheme: "dark"
    },
    contacts: {
        enabled: true,
        titles: {
            ru: "Связаться с банком",
            en: "Contact the bank",
            es: "Contactar al banco",
            fr: "Contacter la banque",
            de: "Bank kontaktieren",
            it: "Contatta la banca",
            pt: "Contactar o banco",
            zh: "联系银行",
            ja: "銀行に連絡",
            ko: "은행 연락처",
            ua: "Зв'язатися з банком"
        },
        items: [
            {
                type: "telegram",
                url: "https://t.me/your_bank_bot",
                icon: "✈️",
                labels: {
                    ru: "Телеграм",
                    en: "Telegram",
                    es: "Telegram",
                    fr: "Telegram",
                    de: "Telegram",
                    it: "Telegram",
                    pt: "Telegram",
                    zh: "Telegram",
                    ja: "テレグラム",
                    ko: "텔레그램",
                    ua: "Телеграм"
                }
            },
            {
                type: "whatsapp",
                url: "https://wa.me/1234567890",
                icon: "📱",
                labels: {
                    ru: "WhatsApp",
                    en: "WhatsApp",
                    es: "WhatsApp",
                    fr: "WhatsApp",
                    de: "WhatsApp",
                    it: "WhatsApp",
                    pt: "WhatsApp",
                    zh: "WhatsApp",
                    ja: "WhatsApp",
                    ko: "왓츠앱",
                    ua: "WhatsApp"
                }
            },
            {
                type: "email",
                url: "mailto:support@bank.com",
                icon: "📧",
                labels: {
                    ru: "Эл. почта",
                    en: "Email",
                    es: "Correo",
                    fr: "Email",
                    de: "E-Mail",
                    it: "Email",
                    pt: "E-mail",
                    zh: "电子邮件",
                    ja: "メール",
                    ko: "이메일",
                    ua: "Ел. пошта"
                }
            },
            {
                type: "phone",
                url: "tel:+1234567890",
                icon: "📞",
                labels: {
                    ru: "Позвонить",
                    en: "Call",
                    es: "Llamar",
                    fr: "Appeler",
                    de: "Anrufen",
                    it: "Chiamare",
                    pt: "Ligar",
                    zh: "打电话",
                    ja: "電話する",
                    ko: "전화하기",
                    ua: "Подзвонити"
                }
            },
            {
                type: "messenger",
                url: "https://m.me/yourbank",
                icon: "💬",
                labels: {
                    ru: "Messenger",
                    en: "Messenger",
                    es: "Messenger",
                    fr: "Messenger",
                    de: "Messenger",
                    it: "Messenger",
                    pt: "Messenger",
                    zh: "Messenger",
                    ja: "メッセンジャー",
                    ko: "메신저",
                    ua: "Messenger"
                }
            },
            {
                type: "twitter",
                url: "https://twitter.com/yourbank",
                icon: "𝕏",
                labels: {
                    ru: "X (Twitter)",
                    en: "X (Twitter)",
                    es: "X (Twitter)",
                    fr: "X (Twitter)",
                    de: "X (Twitter)",
                    it: "X (Twitter)",
                    pt: "X (Twitter)",
                    zh: "X (Twitter)",
                    ja: "X (Twitter)",
                    ko: "X (트위터)",
                    ua: "X (Twitter)"
                }
            },
            {
                type: "instagram",
                url: "https://instagram.com/yourbank",
                icon: "📷",
                labels: {
                    ru: "Instagram",
                    en: "Instagram",
                    es: "Instagram",
                    fr: "Instagram",
                    de: "Instagram",
                    it: "Instagram",
                    pt: "Instagram",
                    zh: "Instagram",
                    ja: "インスタグラム",
                    ko: "인스타그램",
                    ua: "Instagram"
                }
            }
        ]
    },
    texts: {
        ru: {
            headerTitle: "FinBot",
            headerSubtitle: "",
            welcomeMessage: "<b style=\"font-family: -apple-system, BlinkMacSystemFont, &quot;Segoe UI&quot;, Roboto, sans-serif;\"><font color=\"#030303\">Добро пожаловать в банк! </font></b><strong style=\"font-family: -apple-system, BlinkMacSystemFont, &quot;Segoe UI&quot;, Roboto, sans-serif;\">💰</strong><br><br>\n                        Я помогу с банковскими услугами и ответлю на финансовые вопросы.<br><br><b style=\"font-family: -apple-system, BlinkMacSystemFont, &quot;Segoe UI&quot;, Roboto, sans-serif;\">Специализируюсь на:</b><br><span style=\"font-family: -apple-system, BlinkMacSystemFont, &quot;Segoe UI&quot;, Roboto, sans-serif;\">💳 Картах и счетах</span><br><span style=\"font-family: -apple-system, BlinkMacSystemFont, &quot;Segoe UI&quot;, Roboto, sans-serif;\">🏠 Кредитах и ипотеке</span><br><span style=\"font-family: -apple-system, BlinkMacSystemFont, &quot;Segoe UI&quot;, Roboto, sans-serif;\">📈 Инвестициях</span><br><span style=\"font-family: -apple-system, BlinkMacSystemFont, &quot;Segoe UI&quot;, Roboto, sans-serif;\">💼 Бизнес-услугах</span><br>\n                        <br>\n                        <i>Чем могу быть полезен?</i>",
            quickButtons: [
                {
                    text: "💳 Карты",
                    message: "Информация о картах"
                },
                {
                    text: "🏠 Кредиты",
                    message: "Условия кредитования"
                },
                {
                    text: "📈 Инвестиции",
                    message: "Инвестиционные продукты"
                },
                {
                    text: "👔 Менеджер",
                    message: "Связаться с менеджером"
                }
            ]
        },
        en: {
            headerTitle: "FinBot",
            headerSubtitle: "Financial Consultant",
            welcomeMessage: "<strong>Welcome to the bank! 💰</strong><br><br>\n                        I'll help with banking services and answer financial questions.<br><br>\n                        <b>I specialize in:</b><br>\n                        💳 Cards and accounts<br>\n                        🏠 Loans and mortgages<br>\n                        📈 Investments<br>\n                        💼 Business services<br><br>\n                        <i>How can I help you?</i>",
            quickButtons: [
                {
                    text: "💳 Cards",
                    message: "Information about cards"
                },
                {
                    text: "🏠 Loans",
                    message: "Loan conditions"
                },
                {
                    text: "📈 Investments",
                    message: "Investment products"
                },
                {
                    text: "👔 Manager",
                    message: "Contact manager"
                }
            ]
        },
        ua: {
            headerTitle: "FinBot",
            headerSubtitle: "Фінансовий консультант",
            welcomeMessage: "<strong>Ласкаво просимо до банку! 💰</strong><br><br>\n                        Я допоможу з банківськими послугами та відповім на фінансові питання.<br><br>\n                        <b>Спеціалізуюся на:</b><br>\n                        💳 Картках та рахунках<br>\n                        🏠 Кредитах та іпотеці<br>\n                        📈 Інвестиціях<br>\n                        💼 Бізнес-послугах<br><br>\n                        <i>Чим можу бути корисним?</i>",
            quickButtons: [
                {
                    text: "💳 Картки",
                    message: "Інформація про картки"
                },
                {
                    text: "🏠 Кредити",
                    message: "Умови кредитування"
                },
                {
                    text: "📈 Інвестиції",
                    message: "Інвестиційні продукти"
                },
                {
                    text: "👔 Менеджер",
                    message: "Зв’язатися з менеджером"
                }
            ]
        },
        fr: {
            headerTitle: "FinBot",
            headerSubtitle: "Conseiller financier",
            welcomeMessage: "<strong>Bienvenue à la banque ! 💰</strong><br><br>\n                        Je vous aiderai avec les services bancaires et répondrai à vos questions financières.<br><br>\n                        <b>Je suis spécialisé dans :</b><br>\n                        💳 Cartes et comptes<br>\n                        🏠 Prêts et hypothèques<br>\n                        📈 Investissements<br>\n                        💼 Services aux entreprises<br><br>\n                        <i>Comment puis-je vous aider ?</i>",
            quickButtons: [
                {
                    text: "💳 Cartes",
                    message: "Informations sur les cartes"
                },
                {
                    text: "🏠 Prêts",
                    message: "Conditions de prêt"
                },
                {
                    text: "📈 Investissements",
                    message: "Produits d'investissement"
                },
                {
                    text: "👔 Gestionnaire",
                    message: "Contacter un gestionnaire"
                }
            ]
        }
    },
    appearance: {
        position: "bottom-right",
        dimensions: {
            width: 450,
            height: 700
        },
        margins: {
            top: 20,
            right: 60,
            bottom: 10,
            left: 20
        },
        compactMinimizedSize: {
            width: 200,
            height: 65
        },
        compactMinimizedPosition: {
            position: "bottom-right",
            margins: {
                top: 20,
                right: 60,
                bottom: 10,
                left: 20
            }
        },
        fonts: {
            desktop: {
                family: "-apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', sans-serif",
                messageSize: "14px",
                headerSize: "16px",
                quickButtonSize: "13px"
            },
            mobile: {
                family: "-apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', sans-serif",
                messageSize: "16px",
                headerSize: "16px",
                quickButtonSize: "14px"
            }
        },
        colors: {
            header: {
                background: "linear-gradient(90deg, rgb(21, 139, 178) 0%, rgb(39, 82, 180) 100%)",
                textColor: "#ffffff"
            },
            buttons: {
                background: "#0a84b8",
                hoverBackground: "#773ee0",
                textColor: "#ffffff"
            },
            userMessage: {
                background: "#9146dd",
                textColor: "#ffffff"
            }
        },
        widget: {
            type: "Real Estate Agent",
            animationSpeed: 5,
            primaryColor: "#00b3ff",
            icon: "🏠",
            size: 70
        }
    },
    behavior: {
        autoOpen: false,
        autoOpenDelay: 10000,
        autoFocus: true,
        showWelcome: true,
        showQuickButtons: true,
        enableVoice: true,
        enableFileUpload: true,
        saveHistory: true,
        historyLifetime: 72,
        maxHistoryMessages: 50,
        quickButtonsCollapsed: true,
        enablePasteImages: true,
        showInputArea: true,
        enablePopoutMode: true,
        popoutWindowSize: {
            width: 500,
            height: 770
        }
    },
    technical: {
        requestTimeout: 300000,
        maxMessageLength: 1000,
        debug: false,
        maxVoiceDuration: 600,
        maxFileSize: 10485760,
        allowedFileTypes: [
            "image/jpeg",
            "image/png",
            "image/gif",
            "image/webp",
            "image/bmp",
            "application/pdf"
        ],
        voiceSettings: {
            enableServerStorage: true,
            uploadEndpoint: "/upload-voice.php",
            downloadEndpoint: "/voices/",
            fileFormat: "ogg",
            filePrefix: "voice_message_",
            maxVoiceSize: 5242880,
            enableLocalFallback: true
        }
    }
}, baseConfig, configMethods);
window.financeConfig = financeConfig;
// ===============================================
// КОНФИГУРАЦИЯ ДЛЯ E-COMMERCE / ИНТЕРНЕТ-МАГАЗИН
// ===============================================
const ecommerceConfig = mergeConfigs({
    configId: "ecommerceConfig",
    internalConfigName: "ecommerceConfig",
    useIndividualSettings: true,
    switcherSettings: {
        enabled: true,
        labels: {
            ru: "🛍️ Магазин",
            en: "🛍️ Shop",
            es: "🛍️ Tienda",
            fr: "🛍️ Boutique",
            de: "🛒 Shop",
            it: "🛒 Negozio",
            pt: "🛒 Loja",
            zh: "🛒 商店",
            ja: "🛒 ショップ",
            ko: "🛒 상점",
            ua: "🛍️ Магазин"
        },
        descriptions: {
            ru: "Помощник по покупкам",
            en: "Shopping Assistant",
            es: "Asistente de compras",
            fr: "Assistant shopping",
            de: "Einkaufsassistent",
            it: "Assistente acquisti",
            pt: "Assistente de compras",
            zh: "购物助手",
            ja: "ショッピングアシスタント",
            ko: "쇼핑 도우미",
            ua: "Помічник з покупок"
        },
        order: 2
    },
    supportedLanguages: [
        "ru",
        "en",
        "ua",
        "fr",
        "es"
    ],
    defaultLanguage: "ru",
    language: "ru",
    aiCoreUrl: "https://n8n.cryptomator.pro/webhook/webchat-api",
    botInfo: {
        avatar: "🛍️",
        name: "ShopBot",
        description: "Помощник по покупкам"
    },
    theme: {
        mode: "light",
        preferredScheme: "light"
    },
    contacts: {
        enabled: true,
        titles: {
            ru: "Контакты магазина",
            en: "Shop Contacts",
            es: "Contactos de la tienda",
            fr: "Contacts du magasin",
            de: "Shop-Kontakte",
            it: "Contatti del negozio",
            pt: "Contatos da loja",
            zh: "商店联系方式",
            ja: "ショップの連絡先",
            ko: "상점 연락처",
            ua: "Контакти магазину"
        },
        items: [
            {
                type: "telegram",
                url: "https://t.me/your_bank_bot",
                icon: "✈️",
                labels: {
                    ru: "Телеграм",
                    en: "Telegram",
                    es: "Telegram",
                    fr: "Telegram",
                    de: "Telegram",
                    it: "Telegram",
                    pt: "Telegram",
                    zh: "Telegram",
                    ja: "テレグラム",
                    ko: "텔레그램",
                    ua: "Телеграм"
                }
            },
            {
                type: "whatsapp",
                url: "https://wa.me/1234567890",
                icon: "📱",
                labels: {
                    ru: "WhatsApp",
                    en: "WhatsApp",
                    es: "WhatsApp",
                    fr: "WhatsApp",
                    de: "WhatsApp",
                    it: "WhatsApp",
                    pt: "WhatsApp",
                    zh: "WhatsApp",
                    ja: "WhatsApp",
                    ko: "왓츠앱",
                    ua: "WhatsApp"
                }
            },
            {
                type: "email",
                url: "mailto:support@bank.com",
                icon: "📧",
                labels: {
                    ru: "Эл. почта",
                    en: "Email",
                    es: "Correo",
                    fr: "Email",
                    de: "E-Mail",
                    it: "Email",
                    pt: "E-mail",
                    zh: "电子邮件",
                    ja: "メール",
                    ko: "이메일",
                    ua: "Ел. пошта"
                }
            },
            {
                type: "phone",
                url: "tel:+1234567890",
                icon: "📞",
                labels: {
                    ru: "Позвонить",
                    en: "Call",
                    es: "Llamar",
                    fr: "Appeler",
                    de: "Anrufen",
                    it: "Chiamare",
                    pt: "Ligar",
                    zh: "打电话",
                    ja: "電話する",
                    ko: "전화하기",
                    ua: "Подзвонити"
                }
            },
            {
                type: "messenger",
                url: "https://m.me/yourbank",
                icon: "💬",
                labels: {
                    ru: "Messenger",
                    en: "Messenger",
                    es: "Messenger",
                    fr: "Messenger",
                    de: "Messenger",
                    it: "Messenger",
                    pt: "Messenger",
                    zh: "Messenger",
                    ja: "メッセンジャー",
                    ko: "메신저",
                    ua: "Messenger"
                }
            },
            {
                type: "twitter",
                url: "https://twitter.com/yourbank",
                icon: "𝕏",
                labels: {
                    ru: "X (Twitter)",
                    en: "X (Twitter)",
                    es: "X (Twitter)",
                    fr: "X (Twitter)",
                    de: "X (Twitter)",
                    it: "X (Twitter)",
                    pt: "X (Twitter)",
                    zh: "X (Twitter)",
                    ja: "X (Twitter)",
                    ko: "X (트위터)",
                    ua: "X (Twitter)"
                }
            },
            {
                type: "instagram",
                url: "https://instagram.com/yourbank",
                icon: "📷",
                labels: {
                    ru: "Instagram",
                    en: "Instagram",
                    es: "Instagram",
                    fr: "Instagram",
                    de: "Instagram",
                    it: "Instagram",
                    pt: "Instagram",
                    zh: "Instagram",
                    ja: "インスタグラム",
                    ko: "인스타그램",
                    ua: "Instagram"
                }
            }
        ]
    },
    texts: {
        ru: {
            headerTitle: "ShopBot",
            headerSubtitle: "Помощник по покупкам",
            welcomeMessage: "<strong>Добро пожаловать! 🛒</strong><br><br>\n                        Я помогу вам найти товары и ответить на вопросы о заказах.<br><br>\n                        <b>Могу помочь с:</b><br>\n                        🔍 Поиском товаров<br>\n                        📦 Статусом заказа<br>\n                        💳 Оплатой и доставкой<br><br>\n                        <i>Что вас интересует?</i>",
            quickButtons: [
                {
                    text: "🔍 Найти товар",
                    message: "Помогите найти товар"
                },
                {
                    text: "📦 Мой заказ",
                    message: "Проверить статус заказа"
                },
                {
                    text: "💳 Оплата",
                    message: "Вопрос по оплате"
                },
                {
                    text: "🚚 Доставка",
                    message: "Информация о доставке"
                }
            ]
        },
        en: {
            headerTitle: "ShopBot",
            headerSubtitle: "Shopping Assistant",
            welcomeMessage: "<strong>Welcome! 🛒</strong><br><br>\n                        I'll help you find products and answer questions about orders.<br><br>\n                        <b>I can assist with:</b><br>\n                        🔍 Product search<br>\n                        📦 Order status<br>\n                        💳 Payment and delivery<br><br>\n                        <i>What are you interested in?</i>",
            quickButtons: [
                {
                    text: "🔍 Find product",
                    message: "Help me find a product"
                },
                {
                    text: "📦 My order",
                    message: "Check order status"
                },
                {
                    text: "💳 Payment",
                    message: "Question about payment"
                },
                {
                    text: "🚚 Delivery",
                    message: "Delivery information"
                }
            ]
        },
        ua: {
            headerTitle: "ShopBot",
            headerSubtitle: "Помічник з покупок",
            welcomeMessage: "<strong>Ласкаво просимо! 🛒</strong><br><br>\n                        Я допоможу вам знайти товари та відповісти на питання про замовлення.<br><br>\n                        <b>Можу допомогти з:</b><br>\n                        🔍 Пошуком товарів<br>\n                        📦 Статусом замовлення<br>\n                        💳 Оплатою та доставкою<br><br>\n                        <i>Що вас цікавить?</i>",
            quickButtons: [
                {
                    text: "🔍 Знайти товар",
                    message: "Допоможіть знайти товар"
                },
                {
                    text: "📦 Моє замовлення",
                    message: "Перевірити статус замовлення"
                },
                {
                    text: "💳 Оплата",
                    message: "Питання щодо оплати"
                },
                {
                    text: "🚚 Доставка",
                    message: "Інформація про доставку"
                }
            ]
        },
        fr: {
            headerTitle: "ShopBot",
            headerSubtitle: "Assistant d'achat",
            welcomeMessage: "<strong>Bienvenue ! 🛒</strong><br><br>\n                        Je vous aiderai à trouver des produits et à répondre aux questions sur les commandes.<br><br>\n                        <b>Je peux aider avec :</b><br>\n                        🔍 Recherche de produits<br>\n                        📦 Statut de la commande<br>\n                        💳 Paiement et livraison<br><br>\n                        <i>Qu'est-ce qui vous intéresse ?</i>",
            quickButtons: [
                {
                    text: "🔍 Trouver un produit",
                    message: "Aidez-moi à trouver un produit"
                },
                {
                    text: "📦 Ma commande",
                    message: "Vérifier le statut de la commande"
                },
                {
                    text: "💳 Paiement",
                    message: "Question sur le paiement"
                },
                {
                    text: "🚚 Livraison",
                    message: "Informations sur la livraison"
                }
            ]
        }
    },
    appearance: {
        position: "bottom-right",
        dimensions: {
            width: 600,
            height: 750
        },
        margins: {
            top: 20,
            right: 60,
            bottom: 10,
            left: 20
        },
        compactMinimizedSize: {
            width: 200,
            height: 65
        },
        compactMinimizedPosition: {
            position: "bottom-right",
            margins: {
                top: 20,
                right: 60,
                bottom: 10,
                left: 20
            }
        },
        fonts: {
            desktop: {
                family: "-apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', sans-serif",
                messageSize: "14px",
                headerSize: "18px",
                quickButtonSize: "13px"
            },
            mobile: {
                family: "-apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', sans-serif",
                messageSize: "16px",
                headerSize: "16px",
                quickButtonSize: "14px"
            }
        },
        colors: {
            header: {
                background: "linear-gradient(135deg, rgb(192, 17, 128) 0%, rgb(84, 17, 208) 100%)",
                textColor: "#ffffff"
            },
            buttons: {
                background: "#ec4899",
                hoverBackground: "#5a67d8",
                textColor: "#ffffff"
            },
            userMessage: {
                background: "#ff5400",
                textColor: "#ffffff"
            }
        },
        widget: {
            type: "Shopping Assistant",
            animationSpeed: 3,
            primaryColor: "#ee701b",
            icon: "🛍️",
            size: 80
        }
    },
    behavior: {
        autoOpen: false,
        autoOpenDelay: 10000,
        autoFocus: true,
        showWelcome: false,
        showQuickButtons: true,
        enableVoice: true,
        enableFileUpload: false,
        saveHistory: true,
        historyLifetime: 72,
        maxHistoryMessages: 50,
        quickButtonsCollapsed: false,
        enablePasteImages: true,
        showInputArea: true,
        enablePopoutMode: true,
        popoutWindowSize: {
            width: 500,
            height: 770
        }
    },
    technical: {
        requestTimeout: 300000,
        maxMessageLength: 1000,
        debug: false,
        maxVoiceDuration: 600,
        maxFileSize: 10485760,
        allowedFileTypes: [
            "image/jpeg",
            "image/png",
            "image/gif",
            "image/webp",
            "image/bmp",
            "application/pdf"
        ],
        voiceSettings: {
            enableServerStorage: true,
            uploadEndpoint: "/upload-voice.php",
            downloadEndpoint: "/voices/",
            fileFormat: "ogg",
            filePrefix: "voice_message_",
            maxVoiceSize: 5242880,
            enableLocalFallback: true
        }
    }
}, baseConfig, configMethods);
window.ecommerceConfig = ecommerceConfig;
// ===============================================
// КОНФИГУРАЦИЯ ДЛЯ IT/TECH САЙТА
// ===============================================
const techConfig = mergeConfigs({
    configId: "techConfig",
    internalConfigName: "techConfig",
    useIndividualSettings: true,
    switcherSettings: {
        enabled: true,
        labels: {
            ru: "💬 Поддержка",
            en: "💬 Support",
            es: "🤖 Soporte",
            fr: "💬 Support",
            de: "🤖 Support",
            it: "🤖 Supporto",
            pt: "🤖 Suporte",
            zh: "🤖 支持",
            ja: "🤖 サポート",
            ko: "🤖 지원",
            ua: "💬 Підтримка"
        },
        descriptions: {
            ru: "Техническая поддержка",
            en: "Technical Support",
            es: "Soporte técnico",
            fr: "Support technique",
            de: "Technischer Support",
            it: "Supporto tecnico",
            pt: "Suporte técnico",
            zh: "技术支持",
            ja: "テクニカルサポート",
            ko: "기술 지원",
            ua: "Технічна підтримка"
        },
        order: 3
    },
    supportedLanguages: [
        "ru",
        "en",
        "ua",
        "fr"
    ],
    defaultLanguage: "en",
    language: "ru",
    aiCoreUrl: "https://n8n.cryptomator.pro/webhook/webchat-api",
    botInfo: {
        avatar: "💬",
        name: "TechBot",
        description: "Техническая поддержка"
    },
    theme: {
        mode: "dark",
        preferredScheme: "dark"
    },
    contacts: {
        enabled: true,
        titles: {
            ru: "Техподдержка",
            en: "Tech Support",
            es: "Soporte técnico",
            fr: "Support technique",
            de: "Technischer Support",
            it: "Supporto tecnico",
            pt: "Suporte técnico",
            zh: "技术支持",
            ja: "テクニカルサポート",
            ko: "기술 지원",
            ua: "Техпідтримка"
        },
        items: [
            {
                type: "telegram",
                url: "https://t.me/your_bank_bot",
                icon: "✈️",
                labels: {
                    ru: "Телеграм",
                    en: "Telegram",
                    es: "Telegram",
                    fr: "Telegram",
                    de: "Telegram",
                    it: "Telegram",
                    pt: "Telegram",
                    zh: "Telegram",
                    ja: "テレグラム",
                    ko: "텔레그램",
                    ua: "Телеграм"
                }
            },
            {
                type: "whatsapp",
                url: "https://wa.me/1234567890",
                icon: "📱",
                labels: {
                    ru: "WhatsApp",
                    en: "WhatsApp",
                    es: "WhatsApp",
                    fr: "WhatsApp",
                    de: "WhatsApp",
                    it: "WhatsApp",
                    pt: "WhatsApp",
                    zh: "WhatsApp",
                    ja: "WhatsApp",
                    ko: "왓츠앱",
                    ua: "WhatsApp"
                }
            },
            {
                type: "email",
                url: "mailto:support@bank.com",
                icon: "📧",
                labels: {
                    ru: "Эл. почта",
                    en: "Email",
                    es: "Correo",
                    fr: "Email",
                    de: "E-Mail",
                    it: "Email",
                    pt: "E-mail",
                    zh: "电子邮件",
                    ja: "メール",
                    ko: "이메일",
                    ua: "Ел. пошта"
                }
            },
            {
                type: "phone",
                url: "tel:+1234567890",
                icon: "📞",
                labels: {
                    ru: "Позвонить",
                    en: "Call",
                    es: "Llamar",
                    fr: "Appeler",
                    de: "Anrufen",
                    it: "Chiamare",
                    pt: "Ligar",
                    zh: "打电话",
                    ja: "電話する",
                    ko: "전화하기",
                    ua: "Подзвонити"
                }
            },
            {
                type: "messenger",
                url: "https://m.me/yourbank",
                icon: "💬",
                labels: {
                    ru: "Messenger",
                    en: "Messenger",
                    es: "Messenger",
                    fr: "Messenger",
                    de: "Messenger",
                    it: "Messenger",
                    pt: "Messenger",
                    zh: "Messenger",
                    ja: "メッセンジャー",
                    ko: "메신저",
                    ua: "Messenger"
                }
            },
            {
                type: "twitter",
                url: "https://twitter.com/yourbank",
                icon: "𝕏",
                labels: {
                    ru: "X (Twitter)",
                    en: "X (Twitter)",
                    es: "X (Twitter)",
                    fr: "X (Twitter)",
                    de: "X (Twitter)",
                    it: "X (Twitter)",
                    pt: "X (Twitter)",
                    zh: "X (Twitter)",
                    ja: "X (Twitter)",
                    ko: "X (트위터)",
                    ua: "X (Twitter)"
                }
            },
            {
                type: "instagram",
                url: "https://instagram.com/yourbank",
                icon: "📷",
                labels: {
                    ru: "Instagram",
                    en: "Instagram",
                    es: "Instagram",
                    fr: "Instagram",
                    de: "Instagram",
                    it: "Instagram",
                    pt: "Instagram",
                    zh: "Instagram",
                    ja: "インスタグラム",
                    ko: "인스타그램",
                    ua: "Instagram"
                }
            }
        ]
    },
    texts: {
        ru: {
            headerTitle: "TechBot",
            headerSubtitle: "Техническая поддержка",
            welcomeMessage: "<strong>Привет, разработчик! 🤖</strong><br><br>\n                            Я помогу с техническими вопросами и поддержкой.<br><br>\n                            <b>Могу помочь с:</b><br>\n                            💻 Документацией API<br>\n                            🐛 Сообщениями об ошибках<br>\n                            🔧 Помощью в интеграции<br>\n                            📚 Примерами кода<br><br>\n                            <i>Чем могу помочь?</i>",
            quickButtons: [
                {
                    text: "📖 Документация",
                    message: "Показать документацию API"
                },
                {
                    text: "🐛 Сообщить об ошибке",
                    message: "Сообщить об ошибке"
                },
                {
                    text: "💻 Интеграция",
                    message: "Помощь с интеграцией"
                },
                {
                    text: "👨Разработчик",
                    message: "Связаться с разработчиком"
                }
            ]
        },
        en: {
            headerTitle: "TechBot",
            headerSubtitle: "Technical Support",
            welcomeMessage: "<strong>Hello, Developer! 🤖</strong><br><br>\n                            I'm here to help with technical questions and support.<br><br>\n                            <b>I can assist with:</b><br>\n                            💻 API Documentation<br>\n                            🐛 Bug Reports<br>\n                            🔧 Integration Help<br>\n                            📚 Code Examples<br><br>\n                            <i>What can I help you with?</i>",
            quickButtons: [
                {
                    text: "📖 Docs",
                    message: "Show API documentation"
                },
                {
                    text: "🐛 Bug Report",
                    message: "Report a bug"
                },
                {
                    text: "💻 Integration",
                    message: "Integration help"
                },
                {
                    text: "👨Developer",
                    message: "Contact developer"
                }
            ]
        },
        ua: {
            headerTitle: "TechBot",
            headerSubtitle: "Технічна підтримка",
            welcomeMessage: "<strong>Привіт, розробнику! 🤖</strong><br><br>\n                            Я допоможу з технічними питаннями та підтримкою.<br><br>\n                            <b>Можу допомогти з:</b><br>\n                            💻 Документацією API<br>\n                            🐛 Повідомленнями про помилки<br>\n                            🔧 Допомогою в інтеграції<br>\n                            📚 Прикладами коду<br><br>\n                            <i>Чим можу допомогти?</i>",
            quickButtons: [
                {
                    text: "📖 Документація",
                    message: "Показати документацію API"
                },
                {
                    text: "🐛 Повідомити про помилку",
                    message: "Повідомити про помилку"
                },
                {
                    text: "💻 Інтеграція",
                    message: "Допомога з інтеграцією"
                },
                {
                    text: "👨Розробник",
                    message: "Зв'язатися з розробником"
                }
            ]
        },
        fr: {
            headerTitle: "TechBot",
            headerSubtitle: "Support technique",
            welcomeMessage: "<strong>Bonjour, développeur ! 🤖</strong><br><br>\n                            Je suis là pour vous aider avec des questions techniques et du support.<br><br>\n                            <b>Je peux aider avec :</b><br>\n                            💻 Documentation API<br>\n                            🐛 Rapports de bugs<br>\n                            🔧 Aide à l'intégration<br>\n                            📚 Exemples de code<br><br>\n                            <i>Comment puis-je vous aider ?</i>",
            quickButtons: [
                {
                    text: "📖 Docs",
                    message: "Afficher la documentation API"
                },
                {
                    text: "🐛 Signaler un bug",
                    message: "Signaler un bug"
                },
                {
                    text: "💻 Intégration",
                    message: "Aide à l'intégration"
                },
                {
                    text: "👨Développeur",
                    message: "Contacter le développeur"
                }
            ]
        }
    },
    appearance: {
        position: "bottom-right",
        dimensions: {
            width: 400,
            height: 560
        },
        margins: {
            top: 20,
            right: 60,
            bottom: 10,
            left: 20
        },
        compactMinimizedSize: {
            width: 200,
            height: 65
        },
        compactMinimizedPosition: {
            position: "bottom-right",
            margins: {
                top: 20,
                right: 60,
                bottom: 10,
                left: 20
            }
        },
        fonts: {
            desktop: {
                family: "-apple-system, sans-serif",
                messageSize: "14px",
                headerSize: "18px",
                quickButtonSize: "13px"
            },
            mobile: {
                family: "-apple-system, sans-serif",
                messageSize: "16px",
                headerSize: "16px",
                quickButtonSize: "14px"
            }
        },
        colors: {
            header: {
                background: "linear-gradient(135deg, rgb(102, 126, 234) 0%, rgb(118, 75, 162) 100%)",
                textColor: "#ffffff"
            },
            buttons: {
                background: "#667a22",
                hoverBackground: "#5a67d8",
                textColor: "#ffffff"
            },
            userMessage: {
                background: "#ff5400",
                textColor: "#ffffff"
            }
        },
        widget: {
            type: "Minimal Ring",
            animationSpeed: 4,
            primaryColor: "#6b7280",
            icon: "💬",
            size: 80
        }
    },
    behavior: {
        autoOpen: false,
        autoOpenDelay: 10000,
        autoFocus: true,
        showWelcome: false,
        showQuickButtons: false,
        enableVoice: true,
        enableFileUpload: true,
        saveHistory: true,
        historyLifetime: 72,
        maxHistoryMessages: 50,
        quickButtonsCollapsed: true,
        enablePasteImages: true,
        showInputArea: false,
        enablePopoutMode: true,
        popoutWindowSize: {
            width: 500,
            height: 770
        }
    },
    technical: {
        requestTimeout: 300000,
        maxMessageLength: 1000,
        debug: false,
        maxVoiceDuration: 600,
        maxFileSize: 10485760,
        allowedFileTypes: [
            "image/jpeg",
            "image/png",
            "image/gif",
            "image/webp",
            "image/bmp",
            "application/pdf",
            "text/plain",
            "text/csv",
            "application/msword",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        ],
        voiceSettings: {
            enableServerStorage: true,
            uploadEndpoint: "/upload-voice.php",
            downloadEndpoint: "/voices/",
            fileFormat: "ogg",
            filePrefix: "voice_message_",
            maxVoiceSize: 5242880,
            enableLocalFallback: true
        }
    }
}, baseConfig, configMethods);
window.techConfig = techConfig; 
// ===============================================
// КОНФИГУРАЦИЯ ДЛЯ ОБРАЗОВАТЕЛЬНОГО САЙТА
// ===============================================
const educationConfig = mergeConfigs({
    configId: "educationConfig",
    internalConfigName: "educationConfig",
    useIndividualSettings: true,
    switcherSettings: {
        enabled: true,
        labels: {
            ru: "🤖 Обучение",
            en: "🤖 Education",
            es: "📚 Educación",
            fr: "🤖 Éducation",
            de: "📚 Bildung",
            it: "📚 Istruzione",
            pt: "📚 Educação",
            zh: "📚 教育",
            ja: "📚 教育",
            ko: "📚 교육",
            ua: "🤖 Навчання"
        },
        descriptions: {
            ru: "Образовательный помощник",
            en: "Educational Assistant",
            es: "Asistente educativo",
            fr: "Assistant éducatif",
            de: "Bildungsassistent",
            it: "Assistente educativo",
            pt: "Assistente educacional",
            zh: "教育助手",
            ja: "教育アシスタント",
            ko: "교육 도우미",
            ua: "Освітній помічник"
        },
        order: 4
    },
    supportedLanguages: [
        "ru",
        "en",
        "ua",
        "fr"
    ],
    defaultLanguage: "ru",
    language: "ru",
    aiCoreUrl: "https://n8n.cryptomator.pro/webhook/webchat-api",
    botInfo: {
        avatar: "🤖",
        name: "EduBot",
        description: ""
    },
    theme: {
        mode: "light",
        preferredScheme: "light"
    },
    contacts: {
        enabled: true,
        titles: {
            ru: "Контакты школы",
            en: "School Contacts",
            es: "Contactos de la escuela",
            fr: "Contacts de l'école",
            de: "Schulkontakte",
            it: "Contatti della scuola",
            pt: "Contatos da escola",
            zh: "学校联系方式",
            ja: "学校の連絡先",
            ko: "학교 연락처",
            ua: "Контакти школи"
        },
        items: [
            {
                type: "telegram",
                url: "https://t.me/your_bank_bot",
                icon: "✈️",
                labels: {
                    ru: "Телеграм",
                    en: "Telegram",
                    es: "Telegram",
                    fr: "Telegram",
                    de: "Telegram",
                    it: "Telegram",
                    pt: "Telegram",
                    zh: "Telegram",
                    ja: "テレグラム",
                    ko: "텔레그램",
                    ua: "Телеграм"
                }
            },
            {
                type: "whatsapp",
                url: "https://wa.me/1234567890",
                icon: "📱",
                labels: {
                    ru: "WhatsApp",
                    en: "WhatsApp",
                    es: "WhatsApp",
                    fr: "WhatsApp",
                    de: "WhatsApp",
                    it: "WhatsApp",
                    pt: "WhatsApp",
                    zh: "WhatsApp",
                    ja: "WhatsApp",
                    ko: "왓츠앱",
                    ua: "WhatsApp"
                }
            },
            {
                type: "email",
                url: "mailto:support@bank.com",
                icon: "📧",
                labels: {
                    ru: "Эл. почта",
                    en: "Email",
                    es: "Correo",
                    fr: "Email",
                    de: "E-Mail",
                    it: "Email",
                    pt: "E-mail",
                    zh: "电子邮件",
                    ja: "メール",
                    ko: "이메일",
                    ua: "Ел. пошта"
                }
            },
            {
                type: "phone",
                url: "tel:+1234567890",
                icon: "📞",
                labels: {
                    ru: "Позвонить",
                    en: "Call",
                    es: "Llamar",
                    fr: "Appeler",
                    de: "Anrufen",
                    it: "Chiamare",
                    pt: "Ligar",
                    zh: "打电话",
                    ja: "電話する",
                    ko: "전화하기",
                    ua: "Подзвонити"
                }
            },
            {
                type: "messenger",
                url: "https://m.me/yourbank",
                icon: "💬",
                labels: {
                    ru: "Messenger",
                    en: "Messenger",
                    es: "Messenger",
                    fr: "Messenger",
                    de: "Messenger",
                    it: "Messenger",
                    pt: "Messenger",
                    zh: "Messenger",
                    ja: "メッセンジャー",
                    ko: "메신저",
                    ua: "Messenger"
                }
            },
            {
                type: "twitter",
                url: "https://twitter.com/yourbank",
                icon: "𝕏",
                labels: {
                    ru: "X (Twitter)",
                    en: "X (Twitter)",
                    es: "X (Twitter)",
                    fr: "X (Twitter)",
                    de: "X (Twitter)",
                    it: "X (Twitter)",
                    pt: "X (Twitter)",
                    zh: "X (Twitter)",
                    ja: "X (Twitter)",
                    ko: "X (트위터)",
                    ua: "X (Twitter)"
                }
            },
            {
                type: "instagram",
                url: "https://instagram.com/yourbank",
                icon: "📷",
                labels: {
                    ru: "Instagram",
                    en: "Instagram",
                    es: "Instagram",
                    fr: "Instagram",
                    de: "Instagram",
                    it: "Instagram",
                    pt: "Instagram",
                    zh: "Instagram",
                    ja: "インスタグラム",
                    ko: "인스타그램",
                    ua: "Instagram"
                }
            }
        ]
    },
    texts: {
        ru: {
            headerTitle: "EduBot",
            headerSubtitle: "",
            welcomeMessage: "<strong>Привет, студент! 📚</strong><br><br>\n                            Я помогу тебе с обучением и отвечу на вопросы о курсах.<br><br>\n                            <b>Готов помочь с:</b><br>\n                            📖 Выбором курса<br>\n                            📋 Расписанием<br>\n                            💯 Оценками<br>\n                            🎓 Экзаменами<br><br>\n                            <i>О чем хочешь узнать?</i>",
            quickButtons: [
                {
                    text: "📖 Курсы",
                    message: "Показать доступные курсы"
                },
                {
                    text: "📋 Расписание",
                    message: "Мое расписание"
                },
                {
                    text: "💯 Оценки",
                    message: "Проверить оценки"
                },
                {
                    text: "👨Преподаватель",
                    message: "Связаться с преподавателем"
                }
            ]
        }
    },
    appearance: {
        position: "bottom-right",
        dimensions: {
            width: 450,
            height: 700
        },
        margins: {
            top: 20,
            right: 60,
            bottom: 10,
            left: 20
        },
        compactMinimizedSize: {
            width: 200,
            height: 65
        },
        compactMinimizedPosition: {
            position: "bottom-right",
            margins: {
                top: 20,
                right: 60,
                bottom: 10,
                left: 20
            }
        },
        fonts: {
            desktop: {
                family: "-apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', sans-serif",
                messageSize: "14px",
                headerSize: "16px",
                quickButtonSize: "13px"
            },
            mobile: {
                family: "-apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', sans-serif",
                messageSize: "16px",
                headerSize: "16px",
                quickButtonSize: "14px"
            }
        },
        colors: {
            header: {
                background: "linear-gradient(135deg, rgb(29, 101, 119) 0%, rgb(115, 49, 180) 100%)",
                textColor: "#ffffff"
            },
            buttons: {
                background: "#8b5cf6",
                hoverBackground: "#ff5400",
                textColor: "#ffffff"
            },
            userMessage: {
                background: "#15acb7",
                textColor: "#ffffff"
            }
        },
        widget: {
            type: "AI Robot Assistant",
            animationSpeed: 3.9,
            primaryColor: "#2ba1d4",
            icon: "🤖",
            size: 80
        }
    },
    behavior: {
        autoOpen: false,
        autoOpenDelay: 10000,
        autoFocus: true,
        showWelcome: false,
        showQuickButtons: true,
        enableVoice: true,
        enableFileUpload: true,
        saveHistory: true,
        historyLifetime: 72,
        maxHistoryMessages: 50,
        quickButtonsCollapsed: true,
        enablePasteImages: true,
        showInputArea: true,
        enablePopoutMode: true,
        popoutWindowSize: {
            width: 500,
            height: 770
        }
    },
    technical: {
        requestTimeout: 300000,
        maxMessageLength: 1000,
        debug: false,
        maxVoiceDuration: 600,
        maxFileSize: 10485760,
        allowedFileTypes: [
            "image/jpeg",
            "image/png",
            "image/gif",
            "image/webp",
            "image/bmp",
            "application/pdf",
            "text/plain",
            "text/csv",
            "application/msword",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        ],
        voiceSettings: {
            enableServerStorage: true,
            uploadEndpoint: "/upload-voice.php",
            downloadEndpoint: "/voices/",
            fileFormat: "ogg",
            filePrefix: "voice_message_",
            maxVoiceSize: 5242880,
            enableLocalFallback: true
        }
    }
}, baseConfig, configMethods);
window.educationConfig = educationConfig; 

// ===============================================
// КОНФИГУРАЦИЯ: COACHCONFIG

// ===============================================
// КОНФИГУРАЦИЯ: COACHCONFIG
// ===============================================
// КОНФИГУРАЦИЯ ДЛЯ МЕДИЦИНСКОГО САЙТА
// ===============================================
// КОНФИГУРАЦИЯ ДЛЯ РЕСТОРАНА/КАФЕ
// ===============================================
// ✅ НОВЫЕ ФУНКЦИИ УПРАВЛЕНИЯ ТЕМОЙ
// ===============================================

// Получение эффективной темы для конфигурации
function getEffectiveTheme(config) {
    if (!config) return 'auto';
    
    const globalTheme = GlobalConfigSettings.themeSettings.globalTheme;
    const allowPerConfig = GlobalConfigSettings.themeSettings.allowPerConfigTheme;
    const configTheme = config.theme ? config.theme.mode : null;
    
    // Если глобальная тема установлена и не разрешены индивидуальные темы
    if (globalTheme !== 'auto' && !allowPerConfig) {
        return globalTheme;
    }
    
    // Если у конфигурации есть своя тема и это разрешено
    if (configTheme && allowPerConfig) {
        return configTheme;
    }
    
    // Иначе используем глобальную настройку
    return globalTheme || 'auto';
}

// Применение темы к виджету
function applyThemeToWidget(widget, theme) {
    if (!widget) return;
    
    // Удаляем все классы тем
    widget.classList.remove('webchat-theme-auto', 'webchat-theme-light', 'webchat-theme-dark');
    
    // Добавляем класс нужной темы
    widget.classList.add(`webchat-theme-${theme}`);
}

// Установка глобальной темы
function setGlobalTheme(theme) {
    const validThemes = ['auto', 'light', 'dark'];
    if (!validThemes.includes(theme)) {
        console.error('❌ Некорректная тема:', theme);
        return false;
    }
    
    GlobalConfigSettings.themeSettings.globalTheme = theme;
    
    // Применяем ко всем существующим виджетам
    const widgets = document.querySelectorAll('.webchat-widget');
    widgets.forEach(widget => {
        applyThemeToWidget(widget, theme);
    });
    
    return true;
}

// Установка разрешения на индивидуальные темы конфигураций
function setAllowPerConfigTheme(allow) {
    GlobalConfigSettings.themeSettings.allowPerConfigTheme = allow;
}

// ===============================================
// ФУНКЦИИ УПРАВЛЕНИЯ ПЕРЕКЛЮЧАТЕЛЕМ (СУЩЕСТВУЮЩИЕ)
// ===============================================

// Получение списка доступных конфигураций для переключателя
function getAvailableConfigs() {
    // ✅ ДИНАМИЧЕСКИ собираем все конфигурации
    const allConfigs = {};
    
    for (let key in window) {
        if (key.endsWith('Config') && 
            typeof window[key] === 'object' && 
            window[key] !== null &&
            window[key].configId &&
            window[key].botInfo) {
            allConfigs[key] = window[key];
        }
    }
    
    // Фильтруем только включенные конфигурации
    const availableConfigs = {};
    
    Object.keys(allConfigs).forEach(configName => {
        const config = allConfigs[configName];
        const globalSetting = GlobalConfigSettings.availableConfigs[configName];
        const configSetting = config.switcherSettings;
        
        // Проверяем что конфигурация включена и глобально, и индивидуально
        if (globalSetting && globalSetting.enabled && 
            configSetting && configSetting.enabled) {
            availableConfigs[configName] = config;
        }
    });
    
    return availableConfigs;
}

// Получение отсортированного списка конфигураций для UI
// ✅ ОБНОВЛЕННАЯ: Получение отсортированного списка конфигураций для UI с поддержкой языков
function getSortedConfigsForUI(currentLanguage = 'ru') {
    const availableConfigs = getAvailableConfigs();
    
    // Преобразуем в массив с информацией для UI
    const configsArray = Object.keys(availableConfigs).map(configName => {
        const config = availableConfigs[configName];
        const globalSetting = GlobalConfigSettings.availableConfigs[configName];
        const switcherSettings = config.switcherSettings || {};
        
        // ✅ НОВОЕ: Получаем label и description на нужном языке
        const getLocalizedText = (textObj, fallback) => {
            if (typeof textObj === 'object' && textObj !== null) {
                return textObj[currentLanguage] || textObj.ru || textObj.en || fallback;
            }
            return textObj || fallback;
        };
        
        return {
            value: configName,
            label: getLocalizedText(switcherSettings.labels || switcherSettings.label, configName),
            description: getLocalizedText(switcherSettings.descriptions || switcherSettings.description, ''),
            order: globalSetting.order || switcherSettings.order || 999,
            config: config,
            theme: getEffectiveTheme(config)
        };
    });
    
    // Сортируем по порядку
    return configsArray.sort((a, b) => a.order - b.order);
}

// Проверка - должен ли отображаться переключатель
function shouldShowConfigSwitcher() {
    // Проверяем глобальную настройку
    if (!GlobalConfigSettings.showConfigSwitcher) {
        return false;
    }
    
    // Проверяем что есть хотя бы 2 доступные конфигурации
    const availableConfigs = getAvailableConfigs();
    return Object.keys(availableConfigs).length > 1;
}

// Получение конфигурации по умолчанию
function getDefaultConfig() {
    const defaultConfigName = GlobalConfigSettings.configSwitcher.defaultConfig;
    const availableConfigs = getAvailableConfigs();
    
    // Если указанная конфигурация доступна - используем её
    if (availableConfigs[defaultConfigName]) {
        return availableConfigs[defaultConfigName];
    }
    
    // Иначе берем первую доступную
    const sortedConfigs = getSortedConfigsForUI();
    return sortedConfigs.length > 0 ? sortedConfigs[0].config : financeConfig;
}

// ✅ РАСШИРЕННОЕ УПРАВЛЕНИЕ НАСТРОЙКАМИ КОНФИГУРАЦИЙ
const ConfigManager = {
    // Включить/отключить переключатель глобально
    setConfigSwitcherEnabled(enabled) {
        GlobalConfigSettings.showConfigSwitcher = enabled;
    },
    
    // Включить/отключить конкретную конфигурацию
    setConfigEnabled(configName, enabled) {
        if (GlobalConfigSettings.availableConfigs[configName]) {
            GlobalConfigSettings.availableConfigs[configName].enabled = enabled;
        }
    },
    
    // Изменить порядок конфигурации в списке
    setConfigOrder(configName, order) {
        if (GlobalConfigSettings.availableConfigs[configName]) {
            GlobalConfigSettings.availableConfigs[configName].order = order;
        }
    },
    
    // ✅ НОВЫЕ МЕТОДЫ УПРАВЛЕНИЯ ТЕМОЙ
    setGlobalTheme(theme) {
        return setGlobalTheme(theme);
    },
    
    setAllowPerConfigTheme(allow) {
        setAllowPerConfigTheme(allow);
    },
    
    getThemeSettings() {
        return {
            globalTheme: GlobalConfigSettings.themeSettings.globalTheme,
            allowPerConfigTheme: GlobalConfigSettings.themeSettings.allowPerConfigTheme,
            userCanChange: GlobalConfigSettings.themeSettings.userCanChange
        };
    },
    
    setThemeForConfig(configName, theme) {
    // ✅ ДИНАМИЧЕСКИ получаем конфигурацию
    const config = window[configName];
    
    if (config && config.theme) {
        config.theme.mode = theme;
        return true;
    }
    return false;
},
    
    // ✅ НОВЫЕ МЕТОДЫ УПРАВЛЕНИЯ ПРИОРИТЕТОМ
setUseIndividualSettings(use) {
    GlobalConfigSettings.prioritySettings.useIndividualSettings = use;
    if (CONFIG_DEBUG) console.log('🔧 Приоритет индивидуальных настроек:', use ? 'включен' : 'выключен');
},

setAllowPartialOverride(allow) {
    GlobalConfigSettings.prioritySettings.allowPartialOverride = allow;
    if (CONFIG_DEBUG) console.log('🔧 Частичное переопределение:', allow ? 'включено' : 'выключено');
},

getPrioritySettings() {
    return GlobalConfigSettings.prioritySettings;
},
    // Получить текущие настройки
    getSettings() {
        return {
            switcherEnabled: GlobalConfigSettings.showConfigSwitcher,
            availableConfigs: Object.keys(getAvailableConfigs()),
            defaultConfig: GlobalConfigSettings.configSwitcher.defaultConfig,
            totalConfigs: Object.keys(GlobalConfigSettings.availableConfigs).length,
            themeSettings: this.getThemeSettings() // ✅ НОВОЕ: настройки темы
        };
    },
    
    // ✅ НОВЫЙ МЕТОД: Управление индивидуальными настройками конфигурации
setConfigIndividualSettings(configName, useIndividual) {
    // ✅ ДИНАМИЧЕСКИ получаем конфигурацию
    const config = window[configName];
    
    if (config) {
        config.useIndividualSettings = useIndividual;
        if (CONFIG_DEBUG) console.log(`🔧 ${configName}: индивидуальные настройки ${useIndividual ? 'включены' : 'выключены'}`);

        // Если чат уже инициализирован с этой конфигурацией - перезагружаем
        if (window.WebChatConfig && window.WebChatConfig.configId === configName) {
            window.ChatConfigs.apply(configName);
        }
        return true;
    }
    return false;
},

// Получить статус всех конфигураций
getConfigsIndividualStatus() {
    // ✅ ДИНАМИЧЕСКИ собираем все конфигурации
    const allConfigs = getAvailableConfigs();
    
    const status = {};
    Object.keys(allConfigs).forEach(configName => {
        status[configName] = allConfigs[configName].useIndividualSettings || false;
    });
    return status;
},
    
    // Применить пакет настроек
    applySettings(settings) {
        if (settings.switcherEnabled !== undefined) {
            this.setConfigSwitcherEnabled(settings.switcherEnabled);
        }
        
        if (settings.configStates) {
            Object.keys(settings.configStates).forEach(configName => {
                const state = settings.configStates[configName];
                this.setConfigEnabled(configName, state.enabled);
                if (state.order !== undefined) {
                    this.setConfigOrder(configName, state.order);
                }
                // ✅ НОВОЕ: применение темы для конфигурации
                if (state.theme) {
                    this.setThemeForConfig(configName, state.theme);
                }
            });
        }
        
        if (settings.defaultConfig) {
            GlobalConfigSettings.configSwitcher.defaultConfig = settings.defaultConfig;
        }
        
        // ✅ НОВОЕ: применение настроек темы
        if (settings.themeSettings) {
            if (settings.themeSettings.globalTheme) {
                this.setGlobalTheme(settings.themeSettings.globalTheme);
            }
            if (settings.themeSettings.allowPerConfigTheme !== undefined) {
                this.setAllowPerConfigTheme(settings.themeSettings.allowPerConfigTheme);
            }
        }
    }
};

// ===============================================
// ФУНКЦИЯ ПРИМЕНЕНИЯ КОНФИГУРАЦИИ (СМЕНА НА ЛЕТУ)
// ===============================================
function applyConfig(configName) {
    const availableConfigs = getAvailableConfigs();
    const selectedConfig = availableConfigs[configName];
    
    if (!selectedConfig) {
        console.error('❌ Конфигурация не найдена или отключена:', configName);
        return false;
    }
    
    // Применяем конфигурацию
    Object.assign(window.WebChatConfig, selectedConfig);
    
    // ✅ НОВОЕ: Применяем тему конфигурации
    const effectiveTheme = getEffectiveTheme(selectedConfig);
    const widget = document.querySelector('.webchat-widget');
    if (widget) {
        applyThemeToWidget(widget, effectiveTheme);
    }
    
    // Перезапускаем чат если он уже инициализирован
    if (window.webChat) {
        window.webChat.destroy();
        setTimeout(() => {
            initWebChat();
        }, 100);
    }
    return true;
}

// ===============================================
// ЭКСПОРТ КОНФИГУРАЦИЙ И НОВЫХ ФУНКЦИЙ
// ===============================================

// Объект со всеми конфигурациями для удобного доступа
window.ChatConfigs = {
    // ✅ ДИНАМИЧЕСКИ добавляем все конфигурации
    ...(() => {
        const configs = {};
        for (let key in window) {
            if (key.endsWith('Config') && 
                typeof window[key] === 'object' && 
                window[key] !== null &&
                window[key].configId) {
                // Создаем короткое имя (financeConfig -> finance)
                const shortName = key.replace('Config', '');
                configs[shortName] = window[key];
            }
        }
        return configs;
    })(),
    
    // Функции управления
    apply: applyConfig,
    
    // Функции управления переключателем
    manager: ConfigManager,
    getAvailable: getAvailableConfigs,
    getSortedForUI: getSortedConfigsForUI,
    shouldShowSwitcher: shouldShowConfigSwitcher,
    getDefault: getDefaultConfig,
    
    // ✅ НОВЫЕ ФУНКЦИИ УПРАВЛЕНИЯ ТЕМОЙ
    theme: {
        apply: applyThemeToWidget,
        setGlobal: setGlobalTheme,
        getEffective: getEffectiveTheme,
        setAllowPerConfig: setAllowPerConfigTheme
    },
    
    // Настройки системы
    globalSettings: GlobalConfigSettings
};

// Функции управления
window.ChatConfigManager = ConfigManager;
window.getAvailableConfigs = getAvailableConfigs;
window.shouldShowConfigSwitcher = shouldShowConfigSwitcher;
window.getDefaultConfig = getDefaultConfig;

// ✅ НОВЫЕ ГЛОБАЛЬНЫЕ ФУНКЦИИ ДЛЯ УПРАВЛЕНИЯ ТЕМОЙ
window.getEffectiveTheme = getEffectiveTheme;
window.applyThemeToWidget = applyThemeToWidget;
window.setGlobalTheme = setGlobalTheme;
window.baseConfig = baseConfig;

// ✅ КРИТИЧЕСКИ ВАЖНО: Экспорт глобальных настроек
window.GlobalConfigSettings = GlobalConfigSettings;
// ===============================================
// ПРИМЕРЫ ИСПОЛЬЗОВАНИЯ НОВЫХ НАСТРОЕК
// ===============================================

/*
// 🎛️ УПРАВЛЕНИЕ ПЕРЕКЛЮЧАТЕЛЕМ КОНФИГУРАЦИЙ:

// 1. ОТКЛЮЧИТЬ переключатель полностью (фиксированная конфигурация)
window.ChatConfigManager.setConfigSwitcherEnabled(false);

// 2. ВКЛЮЧИТЬ переключатель обратно
window.ChatConfigManager.setConfigSwitcherEnabled(true);

// 3. ОТКЛЮЧИТЬ конкретные конфигурации в списке
window.ChatConfigManager.setConfigEnabled('medicalConfig', false);  // Убрать медицину
window.ChatConfigManager.setConfigEnabled('techConfig', false);     // Убрать техподдержку

// 4. ВКЛЮЧИТЬ конфигурации обратно
window.ChatConfigManager.setConfigEnabled('medicalConfig', true);

// 5. ИЗМЕНИТЬ порядок в списке
window.ChatConfigManager.setConfigOrder('ecommerceConfig', 1);  // Магазин первым
window.ChatConfigManager.setConfigOrder('financeConfig', 2);    // Финансы вторым

// 6. ПАКЕТНЫЕ настройки
window.ChatConfigManager.applySettings({
    switcherEnabled: true,
    defaultConfig: 'ecommerceConfig',
    configStates: {
        financeConfig: { enabled: true, order: 1 },
        ecommerceConfig: { enabled: true, order: 2 },
        techConfig: { enabled: false },           // Отключаем
        medicalConfig: { enabled: false },        // Отключаем
        educationConfig: { enabled: true, order: 3 },
        restaurantConfig: { enabled: true, order: 4 },
        minimalConfig: { enabled: false }         // Отключаем
    }
});

// 7. ПОЛУЧИТЬ текущие настройки
const currentSettings = window.ChatConfigManager.getSettings();
console.log('Текущие настройки:', currentSettings);
*/

// ===============================================
// ИНСТРУКЦИИ ПО ИНТЕГРАЦИИ С НАСТРОЙКАМИ
// ===============================================

/*
ИНТЕГРАЦИЯ С НАСТРОЙКАМИ ПЕРЕКЛЮЧАТЕЛЯ:

1. БЕЗ ПЕРЕКЛЮЧАТЕЛЯ (фиксированная конфигурация):
   <script>
   window.webchatSelectedConfig = 'financeConfig'; // Фиксированная конфигурация
   </script>
   <script>
   // Отключаем переключатель
   window.addEventListener('DOMContentLoaded', function() {
       if (window.ChatConfigManager) {
           window.ChatConfigManager.setConfigSwitcherEnabled(false);
       }
   });
   </script>
   <script src="/smart2/webchat-integration.js"></script>

2. С ПЕРЕКЛЮЧАТЕЛЕМ (но ограниченным выбором):
   <script>
   window.webchatSelectedConfig = 'financeConfig'; // Конфигурация по умолчанию
   </script>
   <script>
   // Настраиваем доступные конфигурации
   window.addEventListener('DOMContentLoaded', function() {
       if (window.ChatConfigManager) {
           // Включаем только нужные конфигурации
           window.ChatConfigManager.setConfigEnabled('financeConfig', true);
           window.ChatConfigManager.setConfigEnabled('ecommerceConfig', true);
           window.ChatConfigManager.setConfigEnabled('techConfig', false);   // Отключаем
           window.ChatConfigManager.setConfigEnabled('medicalConfig', false); // Отключаем
           window.ChatConfigManager.setConfigEnabled('educationConfig', false); // Отключаем
           window.ChatConfigManager.setConfigEnabled('restaurantConfig', false); // Отключаем
           window.ChatConfigManager.setConfigEnabled('minimalConfig', false); // Отключаем
       }
   });
   </script>
   <script src="/smart2/webchat-integration.js"></script>

3. ПОЛНЫЙ ПЕРЕКЛЮЧАТЕЛЬ (все конфигурации):
   <script>
   window.webchatSelectedConfig = 'financeConfig'; // Конфигурация по умолчанию
   </script>
   <script src="/smart2/webchat-integration.js"></script>
   // Переключатель будет показан автоматически

4. НАСТРОЙКА В RUNTIME:
   // После загрузки чата можно изменить настройки
   window.ChatConfigManager.applySettings({
       switcherEnabled: false,  // Отключить переключатель
       defaultConfig: 'ecommerceConfig'
   });
   
5. ПРОВЕРКА ТЕКУЩИХ НАСТРОЕК:
   console.log('Переключатель доступен:', window.shouldShowConfigSwitcher());
   console.log('Доступные конфигурации:', Object.keys(window.getAvailableConfigs()));
   console.log('Конфигурация по умолчанию:', window.getDefaultConfig().botInfo.name);

6. ПРИМЕРЫ УПРАВЛЕНИЯ НАСТРОЙКАМИ ПРИОРИТЕТА:
   // ✅ Включить индивидуальные настройки для всех конфигураций:
   // window.ChatConfigManager.setUseIndividualSettings(true);

   // ✅ Выключить индивидуальные настройки (использовать базовые):
   // window.ChatConfigManager.setUseIndividualSettings(false);

   // ✅ Частичное переопределение - берем все из базовых и меняем только то, что указано:
   // window.ChatConfigManager.setAllowPartialOverride(true);

   // ✅ Полная замена - используем только индивидуальные настройки:
   // window.ChatConfigManager.setAllowPartialOverride(false);
*/