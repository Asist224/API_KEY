// monitoring-config.js - Конфигурация системы мониторинга
// =====================================================================================
// СИСТЕМА КОНФИГУРАЦИИ ДЛЯ МОНИТОРИНГА ЧАТОВ
// =====================================================================================
// Автоматически сгенерировано: 14.11.2025 06:44:58

// ===============================================
// ГЛАВНЫЕ НАСТРОЙКИ МОНИТОРИНГА
// ===============================================
const MonitoringConfig = {
    "language": "ru",
    "display": {
        "filters": {
            "period": true,
            "configuration": false,
            "platform": true,
            "search": true,
            "refreshButton": true,
            "analysisButtons": true
        },
        "statsCards": {
            "totalUsers": true,
            "activeSessions": true,
            "avgSessionTime": true,
            "totalMessages": true
        },
        "charts": {
            "activity": true,
            "geography": true,
            "platforms": true
        },
        "tableColumns": {
            "leadScore": true,
            "bantAnalysis": true,
            "contactName": true,
            "contactPhone": true,
            "contactEmail": true,
            "contactMessengers": true,
            "contactCompany": false,
            "sessionId": false,
            "ipAddress": false,
            "country": true,
            "city": false,
            "platform": true,
            "configuration": false,
            "startTime": false,
            "duration": true,
            "messages": true,
            "satisfaction": false,
            "crmStatus": true,
            "status": true,
            "actions": true,
            "actionButtons": {
                "viewDialog": true,
                "analyze": true,
                "viewAnalysis": true,
                "extractContacts": true,
                "deleteRecord": true
            }
        }
    },
    "crmIntegration": {
        "enabled": true
    },
    "emailMonitoring": {
        "enabled": true
    },
    "highlights": {
        "enabled": true,
        "types": {
            "pricing": {
                "enabled": true,
                "color": "#FFD700",
                "icon": "💰"
            },
            "objection": {
                "enabled": true,
                "color": "#FF6B6B",
                "icon": "❌"
            },
            "buying_signal": {
                "enabled": true,
                "color": "#51CF66",
                "icon": "✅"
            }
        }
    },
    "analysisLanguageSync": {
        "autoSync": false
    },
    "availableConfigurations": {
        "financeConfig": {
            "enabled": true,
            "order": 1,
            "icon": "💰",
            "labels": {
                "ru": "Финансы",
                "en": "Finance",
                "es": "Finanzas",
                "fr": "Finances",
                "de": "Finanzen",
                "it": "Finanza",
                "pt": "Finanças",
                "zh": "金融",
                "ja": "ファイナンス",
                "ko": "금융",
                "ua": "Фінанси"
            }
        },
        "ecommerceConfig": {
            "enabled": true,
            "order": 2,
            "icon": "🛒",
            "labels": {
                "ru": "Магазин",
                "en": "Shop",
                "es": "Tienda",
                "fr": "Boutique",
                "de": "Shop",
                "it": "Negozio",
                "pt": "Loja",
                "zh": "商店",
                "ja": "ショップ",
                "ko": "상점",
                "ua": "Магазин"
            }
        },
        "techConfig": {
            "enabled": true,
            "order": 3,
            "icon": "🤖",
            "labels": {
                "ru": "Поддержка",
                "en": "Support",
                "es": "Soporte",
                "fr": "Support",
                "de": "Support",
                "it": "Supporto",
                "pt": "Suporte",
                "zh": "支持",
                "ja": "サポート",
                "ko": "지원",
                "ua": "Підтримка"
            }
        },
        "educationConfig": {
            "enabled": false,
            "order": 4,
            "icon": "📚",
            "labels": {
                "ru": "Обучение",
                "en": "Education",
                "es": "Educación",
                "fr": "Éducation",
                "de": "Bildung",
                "it": "Istruzione",
                "pt": "Educação",
                "zh": "教育",
                "ja": "教育",
                "ko": "교육",
                "ua": "Навчання"
            }
        },
        "medicalConfig": {
            "enabled": false,
            "order": 5,
            "icon": "👩‍⚕️",
            "labels": {
                "ru": "Медицина",
                "en": "Medical",
                "es": "Medicina",
                "fr": "Médecine",
                "de": "Medizin",
                "it": "Medicina",
                "pt": "Medicina",
                "zh": "医疗",
                "ja": "医療",
                "ko": "의료",
                "ua": "Медицина"
            }
        },
        "restaurantConfig": {
            "enabled": false,
            "order": 6,
            "icon": "👨‍🍳",
            "labels": {
                "ru": "Ресторан",
                "en": "Restaurant",
                "es": "Restaurante",
                "fr": "Restaurant",
                "de": "Restaurant",
                "it": "Ristorante",
                "pt": "Restaurante",
                "zh": "餐厅",
                "ja": "レストラン",
                "ko": "레스토랑",
                "ua": "Ресторан"
            }
        },
        "minimalConfig": {
            "enabled": false,
            "order": 7,
            "icon": "💬",
            "labels": {
                "ru": "Базовый",
                "en": "Basic",
                "es": "Básico",
                "fr": "Basique",
                "de": "Basis",
                "it": "Base",
                "pt": "Básico",
                "zh": "基础",
                "ja": "ベーシック",
                "ko": "기본",
                "ua": "Базовий"
            }
        }
    },
    "availableAnalysisLanguages": {
        "ru": {
            "enabled": true,
            "order": 1,
            "flag": "🇷🇺",
            "labels": {
                "ru": "Русский",
                "en": "Russian",
                "es": "Ruso",
                "fr": "Russe",
                "de": "Russisch",
                "it": "Russo",
                "pt": "Russo",
                "zh": "俄语",
                "ja": "ロシア語",
                "ko": "러시아어",
                "ua": "Російська"
            }
        },
        "en": {
            "enabled": true,
            "order": 2,
            "flag": "🇬🇧",
            "labels": {
                "ru": "Английский",
                "en": "English",
                "es": "Inglés",
                "fr": "Anglais",
                "de": "Englisch",
                "it": "Inglese",
                "pt": "Inglês",
                "zh": "英语",
                "ja": "英語",
                "ko": "영어",
                "ua": "Англійська"
            }
        },
        "es": {
            "enabled": false,
            "order": 3,
            "flag": "🇪🇸",
            "labels": {
                "ru": "Испанский",
                "en": "Spanish",
                "es": "Español",
                "fr": "Espagnol",
                "de": "Spanisch",
                "it": "Spagnolo",
                "pt": "Espanhol",
                "zh": "西班牙语",
                "ja": "スペイン語",
                "ko": "스페인어",
                "ua": "Іспанська"
            }
        },
        "fr": {
            "enabled": false,
            "order": 4,
            "flag": "🇫🇷",
            "labels": {
                "ru": "Французский",
                "en": "French",
                "es": "Francés",
                "fr": "Français",
                "de": "Französisch",
                "it": "Francese",
                "pt": "Francês",
                "zh": "法语",
                "ja": "フランス語",
                "ko": "프랑스어",
                "ua": "Французька"
            }
        },
        "de": {
            "enabled": false,
            "order": 5,
            "flag": "🇩🇪",
            "labels": {
                "ru": "Немецкий",
                "en": "German",
                "es": "Alemán",
                "fr": "Allemand",
                "de": "Deutsch",
                "it": "Tedesco",
                "pt": "Alemão",
                "zh": "德语",
                "ja": "ドイツ語",
                "ko": "독일어",
                "ua": "Німецька"
            }
        },
        "it": {
            "enabled": false,
            "order": 6,
            "flag": "🇮🇹",
            "labels": {
                "ru": "Итальянский",
                "en": "Italian",
                "es": "Italiano",
                "fr": "Italien",
                "de": "Italienisch",
                "it": "Italiano",
                "pt": "Italiano",
                "zh": "意大利语",
                "ja": "イタリア語",
                "ko": "이탈리아어",
                "ua": "Італійська"
            }
        },
        "pt": {
            "enabled": false,
            "order": 7,
            "flag": "🇵🇹",
            "labels": {
                "ru": "Португальский",
                "en": "Portuguese",
                "es": "Portugués",
                "fr": "Portugais",
                "de": "Portugiesisch",
                "it": "Portoghese",
                "pt": "Português",
                "zh": "葡萄牙语",
                "ja": "ポルトガル語",
                "ko": "포르투갈어",
                "ua": "Португальська"
            }
        },
        "zh": {
            "enabled": false,
            "order": 8,
            "flag": "🇨🇳",
            "labels": {
                "ru": "Китайский",
                "en": "Chinese",
                "es": "Chino",
                "fr": "Chinois",
                "de": "Chinesisch",
                "it": "Cinese",
                "pt": "Chinês",
                "zh": "中文",
                "ja": "中国語",
                "ko": "중국어",
                "ua": "Китайська"
            }
        },
        "ja": {
            "enabled": false,
            "order": 9,
            "flag": "🇯🇵",
            "labels": {
                "ru": "Японский",
                "en": "Japanese",
                "es": "Japonés",
                "fr": "Japonais",
                "de": "Japanisch",
                "it": "Giapponese",
                "pt": "Japonês",
                "zh": "日语",
                "ja": "日本語",
                "ko": "일본어",
                "ua": "Японська"
            }
        },
        "ko": {
            "enabled": false,
            "order": 10,
            "flag": "🇰🇷",
            "labels": {
                "ru": "Корейский",
                "en": "Korean",
                "es": "Coreano",
                "fr": "Coréen",
                "de": "Koreanisch",
                "it": "Coreano",
                "pt": "Coreano",
                "zh": "韩语",
                "ja": "韓国語",
                "ko": "한국어",
                "ua": "Корейська"
            }
        },
        "ua": {
            "enabled": false,
            "order": 11,
            "flag": "🇺🇦",
            "labels": {
                "ru": "Украинский",
                "en": "Ukrainian",
                "es": "Ucraniano",
                "fr": "Ukrainien",
                "de": "Ukrainisch",
                "it": "Ucraino",
                "pt": "Ucraniano",
                "zh": "乌克兰语",
                "ja": "ウクライナ語",
                "ko": "우크라이나어",
                "ua": "Українська"
            }
        }
    },
    "availableResultLanguages": {
        "ru": {
            "enabled": true,
            "order": 1,
            "flag": "🇷🇺",
            "labels": {
                "ru": "Русский",
                "en": "Russian",
                "es": "Ruso",
                "fr": "Russe",
                "de": "Russisch",
                "it": "Russo",
                "pt": "Russo",
                "zh": "俄语",
                "ja": "ロシア語",
                "ko": "러시아어",
                "ua": "Російська"
            }
        },
        "en": {
            "enabled": true,
            "order": 2,
            "flag": "🇬🇧",
            "labels": {
                "ru": "Английский",
                "en": "English",
                "es": "Inglés",
                "fr": "Anglais",
                "de": "Englisch",
                "it": "Inglese",
                "pt": "Inglês",
                "zh": "英语",
                "ja": "英語",
                "ko": "영어",
                "ua": "Англійська"
            }
        },
        "es": {
            "enabled": false,
            "order": 3,
            "flag": "🇪🇸",
            "labels": {
                "ru": "Испанский",
                "en": "Spanish",
                "es": "Español",
                "fr": "Espagnol",
                "de": "Spanisch",
                "it": "Spagnolo",
                "pt": "Espanhol",
                "zh": "西班牙语",
                "ja": "スペイン語",
                "ko": "스페인어",
                "ua": "Іспанська"
            }
        },
        "fr": {
            "enabled": false,
            "order": 4,
            "flag": "🇫🇷",
            "labels": {
                "ru": "Французский",
                "en": "French",
                "es": "Francés",
                "fr": "Français",
                "de": "Französisch",
                "it": "Francese",
                "pt": "Francês",
                "zh": "法语",
                "ja": "フランス語",
                "ko": "프랑스어",
                "ua": "Французька"
            }
        },
        "de": {
            "enabled": false,
            "order": 5,
            "flag": "🇩🇪",
            "labels": {
                "ru": "Немецкий",
                "en": "German",
                "es": "Alemán",
                "fr": "Allemand",
                "de": "Deutsch",
                "it": "Tedesco",
                "pt": "Alemão",
                "zh": "德语",
                "ja": "ドイツ語",
                "ko": "독일어",
                "ua": "Німецька"
            }
        },
        "it": {
            "enabled": false,
            "order": 6,
            "flag": "🇮🇹",
            "labels": {
                "ru": "Итальянский",
                "en": "Italian",
                "es": "Italiano",
                "fr": "Italien",
                "de": "Italienisch",
                "it": "Italiano",
                "pt": "Italiano",
                "zh": "意大利语",
                "ja": "イタリア語",
                "ko": "이탈리아어",
                "ua": "Італійська"
            }
        },
        "pt": {
            "enabled": false,
            "order": 7,
            "flag": "🇵🇹",
            "labels": {
                "ru": "Португальский",
                "en": "Portuguese",
                "es": "Portugués",
                "fr": "Portugais",
                "de": "Portugiesisch",
                "it": "Portoghese",
                "pt": "Português",
                "zh": "葡萄牙语",
                "ja": "ポルトガル語",
                "ko": "포르투갈어",
                "ua": "Португальська"
            }
        },
        "zh": {
            "enabled": false,
            "order": 8,
            "flag": "🇨🇳",
            "labels": {
                "ru": "Китайский",
                "en": "Chinese",
                "es": "Chino",
                "fr": "Chinois",
                "de": "Chinesisch",
                "it": "Cinese",
                "pt": "Chinês",
                "zh": "中文",
                "ja": "中国語",
                "ko": "중국어",
                "ua": "Китайська"
            }
        },
        "ja": {
            "enabled": false,
            "order": 9,
            "flag": "🇯🇵",
            "labels": {
                "ru": "Японский",
                "en": "Japanese",
                "es": "Japonés",
                "fr": "Japonais",
                "de": "Japanisch",
                "it": "Giapponese",
                "pt": "Japonês",
                "zh": "日语",
                "ja": "日本語",
                "ko": "일본어",
                "ua": "Японська"
            }
        },
        "ko": {
            "enabled": false,
            "order": 10,
            "flag": "🇰🇷",
            "labels": {
                "ru": "Корейский",
                "en": "Korean",
                "es": "Coreano",
                "fr": "Coréen",
                "de": "Koreanisch",
                "it": "Coreano",
                "pt": "Coreano",
                "zh": "韩语",
                "ja": "韓国語",
                "ko": "한국어",
                "ua": "Корейська"
            }
        },
        "ua": {
            "enabled": false,
            "order": 11,
            "flag": "🇺🇦",
            "labels": {
                "ru": "Украинский",
                "en": "Ukrainian",
                "es": "Ucraniano",
                "fr": "Ukrainien",
                "de": "Ukrainisch",
                "it": "Ucraino",
                "pt": "Ucraniano",
                "zh": "乌克兰语",
                "ja": "ウクライナ語",
                "ko": "우크라이나어",
                "ua": "Українська"
            }
        }
    },
    "availablePlatforms": {
        "webchat": {
            "enabled": true,
            "order": 1,
            "icon": "💬",
            "labels": {
                "ru": "WebChat",
                "en": "WebChat",
                "es": "WebChat",
                "fr": "WebChat",
                "de": "WebChat",
                "it": "WebChat",
                "pt": "WebChat",
                "zh": "WebChat",
                "ja": "WebChat",
                "ko": "WebChat",
                "ua": "WebChat"
            }
        },
        "telegram": {
            "enabled": true,
            "order": 2,
            "icon": "✈️",
            "labels": {
                "ru": "Telegram",
                "en": "Telegram",
                "es": "Telegram",
                "fr": "Telegram",
                "de": "Telegram",
                "it": "Telegram",
                "pt": "Telegram",
                "zh": "Telegram",
                "ja": "テレグラム",
                "ko": "텔레그램",
                "ua": "Telegram"
            }
        },
        "whatsapp": {
            "enabled": true,
            "order": 3,
            "icon": "💚",
            "labels": {
                "ru": "WhatsApp",
                "en": "WhatsApp",
                "es": "WhatsApp",
                "fr": "WhatsApp",
                "de": "WhatsApp",
                "it": "WhatsApp",
                "pt": "WhatsApp",
                "zh": "WhatsApp",
                "ja": "WhatsApp",
                "ko": "왓츠앱",
                "ua": "WhatsApp"
            }
        },
        "facebook": {
            "enabled": true,
            "order": 4,
            "icon": "👤",
            "labels": {
                "ru": "Facebook",
                "en": "Facebook",
                "es": "Facebook",
                "fr": "Facebook",
                "de": "Facebook",
                "it": "Facebook",
                "pt": "Facebook",
                "zh": "Facebook",
                "ja": "Facebook",
                "ko": "페이스북",
                "ua": "Facebook"
            }
        },
        "instagram": {
            "enabled": false,
            "order": 5,
            "icon": "📷",
            "labels": {
                "ru": "Instagram",
                "en": "Instagram",
                "es": "Instagram",
                "fr": "Instagram",
                "de": "Instagram",
                "it": "Instagram",
                "pt": "Instagram",
                "zh": "Instagram",
                "ja": "インスタグラム",
                "ko": "인스타그램",
                "ua": "Instagram"
            }
        },
        "viber": {
            "enabled": false,
            "order": 6,
            "icon": "💜",
            "labels": {
                "ru": "Viber",
                "en": "Viber",
                "es": "Viber",
                "fr": "Viber",
                "de": "Viber",
                "it": "Viber",
                "pt": "Viber",
                "zh": "Viber",
                "ja": "Viber",
                "ko": "Viber",
                "ua": "Viber"
            }
        },
        "vk": {
            "enabled": false,
            "order": 7,
            "icon": "🔵",
            "labels": {
                "ru": "VKontakte",
                "en": "VKontakte",
                "es": "VKontakte",
                "fr": "VKontakte",
                "de": "VKontakte",
                "it": "VKontakte",
                "pt": "VKontakte",
                "zh": "VKontakte",
                "ja": "VKontakte",
                "ko": "VKontakte",
                "ua": "VKontakte"
            }
        },
        "slack": {
            "enabled": false,
            "order": 8,
            "icon": "🔷",
            "labels": {
                "ru": "Slack",
                "en": "Slack",
                "es": "Slack",
                "fr": "Slack",
                "de": "Slack",
                "it": "Slack",
                "pt": "Slack",
                "zh": "Slack",
                "ja": "Slack",
                "ko": "Slack",
                "ua": "Slack"
            }
        },
        "discord": {
            "enabled": false,
            "order": 9,
            "icon": "🎮",
            "labels": {
                "ru": "Discord",
                "en": "Discord",
                "es": "Discord",
                "fr": "Discord",
                "de": "Discord",
                "it": "Discord",
                "pt": "Discord",
                "zh": "Discord",
                "ja": "Discord",
                "ko": "디스코드",
                "ua": "Discord"
            }
        }
    },
    "theme": {
        "mode": "dark"
    },
    "branding": {
        "enabled": true,
        "logoType": "svg",
        "logoSvg": "<svg width=\"32\" height=\"32\" viewBox=\"0 0 32 32\" fill=\"none\" xmlns=\"http://www.w3.org/2000/svg\">\n            <circle cx=\"16\" cy=\"16\" r=\"15\" fill=\"url(#brandGrad1)\" opacity=\"0.12\"/>\n            <g transform=\"translate(8, 8)\">\n                <circle cx=\"8\" cy=\"8\" r=\"2.2\" fill=\"url(#brandGrad1)\"/>\n                <circle cx=\"2\" cy=\"4\" r=\"1.3\" fill=\"url(#brandGrad2)\"/>\n                <circle cx=\"14\" cy=\"4\" r=\"1.3\" fill=\"url(#brandGrad2)\"/>\n                <circle cx=\"2\" cy=\"12\" r=\"1.3\" fill=\"url(#brandGrad2)\"/>\n                <circle cx=\"14\" cy=\"12\" r=\"1.3\" fill=\"url(#brandGrad2)\"/>\n                <circle cx=\"8\" cy=\"1\" r=\"1.3\" fill=\"url(#brandGrad2)\"/>\n                <circle cx=\"8\" cy=\"15\" r=\"1.3\" fill=\"url(#brandGrad2)\"/>\n                <line x1=\"8\" y1=\"8\" x2=\"2\" y2=\"4\" stroke=\"url(#brandGrad1)\" stroke-width=\"0.8\" opacity=\"0.7\"/>\n                <line x1=\"8\" y1=\"8\" x2=\"14\" y2=\"4\" stroke=\"url(#brandGrad1)\" stroke-width=\"0.8\" opacity=\"0.7\"/>\n                <line x1=\"8\" y1=\"8\" x2=\"2\" y2=\"12\" stroke=\"url(#brandGrad1)\" stroke-width=\"0.8\" opacity=\"0.7\"/>\n                <line x1=\"8\" y1=\"8\" x2=\"14\" y2=\"12\" stroke=\"url(#brandGrad1)\" stroke-width=\"0.8\" opacity=\"0.7\"/>\n                <line x1=\"8\" y1=\"8\" x2=\"8\" y2=\"1\" stroke=\"url(#brandGrad1)\" stroke-width=\"0.8\" opacity=\"0.7\"/>\n                <line x1=\"8\" y1=\"8\" x2=\"8\" y2=\"15\" stroke=\"url(#brandGrad1)\" stroke-width=\"0.8\" opacity=\"0.7\"/>\n            </g>\n            <defs>\n                <linearGradient id=\"brandGrad1\" x1=\"0%\" y1=\"0%\" x2=\"100%\" y2=\"100%\">\n                    <stop offset=\"0%\" style=\"stop-color:#6366f1\"/>\n                    <stop offset=\"100%\" style=\"stop-color:#8b5cf6\"/>\n                </linearGradient>\n                <linearGradient id=\"brandGrad2\" x1=\"0%\" y1=\"0%\" x2=\"100%\" y2=\"100%\">\n                    <stop offset=\"0%\" style=\"stop-color:#3b82f6\"/>\n                    <stop offset=\"100%\" style=\"stop-color:#6366f1\"/>\n                </linearGradient>\n            </defs>\n        </svg>",
        "icon": "🤖",
        "imageUrl": "",
        "companyName": "NexusMindAI",
        "poweredByText": "Powered by",
        "size": {
            "logoWidth": 32,
            "logoHeight": 32,
            "fontSize": 12
        }
    },
    "technical": {
        "refreshInterval": 30000,
        "itemsPerPage": 10,
        "dataEndpoint": "https://n8n.cryptomator.pro/webhook/chat-monitoring-data",
        "dialogsEndpoint": "https://n8n.cryptomator.pro/webhook/chat-dialogs",
        "analyzeEndpoint": "https://n8n.cryptomator.pro/webhook/analyze-dialog",
        "autoAnalysisSettingsEndpoint": "https://n8n.cryptomator.pro/webhook/auto-analysis-settings",
        "cleanupSettingsEndpoint": "https://n8n.cryptomator.pro/webhook/cleanup-settings",
        "updateCleanupSettingsEndpoint": "https://n8n.cryptomator.pro/webhook/update-cleanup-settings",
        "getAnalysisEndpoint": "https://n8n.cryptomator.pro/webhook/get-analysis",
        "getAllAnalysisEndpoint": "https://n8n.cryptomator.pro/webhook/get-all-analysis",
        "serverTimeEndpoint": "https://n8n.cryptomator.pro/webhook/server-time",
        "extractContactsEndpoint": "https://n8n.cryptomator.pro/webhook/extract-contact-data",
        "getContactsEndpoint": "https://n8n.cryptomator.pro/webhook/get-contact-data",
        "sendToCRMEndpoint": "https://n8n.cryptomator.pro/webhook-test/send-to-kommocrm",
        "getCRMStatusEndpoint": "https://n8n.cryptomator.pro/webhook/crm-status",
        "crmSettingsEndpoint": "https://n8n.cryptomator.pro/webhook/crm-settings",
        "updateCRMSettingsEndpoint": "https://n8n.cryptomator.pro/webhook/update-crm-settings",
        "emailDataEndpoint": "https://n8n.cryptomator.pro/webhook/email-monitoring-data",
        "emailDialogsEndpoint": "https://n8n.cryptomator.pro/webhook/email-dialogs",
        "analyzeEmailEndpoint": "https://n8n.cryptomator.pro/webhook/analyze-email-dialog",
        "getEmailAnalysisEndpoint": "https://n8n.cryptomator.pro/webhook/get-email-analysis",
        "getAllEmailAnalysisEndpoint": "https://n8n.cryptomator.pro/webhook/get-all-email-analysis",
        "extractEmailContactsEndpoint": "https://n8n.cryptomator.pro/webhook/extract-email-contact",
        "getEmailContactsEndpoint": "https://n8n.cryptomator.pro/webhook/get-email-contact-data",
        "getAnalysisLanguageEndpoint": "https://n8n.cryptomator.pro/webhook/get-analysis-language",
        "setAnalysisLanguageEndpoint": "https://n8n.cryptomator.pro/webhook/save-analysis-language",
        "deleteSessionEndpoint": "https://n8n.cryptomator.pro/webhook/delete-session",
        "deleteEmailEndpoint": "https://n8n.cryptomator.pro/webhook/delete-email",
        "detectHighlightsEndpoint": "https://n8n.cryptomator.pro/webhook/detect-highlights",
        "getHighlightsEndpoint": "https://n8n.cryptomator.pro/webhook/get-highlights",
        "authLoginEndpoint": "https://n8n.cryptomator.pro/webhook/auth-login",
        "authValidateEndpoint": "https://n8n.cryptomator.pro/webhook/auth-validate",
        "apiKey": "24fs-$r4d-defd-77ds-7eds"
    }
};

// ===============================================
// ПЕРЕВОДЫ ИНТЕРФЕЙСА
// ===============================================
const MonitoringTranslations = {
    // 🇷🇺 РУССКИЙ
    ru: {
        // Заголовок
        header: {
            title: "Monitoring Dashboard",
            live: "Live",
            settings: "Настройки"
        },
        
        // Фильтры
        filters: {
            period: {
                label: "Период",
                options: {
                    '1h': "Последний час",
                    '24h': "Последние 24 часа",
                    '7d': "Последняя неделя",
                    '30d': "Последний месяц",
                    'custom': "Произвольный период"
                },
                customStart: "Дата начала",
                customEnd: "Дата окончания"
            },
            configuration: {
                label: "Конфигурация",
                all: "Все конфигурации"
            },
            platform: {
                label: "Платформа",
                all: "Все платформы"
            },
            search: {
                placeholder: "Поиск по IP, стране, городу..."
            },
            buttons: {
                refresh: "Обновить",
                analyzeAll: "Анализ всех",
                analyzeByLanguage: "Анализ по языку",
                analyzeLabel: "Анализ диалогов"
            }
        },
        
        analysisResultLanguage: {
    label: "Язык результата анализа",
    modalTitle: "Выберите язык результатов анализа",
    notification: "Язык результатов анализа изменен на: {language}",
    loadError: "Ошибка загрузки языка анализа",
    setError: "Ошибка при установке языка",
    configError: "Конфигурация языков не найдена",
    containerError: "Контейнер для кнопок не найден"
},
        
        // Карточки статистики
        stats: {
            totalUsers: {
                title: "Всего пользователей",
                trend: "за период"
            },
            activeSessions: {
                title: "Активные сессии",
                trend: "Стабильно"
            },
            avgSessionTime: {
                title: "Среднее время сессии",
                trend: "за период"
            },
            totalMessages: {
                title: "Всего сообщений",
                trend: "за период"
            }
        },
        
        // Графики
        charts: {
            activity: {
                title: "Активность по времени",
                refresh: "Обновить график",
                yAxis: "Количество событий",
                currentHour: "Текущий час",
                events: "События"
            },
            geography: {
                title: "География пользователей",
                refresh: "Обновить график",
                noData: "Нет данных для отображения"
            },
            platforms: {
                title: "Распределение по платформам",
                refresh: "Обновить график",
                noData: "Нет данных для отображения"
            }
        },
        
        // Таблица
        table: {
            title: "Пользователи",
            export: "Экспорт",
            noData: "Нет данных для отображения",
            loading: "Загрузка данных...",
            columns: {
    leadScore: "Lead Score",
    contactName: "Имя",
    contactPhone: "Телефон",
    contactEmail: "Email",
    contactMessengers: "Мессенджеры",
    contactCompany: "Компания",
    sessionId: "Session ID",
    ipAddress: "IP адрес",
    country: "Страна",
    city: "Город",
    platform: "Платформа",
    configuration: "Конфигурация",
    startTime: "Время начала",
    duration: "Длительность",
    messages: "Сообщений",
    satisfaction: "Удовлетворенность",
    crmStatus: "CRM", 
    status: "Статус",
    actions: "Действия"
},
            status: {
                active: "Активен",
                inactive: "Неактивен"
            },
            actions: {
                viewDialog: "Диалог",
                analyze: "Анализ",
                highlights: "Highlights",
                viewAnalysis: "Результат",
                extractContacts: "Извлечь контакты",  // ДОБАВЬТЕ ЭТУ СТРОКУ
                updateContacts: "Обновить контакты",  // ДОБАВЬТЕ ЭТУ СТРОКУ
                deleteRecord: "Удалить"  // ДОБАВЬТЕ ЭТУ СТРОКУ
            }
        },
        
        // Пагинация
        pagination: {
            previous: "Назад",
            next: "Вперед"
        },
        
        // Модальные окна
        dialogs: {
            dialog: {
                title: "Диалог",
                loading: "Загрузка диалога...",
                notFound: "Диалог не найден",
                error: "Ошибка загрузки диалога",
                user: "Пользователь",
                bot: "Бот"
            },
            analysis: {
                title: "Анализ диалога",
                loading: "Анализируем диалог",
                error: "Ошибка при анализе диалога",
                analyzingAll: "Анализируем все диалоги...",
                timeNotice: "Это может занять несколько минут"
            },
            language: {
                title: "Выберите язык для анализа",
                russian: "Русский",
                english: "Английский"
            },
            settings: {
                title: "Настройки мониторинга",
                autoAnalysis: {
                    title: "Автоматический анализ диалогов",
                    enable: "Включить автоанализ",
                    delay: "Задержка после неактивности",
                    minutes: "минут",
                    serverMode: "Серверный режим",
                    enabledNotice: "Серверный автоанализ включен (проверка каждые 5 минут)",
                    disabledNotice: "Серверный автоанализ выключен"
                },
                dbCleanup: {
    title: "Автоматическая очистка базы данных",
    active: "Активна (ежедневно в 3:00)",
    monitoringData: "Хранить данные мониторинга",
    analysisResults: "Хранить результаты анализов",
    dialogsData: "Хранить диалоги",
    contactsData: "Хранить контактные данные",
    days: "дней"
},
                buttons: {
                    save: "Сохранить все настройки",
                    cancel: "Отмена"
                }
            }
        },
        
        // Форматирование
        formatting: {
            today: "Сегодня",
            yesterday: "Вчера",
            seconds: "сек",
            minutes: "мин",
            hours: "ч",
            unknown: "Н/Д",
            guest: "Гость"
        },
        
        // Ошибки
        errors: {
            loadData: "Не удалось загрузить данные. Проверьте подключение.",
            connectionError: "Ошибка подключения к серверу"
        },
        
        // Анализ
        analysis: {
            emotionalTone: {
                title: "Эмоциональный тон диалога",
                overall: "Общий тон",
                satisfaction: "Удовлетворенность клиента",
                positive: "Позитивный",
                negative: "Негативный",
                neutral: "Нейтральный"
            },
            needs: {
                title: "Выявленные потребности"
            },
            missedOpportunities: {
                title: "Упущенные возможности"
            },
            recommendations: {
                title: "Рекомендации по улучшению"
            },
            statistics: {
                title: "Общая статистика",
                totalDialogs: "Проанализировано диалогов",
                avgSatisfaction: "Средняя удовлетворенность",
                resolved: "Решено вопросов"
            }
        },
        
        // Уведомления
            notifications: {
            settingsSaved: "Все настройки успешно сохранены",
            settingsError: "Ошибка сохранения настроек",
            periodWarning: "Период хранения мониторинга должен быть от 7 до 365 дней",
            analysisWarning: "Период хранения анализов должен быть от 30 до 365 дней",
            dialogsWarning: "Период хранения диалогов должен быть от 7 до 365 дней",
            contactsWarning: "Период хранения контактов должен быть от 30 до 365 дней",
            copiedToClipboard: "Скопировано в буфер обмена",
            autoAnalysisEnabled: "Серверный автоанализ включен (проверка каждые 5 минут)",
            autoAnalysisDisabled: "Серверный автоанализ выключен",
            clientDataNotFound: "Данные клиента не найдены",
            deleteConfirm: "Вы уверены, что хотите удалить эту запись?",
            deleting: "Удаление записи...",
            deleteSuccess: "Запись успешно удалена",
            deleteError: "Ошибка при удалении записи"
        },
        
        auth: {
        loginSuccess: "Вход выполнен успешно!",
        logoutConfirm: "Вы уверены, что хотите выйти?",
        logoutSuccess: "Вы вышли из системы",
        logoutButton: "Выход",
        notAuthorized: "Пользователь не авторизован",
        accessDenied: "Доступ запрещен! Требуется роль: ",
        or: " или ",
        invalidCredentials: "Неверное имя пользователя или пароль",
        loginError: "Ошибка входа. Попробуйте снова.",
        modalTitle: "Monitoring Dashboard",
        modalSubtitle: "Введите учетные данные для доступа",
        usernameLabel: "Имя пользователя",
        usernamePlaceholder: "Введите логин",
        passwordLabel: "Пароль",
        passwordPlaceholder: "Введите пароль",
        rememberMe: "Запомнить меня на 7 дней",
        loginButton: "Войти",
        secureConnection: "Защищенное соединение"
    },
        
        // Модальное окно удаления
deleteModal: {
    title: "Подтверждение удаления",
    messageSession: "Вы уверены, что хотите удалить эту запись?",
    messageEmail: "Вы уверены, что хотите удалить эту email переписку?",
    cancel: "Отмена",
    confirm: "Удалить"
},
        
    // Контакты
    contacts: {
        title: "Контактные данные",
        name: "Имя",
        phone: "Телефон",
        email: "Email",
        messengers: "Мессенджеры",
        company: "Компания",
        extracting: "Извлечение контактов...",
        extracted: "Контакты извлечены",
        extractError: "Ошибка извлечения контактов",
        dataSource: "Источник данных",
        aiConfidence: "Уверенность AI",
        extractedFromDialog: "из диалога",
        extractedFromProfile: "из профиля"
    }, 
    
    clientCard: {
    title: "Карточка клиента",
    tabs: {
        overview: "Обзор",
        dialog: "Диалог", 
        details: "Детали",
        history: "История",
        analysis: "Результат анализа"
    },
    quickActions: {
        analyze: "Провести анализ",
        extractContacts: "Извлечь контакты"
    },
    overview: {
        messages: "Сообщений",
        duration: "Длительность",
        satisfaction: "Удовлетворенность",
        geolocation: "Геолокация",
        ipAddress: "IP адрес",
        country: "Страна",
        city: "Город",
        professionalInfo: "Профессиональная информация",
        company: "Компания",
        position: "Должность",
        location: "Местоположение"
    },
    details: {
        technicalInfo: "Техническая информация",
        sessionId: "Session ID",
        platform: "Платформа",
        configuration: "Конфигурация",
        language: "Язык",
        timestamps: "Временные метки",
        firstMessage: "Первое сообщение",
        lastActivity: "Последняя активность",
        dataSource: "Источник контактных данных",
        aiConfidence: "Уверенность AI"
    },
    history: {
        dialogStart: "Начало диалога",
        contactsExtracted: "Контакты извлечены",
        analysisCompleted: "Проведен анализ",
        satisfactionLevel: "удовлетворенность",
        lastActivity: "Последняя активность"
    },
    contact: {
        phone: "Телефон",
        email: "Email",
        copyToClipboard: "Нажмите для копирования",
        openInApp: "Открыть в приложении"
    },
    status: {
        active: "Активен",
        inactive: "Неактивен"
    }
}, 

// Highlights - НОВЫЙ БЛОК
    highlights: {
        title: "Ключевые моменты",
        button: " Highlights",
        analyzing: "Анализируем диалог...",
        analyzed: "Highlights обработаны",
        analyzeError: "Ошибка обработки highlights",
        noHighlights: "Ключевые моменты не найдены",
        found: "Найдено",
        reanalyze: "Повторный анализ", 
        newMessages: "новых сообщений",
        reanalyzing: "Повторный анализ...",
        reanalyzed: "Повторный анализ завершен!",
        reanalyzeError: "Ошибка при повторном анализе",
        newMessagesDetected: "Обнаружено {count} новых сообщений после последнего анализа",
        stats: {
            title: "Статистика",
            total: "Всего"
        },
        types: {
            pricing: "Цены",
            objection: "Возражения",
            buying_signal: "Сигналы покупки"
        },
        confidence: "Уверенность",
        scrollTo: "Перейти к сообщению",
        filters: {
            all: "Все",
            pricing: "Цены",
            objection: "Возражения",
            buying_signal: "Сигналы"
        },
        noFilterResults: "Нет highlights этого типа"
    },

leadScoring: {
    title: "Lead Scoring",
    score: "Lead Score",
    temperature: {
        hot: "Горячий",
        warm: "Теплый", 
        cold: "Холодный",
        leadType: "лид"
    },
    factors: {
        satisfaction: "Удовлетворенность",
        contacts: "Контакты",
        points: "баллов"
    },
    recommendation: "Рекомендация",
    urgentNotice: "Рекомендуется срочная отправка в CRM!",
    sendToCRM: "Отправить в CRM",
    sentToCRM: "Отправлено в CRM",
    confirmSend: "Отправить {temperature} лид (Score: {score}) в CRM?",
    sending: "Отправка данных в CRM...",
    successMessage: "Лид отправлен в CRM! Score: {score} ({temperature})",
    errorMessage: "Ошибка отправки в CRM: {error}",
    unknownError: "Неизвестная ошибка",
    crmIdLabel: "ID в CRM"
},

// BANT Analysis - НОВЫЙ БЛОК
bantAnalysis: {
    title: "BANT-квалификация",
    showAnalysis: "Показать анализ BANT",
    hideAnalysis: "Скрыть анализ",
    qualified: "Квалифицирован",
    notQualified: "Не квалифицирован",
    qualificationLevel: {
        label: "Уровень квалификации",
        SQL: "SQL (Sales Qualified Lead)",
        MQL: "MQL (Marketing Qualified Lead)", 
        cold: "Cold Lead (Холодный лид)",          // ⭐ ДОБАВЛЕНО
        warm: "Warm Lead (Теплый лид)",            // ⭐ ДОБАВЛЕНО
        hot: "Hot Lead (Горячий лид)",             // ⭐ ДОБАВЛЕНО
        Unqualified: "Не квалифицирован"
    },
    totalScore: "Общий балл",
    factors: {
        budget: {
            title: "💰 Budget (Бюджет)",
            score: "Балл",
            value: "Сумма",
            range: "Диапазон",
            mentioned: "Упоминание",
            confidence: "Уверенность",
            yes: "Да",
            no: "Нет"
        },
        authority: {
            title: "👤 Authority (Полномочия)",
            score: "Балл",
            role: "Роль",
            level: "Уровень",
            position: "Должность",
            confidence: "Уверенность",
            roles: {
                decision_maker: "Принимающий решение",
                influencer: "Влияющий",
                gatekeeper: "Контролирующий доступ",
                user: "Пользователь",
                unknown: "Неизвестно"
            },
            levels: {
                c_level: "C-level руководитель",
                executive: "Руководитель",
                manager: "Менеджер",
                user: "Пользователь",
                specialist: "Специалист",
                unknown: "Неизвестно"
            }
        },
        need: {
            title: "🎯 Need (Потребность)",
            score: "Балл",
            severity: "Критичность",
            painPoints: "Болевые точки",
            confidence: "Уверенность",
            severityLevels: {
                critical: "Критическая",
                high: "Высокая",
                medium: "Средняя",
                low: "Низкая"
            }
        },
        timeline: {
            title: "⏰ Timeline (Сроки)",
            score: "Балл",
            urgency: "Срочность",
            deadline: "Дедлайн",
            confidence: "Уверенность",
            urgencyLevels: {
                immediate: "Немедленно",
                this_week: "На этой неделе",
                this_month: "В этом месяце",
                this_quarter: "В этом квартале",
                short_term: "Короткий срок",
                medium_term: "Средний срок",
                long_term: "Долгий срок",
                later: "Позже",
                undefined: "Не определено"
            }
        }
    },
    reasoning: "Обоснование",
    description: "Описание",
    confidence: "Уверенность"
},

// Тестовый лид - ОТДЕЛЬНЫЙ БЛОК
testLead: {
    title: "🧪 Тестовый лид от системы мониторинга",
    name: "Тест",
    comments: "Это тестовый лид для проверки интеграции. Создан: {date}",
    testSuccess: "Подключение к CRM успешно! Тестовый лид создан.",
    specifyWebhook: "Укажите Webhook URL",
    testing: "Тестирование...",
    connectionError: "Ошибка подключения к CRM"
},

// Статусы CRM - ОТДЕЛЬНЫЙ БЛОК
crmStatuses: {
    loading: "Загружены статусы CRM: {count}",
    loadError: "Ошибка загрузки статусов CRM"
},

// Настройки CRM в модальном окне - ОТДЕЛЬНЫЙ БЛОК
crmSettings: {
    loaded: "Настройки CRM загружены",
    saveError: "Ошибка сохранения настроек CRM",
    specifyUrl: "Укажите Webhook URL для CRM", 
    urlMustContain: "Webhook URL должен быть корректным",
    testResultSuccess: "Успешно! ID лида: {id}",
    testResultError: "Ошибка: {error}"
},

// CRM интеграция - ОТДЕЛЬНЫЙ БЛОК
crm: {
    title: "Настройки интеграции с CRM",
    webhookUrl: "Webhook URL для CRM:",
    webhookHint: "Получите webhook URL в настройках вашей CRM системы",
    autoSend: "Автоматическая отправка горячих лидов:",
    autoSendHint: "Автоматически отправлять в CRM лиды с Lead Score ≥ минимального значения",
    minScore: "Минимальный Lead Score для автоотправки:",
    scoreRange: "(50-100)",
    testConnection: "Тест подключения",
    sendButton: "Отправить в CRM",
    sentButton: "Отправлено в CRM"

   },
   
   crmConfirm: {
    title: "Подтвердите действие",
    confirmMessage: "Отправить {temperature} лид (Score: {score}) в CRM?",
    cancelButton: "Отмена",
    sendButton: "Отправить"
},
   // Email мониторинг
    emailMonitoring: {
        tabs: {
            messengers: "Пользователи мессенджеров",
            email: "Email переписка"
        },
        table: {
            columns: {
                email: "Email",
                name: "Имя",
                subject: "Тема",
                status: "Статус",
                leadScore: "Lead Score",
                satisfaction: "Удовлетворенность",
                messages: "Сообщений",
                lastActivity: "Последняя активность",
                actions: "Действия"
            },
            status: {
                new: "📥 Новое",
                unread: "🔵 Непрочитанное",
                waiting: "⏳ Ожидает ответа",
                conversation: "💬 Переписка",
                inactive: "💤 Неактивная"
            },
            actions: {
                viewDialog: "Диалог",
                viewAnalysis: "Результат",
                extractContacts: "Обновить контакты",
                runAnalysis: "Анализ",
                deleteRecord: "Удалить"
            },
            noData: "Нет данных для отображения",
            loading: "Загрузка данных email..."
        }
    }
}, 
    
    // 🇺🇸 АНГЛИЙСКИЙ
    en: {
        // Заголовок
        header: {
            title: "Monitoring Dashboard",
            live: "Live",
            settings: "Settings"
        },
        
        // Фильтры
        filters: {
            period: {
                label: "Period",
                options: {
                    '1h': "Last hour",
                    '24h': "Last 24 hours",
                    '7d': "Last week",
                    '30d': "Last month",
                    'custom': "Custom period"
                },
                customStart: "Start date",
                customEnd: "End date"
            },
            configuration: {
                label: "Configuration",
                all: "All configurations"
            },
            platform: {
                label: "Platform",
                all: "All platforms"
            },
            search: {
                placeholder: "Search by IP, country, city..."
            },
            buttons: {
               refresh: "Refresh",
               analyzeAll: "Analyze all",
               analyzeByLanguage: "Analyze by language",
               analyzeLabel: "Dialog analysis"
            }
        },
        
        analysisResultLanguage: {
    label: "Analysis result language",
    modalTitle: "Select analysis results language",
    notification: "Analysis results language changed to: {language}",
    loadError: "Error loading analysis language",
    setError: "Error setting language",
    configError: "Language configuration not found",
    containerError: "Button container not found"
},
        
        // Карточки статистики
        stats: {
            totalUsers: {
                title: "Total users",
                trend: "for period"
            },
            activeSessions: {
                title: "Active sessions",
                trend: "Stable"
            },
            avgSessionTime: {
                title: "Average session time",
                trend: "for period"
            },
            totalMessages: {
                title: "Total messages",
                trend: "for period"
            }
        },
        
        // Графики
        charts: {
            activity: {
                title: "Activity over time",
                refresh: "Refresh chart",
                yAxis: "Number of events",
                currentHour: "Current hour",
                events: "Events"
            },
            geography: {
                title: "User geography",
                refresh: "Refresh chart",
                noData: "No data to display"
            },
            platforms: {
                title: "Platform distribution",
                refresh: "Refresh chart",
                noData: "No data to display"
            }
        },
        
        // Таблица
        table: {
            title: "Users",
            export: "Export",
            noData: "No data to display",
            loading: "Loading data...",
            columns: {
                leadScore: "Lead Score",
                contactName: "Name",
                contactPhone: "Phone",
                contactEmail: "Email",
                contactMessengers: "Messengers",
                contactCompany: "Company",
                sessionId: "Session ID",
                ipAddress: "IP address",
                country: "Country",
                city: "City",
                platform: "Platform",
                configuration: "Configuration",
                startTime: "Start time",
                duration: "Duration",
                messages: "Messages",
                satisfaction: "Satisfaction",
                crmStatus: "CRM", 
                status: "Status",
                actions: "Actions"
            },
            status: {
                active: "Active",
                inactive: "Inactive"
            },
            actions: {
                viewDialog: "Dialog",
                analyze: "Analyze",
                viewAnalysis: "Result",
                extractContacts: "Extract contacts",
                updateContacts: "Update contacts",
                deleteRecord: "Delete"
            }
        },
        
        // Пагинация
        pagination: {
            previous: "Previous",
            next: "Next"
        },
        
        // Модальные окна
        dialogs: {
            dialog: {
                title: "Dialog",
                loading: "Loading dialog...",
                notFound: "Dialog not found",
                error: "Error loading dialog",
                user: "User",
                bot: "Bot"
            },
            analysis: {
                title: "Dialog analysis",
                loading: "Analyzing dialog",
                error: "Error analyzing dialog",
                analyzingAll: "Analyzing all dialogs...",
                timeNotice: "This may take a few minutes"
            },
            language: {
                title: "Select language for analysis",
                russian: "Russian",
                english: "English"
            },
            settings: {
                title: "Monitoring settings",
                autoAnalysis: {
                    title: "Automatic dialog analysis",
                    enable: "Enable auto-analysis",
                    delay: "Delay after inactivity",
                    minutes: "minutes",
                    serverMode: "Server mode",
                    enabledNotice: "Server auto-analysis enabled (check every 5 minutes)",
                    disabledNotice: "Server auto-analysis disabled"
                },
                dbCleanup: {
    title: "Automatic Database Cleanup",
    active: "Active (daily at 3:00 AM)",
    monitoringData: "Keep monitoring data",
    analysisResults: "Keep analysis results",
    dialogsData: "Keep dialogs",
    contactsData: "Keep contact data",
    days: "days"
},
                buttons: {
                    save: "Save all settings",
                    cancel: "Cancel"
                }
            }
        },
        
        // Форматирование
        formatting: {
            today: "Today",
            yesterday: "Yesterday",
            seconds: "sec",
            minutes: "min",
            hours: "h",
            unknown: "N/A",
            guest: "Guest"
        },
        
        // Ошибки
        errors: {
            loadData: "Failed to load data. Check your connection.",
            connectionError: "Server connection error"
        },
        
        // Анализ
        analysis: {
            emotionalTone: {
                title: "Dialog emotional tone",
                overall: "Overall tone",
                satisfaction: "Customer satisfaction",
                positive: "Positive",
                negative: "Negative",
                neutral: "Neutral"
            },
            needs: {
                title: "Identified needs"
            },
            missedOpportunities: {
                title: "Missed opportunities"
            },
            recommendations: {
                title: "Improvement recommendations"
            },
            statistics: {
                title: "Overall statistics",
                totalDialogs: "Dialogs analyzed",
                avgSatisfaction: "Average satisfaction",
                resolved: "Issues resolved"
            }
        },
        
        // Уведомления
            notifications: {
            settingsSaved: "All settings saved successfully",
            settingsError: "Error saving settings",
            periodWarning: "Monitoring retention period must be between 7 and 365 days",
            analysisWarning: "Analysis retention period must be between 30 and 365 days",
            dialogsWarning: "Dialog retention period must be between 7 and 365 days",
            contactsWarning: "Contact retention period must be between 30 and 365 days",
            copiedToClipboard: "Copied to clipboard",
            autoAnalysisEnabled: "Server auto-analysis enabled (check every 5 minutes)",
            autoAnalysisDisabled: "Server auto-analysis disabled",
            clientDataNotFound: "Client data not found",
            deleting: "Deleting record...",
            deleteSuccess: "Record successfully deleted",
            deleteError: "Error deleting record"
        },
        
        auth: {
        loginSuccess: "Login successful!",
        logoutConfirm: "Are you sure you want to log out?",
        logoutSuccess: "You have been logged out",
        logoutButton: "Logout",
        notAuthorized: "User not authorized",
        accessDenied: "Access denied! Required role: ",
        or: " or ",
        invalidCredentials: "Invalid username or password",
        loginError: "Login error. Please try again.",
        modalTitle: "Monitoring Dashboard",
        modalSubtitle: "Enter your credentials to access",
        usernameLabel: "Username",
        usernamePlaceholder: "Enter username",
        passwordLabel: "Password",
        passwordPlaceholder: "Enter password",
        rememberMe: "Remember me for 7 days",
        loginButton: "Login",
        secureConnection: "Secure connection"
    },
        
        deleteModal: {
    title: "Delete Confirmation",
    messageSession: "Are you sure you want to delete this record?",
    messageEmail: "Are you sure you want to delete this email conversation?",
    cancel: "Cancel",
    confirm: "Delete"
},
        
        // Контакты
        contacts: {
            title: "Contact Information",
            name: "Name",
            phone: "Phone",
            email: "Email",
            messengers: "Messengers",
            company: "Company",
            extracting: "Extracting contacts...",
            extracted: "Contacts extracted",
            extractError: "Error extracting contacts",
            dataSource: "Data source",
            aiConfidence: "AI Confidence",
            extractedFromDialog: "from dialog",
            extractedFromProfile: "from profile"
        },
        
clientCard: {
    title: "Client Card",
    tabs: {
        overview: "Overview",
        dialog: "Dialog",
        details: "Details", 
        history: "History",
        analysis: "Analysis Result"
    },
    quickActions: {
        analyze: "Run Analysis",
        extractContacts: "Extract Contacts"
    },
    overview: {
        messages: "Messages",
        duration: "Duration",
        satisfaction: "Satisfaction",
        geolocation: "Geolocation",
        ipAddress: "IP Address",
        country: "Country",
        city: "City",
        professionalInfo: "Professional Information",
        company: "Company",
        position: "Position",
        location: "Location"
    },
    details: {
        technicalInfo: "Technical Information",
        sessionId: "Session ID",
        platform: "Platform",
        configuration: "Configuration",
        language: "Language",
        timestamps: "Timestamps",
        firstMessage: "First Message",
        lastActivity: "Last Activity",
        dataSource: "Contact Data Source",
        aiConfidence: "AI Confidence"
    },
    history: {
        dialogStart: "Dialog Started",
        contactsExtracted: "Contacts Extracted",
        analysisCompleted: "Analysis Completed",
        satisfactionLevel: "satisfaction",
        lastActivity: "Last Activity"
    },
    contact: {
        phone: "Phone",
        email: "Email",
        copyToClipboard: "Click to copy",
        openInApp: "Open in app"
    },
    status: {
        active: "Active",
        inactive: "Inactive"
       }
    },
    
    highlights: {
    title: "Key Moments",
    button: "Highlights",
    analyzing: "Analyzing dialog...",
    analyzed: "Highlights processed",
    analyzeError: "Error processing highlights",
    noHighlights: "No key moments found",
    found: "Found",
    reanalyze: "Re-analyze",
    newMessages: "new messages",
    reanalyzing: "Re-analyzing...",
    reanalyzed: "Re-analysis completed!",
    reanalyzeError: "Error during re-analysis",
    newMessagesDetected: "Detected {count} new messages since last analysis",
    stats: {
        title: "Statistics",
        total: "Total"
    },
    types: {
        pricing: "Pricing",
        objection: "Objections",
        buying_signal: "Buying Signals"
    },
    confidence: "Confidence",
    scrollTo: "Go to message",
    filters: {
        all: "All",
        pricing: "Pricing",
        objection: "Objections",
        buying_signal: "Signals"
    },
    noFilterResults: "No highlights of this type"
},

    // Lead Scoring
leadScoring: {
    title: "Lead Scoring",
    score: "Lead Score",
    temperature: {
        hot: "Hot",
        warm: "Warm",
        cold: "Cold",
        leadType: "lead"
    },
    factors: {
        satisfaction: "Satisfaction",
        contacts: "Contacts",
        points: "points"
    },
    recommendation: "Recommendation",
    urgentNotice: "Urgent CRM submission recommended!",
    sendToCRM: "Send to CRM",
    sentToCRM: "Sent to CRM",
    confirmSend: "Send {temperature} lead (Score: {score}) to CRM?",
    sending: "Sending data to CRM...",
    successMessage: "Lead sent to CRM! Score: {score} ({temperature})",
    errorMessage: "CRM sending error: {error}",
    unknownError: "Unknown error",
    crmIdLabel: "CRM ID"
},

bantAnalysis: {
    title: "BANT Qualification",
    showAnalysis: "Show BANT Analysis",
    hideAnalysis: "Hide Analysis",
    qualified: "Qualified",
    notQualified: "Not Qualified",
    qualificationLevel: {
        label: "Qualification Level",
        SQL: "SQL (Sales Qualified Lead)",
        MQL: "MQL (Marketing Qualified Lead)",
        cold: "Cold Lead",                         // ⭐ ADDED
        warm: "Warm Lead",                         // ⭐ ADDED
        hot: "Hot Lead",                           // ⭐ ADDED
        Unqualified: "Unqualified"
    },
    totalScore: "Total Score",
    factors: {
        budget: {
            title: "💰 Budget",
            score: "Score",
            value: "Amount",
            range: "Range",
            mentioned: "Mentioned",
            confidence: "Confidence",
            yes: "Yes",
            no: "No"
        },
        authority: {
            title: "👤 Authority",
            score: "Score",
            role: "Role",
            level: "Level",
            position: "Position",
            confidence: "Confidence",
            roles: {
                decision_maker: "Decision Maker",
                influencer: "Influencer",
                gatekeeper: "Gatekeeper",
                user: "User",
                unknown: "Unknown"
            },
            levels: {
                c_level: "C-Level",
                executive: "Executive",
                manager: "Manager",
                user: "User",
                specialist: "Specialist",
                unknown: "Unknown"
            }
        },
        need: {
            title: "🎯 Need",
            score: "Score",
            severity: "Severity",
            painPoints: "Pain Points",
            confidence: "Confidence",
            severityLevels: {
                critical: "Critical",
                high: "High",
                medium: "Medium",
                low: "Low"
            }
        },
        timeline: {
            title: "⏰ Timeline",
            score: "Score",
            urgency: "Urgency",
            deadline: "Deadline",
            confidence: "Confidence",
            urgencyLevels: {
                immediate: "Immediate",
                this_week: "This Week",
                this_month: "This Month",
                this_quarter: "This Quarter",
                short_term: "Short Term",
                medium_term: "Medium Term",
                long_term: "Long Term",
                later: "Later",
                undefined: "Undefined"
            }
        }
    },
    reasoning: "Reasoning",
    description: "Description",
    confidence: "Confidence"
},

// Test lead
testLead: {
    title: "🧪 Test lead from monitoring system",
    name: "Test",
    comments: "This is a test lead for integration check. Created: {date}",
    testSuccess: "CRM connection successful! Test lead created.",
    specifyWebhook: "Please specify Webhook URL",
    testing: "Testing...",
    connectionError: "CRM connection error"
},

// CRM statuses
crmStatuses: {
    loading: "CRM statuses loaded: {count}",
    loadError: "Error loading CRM statuses"
},

// CRM settings in modal
crmSettings: {
    loaded: "CRM settings loaded",
    saveError: "Error saving CRM settings",
    specifyUrl: "Please specify CRM Webhook URL",
    urlMustContain: "Webhook URL must be valid",
    testResultSuccess: "Success! Lead ID: {id}",
    testResultError: "Error: {error}"
},

// CRM integration
crm: {
    title: "CRM Integration Settings",
    webhookUrl: "CRM Webhook URL:",
    webhookHint: "Get webhook URL from your CRM system settings",
    autoSend: "Auto-send hot leads:",
    autoSendHint: "Automatically send leads with Lead Score ≥ minimum value to CRM",
    minScore: "Minimum Lead Score for auto-send:",
    scoreRange: "(50-100)",
    testConnection: "Test Connection",
    sendButton: "Send to CRM",
    sentButton: "Sent to CRM"
   },
   
   crmConfirm: {
    title: "Confirm action",
    confirmMessage: "Send {temperature} lead (Score: {score}) to CRM?",
    cancelButton: "Cancel",
    sendButton: "Send"
},
   
   // Email monitoring
    emailMonitoring: {
    tabs: {
        messengers: "Messenger Users",
        email: "Email Correspondence"
    },
    table: {
        columns: {
            email: "Email",
            name: "Name",
            subject: "Subject",
            status: "Status",
            leadScore: "Lead Score",
            satisfaction: "Satisfaction",
            messages: "Messages",
            lastActivity: "Last Activity",
            actions: "Actions"
        },
        status: {
            new: "📥 New",
            unread: "🔵 Unread",
            waiting: "⏳ Waiting for Reply",
            conversation: "💬 Conversation",
            inactive: "💤 Inactive"
        },
        actions: {
            viewDialog: "Dialog",
            viewAnalysis: "Result",
            extractContacts: "Update Contacts",
            runAnalysis: "Analysis",
            deleteRecord: "Delete"
        },
        noData: "No data to display",
        loading: "Loading email data..."
    }
  }
},
    
    // 🇪🇸 ИСПАНСКИЙ
es: {
    // Заголовок
    header: {
        title: "Panel de Monitoreo",
        live: "En vivo",
        settings: "Configuración"
    },
    
    // Фильтры
    filters: {
        period: {
            label: "Período",
            options: {
                '1h': "Última hora",
                '24h': "Últimas 24 horas",
                '7d': "Última semana",
                '30d': "Último mes",
                'custom': "Período personalizado"
            },
            customStart: "Fecha de inicio",
            customEnd: "Fecha de fin"
        },
        configuration: {
            label: "Configuración",
            all: "Todas las configuraciones"
        },
        platform: {
            label: "Plataforma",
            all: "Todas las plataformas"
        },
        search: {
            placeholder: "Buscar por IP, país, ciudad..."
        },
        buttons: {
            refresh: "Actualizar",
            analyzeAll: "Analizar todo",
            analyzeByLanguage: "Analizar por idioma",
            analyzeLabel: "Análisis de diálogos"
        }
    },
    
    analysisResultLanguage: {
    label: "Idioma del resultado del análisis",
    modalTitle: "Seleccionar idioma de resultados de análisis",
    notification: "Idioma de resultados de análisis cambiado a: {language}",
    loadError: "Error al cargar el idioma de análisis",
    setError: "Error al establecer el idioma",
    configError: "Configuración de idiomas no encontrada",
    containerError: "Contenedor de botones no encontrado"
},
    // Карточки статистики
    stats: {
        totalUsers: {
            title: "Usuarios totales",
            trend: "por período"
        },
        activeSessions: {
            title: "Sesiones activas",
            trend: "Estable"
        },
        avgSessionTime: {
            title: "Tiempo promedio de sesión",
            trend: "por período"
        },
        totalMessages: {
            title: "Mensajes totales",
            trend: "por período"
        }
    },
    
    // Графики
    charts: {
        activity: {
            title: "Actividad por tiempo",
            refresh: "Actualizar gráfico",
            yAxis: "Número de eventos",
            currentHour: "Hora actual",
            events: "Eventos"
        },
        geography: {
            title: "Geografía de usuarios",
            refresh: "Actualizar gráfico",
            noData: "Sin datos para mostrar"
        },
        platforms: {
            title: "Distribución por plataformas",
            refresh: "Actualizar gráfico",
            noData: "Sin datos para mostrar"
        }
    },
    
    // Таблица
    table: {
        title: "Usuarios",
        export: "Exportar",
        noData: "Sin datos para mostrar",
        loading: "Cargando datos...",
        columns: {
            leadScore: "Puntuación",
            contactName: "Nombre",
            contactPhone: "Teléfono",
            contactEmail: "Email",
            contactMessengers: "Mensajeros",
            contactCompany: "Empresa",
            sessionId: "ID de sesión",
            ipAddress: "Dirección IP",
            country: "País",
            city: "Ciudad",
            platform: "Plataforma",
            configuration: "Configuración",
            startTime: "Hora de inicio",
            duration: "Duración",
            messages: "Mensajes",
            satisfaction: "Satisfacción",
            crmStatus: "CRM", 
            status: "Estado",
            actions: "Acciones"
        },
        status: {
            active: "Activo",
            inactive: "Inactivo"
        },
        actions: {
            viewDialog: "Diálogo",
            analyze: "Analizar",
            viewAnalysis: "Resultado",
            extractContacts: "Extraer contactos",
            updateContacts: "Actualizar contactos",
            deleteRecord: "Eliminar"
        }
    },
    
    // Пагинация
    pagination: {
        previous: "Anterior",
        next: "Siguiente"
    },
    
    // Модальные окна
    dialogs: {
        dialog: {
            title: "Diálogo",
            loading: "Cargando diálogo...",
            notFound: "Diálogo no encontrado",
            error: "Error al cargar el diálogo",
            user: "Usuario",
            bot: "Bot"
        },
        analysis: {
            title: "Análisis de diálogo",
            loading: "Analizando diálogo",
            error: "Error al analizar el diálogo",
            analyzingAll: "Analizando todos los diálogos...",
            timeNotice: "Esto puede tardar unos minutos"
        },
        language: {
            title: "Seleccione idioma para análisis",
            russian: "Ruso",
            english: "Inglés"
        },
        settings: {
            title: "Configuración de monitoreo",
            autoAnalysis: {
                title: "Análisis automático de diálogos",
                enable: "Activar autoanálisis",
                delay: "Retraso después de inactividad",
                minutes: "minutos",
                serverMode: "Modo servidor",
                enabledNotice: "Autoanálisis del servidor activado (verificación cada 5 minutos)",
                disabledNotice: "Autoanálisis del servidor desactivado"
            },
            dbCleanup: {
    title: "Limpieza automática de base de datos",
    active: "Activa (diariamente a las 3:00)",
    monitoringData: "Mantener datos de monitoreo",
    analysisResults: "Mantener resultados de análisis",
    dialogsData: "Mantener diálogos",
    contactsData: "Mantener datos de contacto",
    days: "días"
},
            buttons: {
                save: "Guardar toda la configuración",
                cancel: "Cancelar"
            }
        }
    },
    
    // Форматирование
    formatting: {
        today: "Hoy",
        yesterday: "Ayer",
        seconds: "seg",
        minutes: "min",
        hours: "h",
        unknown: "N/D",
        guest: "Invitado"
    },
    
    // Ошибки
    errors: {
        loadData: "No se pudieron cargar los datos. Verifique su conexión.",
        connectionError: "Error de conexión al servidor"
    },
    
    // Анализ
    analysis: {
        emotionalTone: {
            title: "Tono emocional del diálogo",
            overall: "Tono general",
            satisfaction: "Satisfacción del cliente",
            positive: "Positivo",
            negative: "Negativo",
            neutral: "Neutral"
        },
        needs: {
            title: "Necesidades identificadas"
        },
        missedOpportunities: {
            title: "Oportunidades perdidas"
        },
        recommendations: {
            title: "Recomendaciones de mejora"
        },
        statistics: {
            title: "Estadísticas generales",
            totalDialogs: "Diálogos analizados",
            avgSatisfaction: "Satisfacción promedio",
            resolved: "Problemas resueltos"
        }
    },
    
    // Уведомления
            notifications: {
            settingsSaved: "Toda la configuración se guardó correctamente",
            settingsError: "Error al guardar la configuración",
            periodWarning: "El período de retención de monitoreo debe ser entre 7 y 365 días",
            analysisWarning: "El período de retención de análisis debe ser entre 30 y 365 días",
            copiedToClipboard: "Copiado al portapapeles",
            autoAnalysisEnabled: "Autoanálisis del servidor activado (verificación cada 5 minutos)",
            autoAnalysisDisabled: "Autoanálisis del servidor desactivado",
            clientDataNotFound: "Datos del cliente no encontrados",
            deleting: "Eliminando registro...",
            deleteSuccess: "Registro eliminado correctamente",
            deleteError: "Error al eliminar el registro"
        },
        
        auth: {
        loginSuccess: "¡Inicio de sesión exitoso!",
        logoutConfirm: "¿Está seguro de que desea cerrar sesión?",
        logoutSuccess: "Ha cerrado sesión",
        logoutButton: "Cerrar sesión",
        notAuthorized: "Usuario no autorizado",
        accessDenied: "¡Acceso denegado! Rol requerido: ",
        or: " o ",
        invalidCredentials: "Nombre de usuario o contraseña inválidos",
        loginError: "Error de inicio de sesión. Inténtelo de nuevo.",
        modalTitle: "Panel de Monitoreo",
        modalSubtitle: "Ingrese sus credenciales para acceder",
        usernameLabel: "Nombre de usuario",
        usernamePlaceholder: "Ingrese nombre de usuario",
        passwordLabel: "Contraseña",
        passwordPlaceholder: "Ingrese contraseña",
        rememberMe: "Recordarme durante 7 días",
        loginButton: "Iniciar sesión",
        secureConnection: "Conexión segura"
    },
        
        deleteModal: {
    title: "Confirmación de eliminación",
    messageSession: "¿Está seguro de que desea eliminar este registro?",
    messageEmail: "¿Está seguro de que desea eliminar esta conversación de correo?",
    cancel: "Cancelar",
    confirm: "Eliminar"
},
    
    contacts: {
    title: "Información de contacto",
    name: "Nombre",
    phone: "Teléfono",
    email: "Email",
    messengers: "Mensajeros",
    company: "Empresa",
    extracting: "Extrayendo contactos...",
    extracted: "Contactos extraídos",
    extractError: "Error al extraer contactos",
    dataSource: "Fuente de datos",
    aiConfidence: "Confianza de IA",
    extractedFromDialog: "del diálogo",
    extractedFromProfile: "del perfil"
  },
  
  clientCard: {
    title: "Tarjeta de Cliente",
    tabs: {
        overview: "Vista General",
        dialog: "Diálogo",
        details: "Detalles",
        history: "Historial",
        analysis: "Resultado del Análisis"
    },
    quickActions: {
        analyze: "Realizar Análisis",
        extractContacts: "Extraer Contactos"
    },
    overview: {
        messages: "Mensajes",
        duration: "Duración",
        satisfaction: "Satisfacción",
        geolocation: "Geolocalización",
        ipAddress: "Dirección IP",
        country: "País",
        city: "Ciudad",
        professionalInfo: "Información Profesional",
        company: "Empresa",
        position: "Cargo",
        location: "Ubicación"
    },
    details: {
        technicalInfo: "Información Técnica",
        sessionId: "ID de Sesión",
        platform: "Plataforma",
        configuration: "Configuración",
        language: "Idioma",
        timestamps: "Marcas de Tiempo",
        firstMessage: "Primer Mensaje",
        lastActivity: "Última Actividad",
        dataSource: "Fuente de Datos de Contacto",
        aiConfidence: "Confianza de IA"
    },
    history: {
        dialogStart: "Inicio del Diálogo",
        contactsExtracted: "Contactos Extraídos",
        analysisCompleted: "Análisis Completado",
        satisfactionLevel: "satisfacción",
        lastActivity: "Última Actividad"
    },
    contact: {
        phone: "Teléfono",
        email: "Correo",
        copyToClipboard: "Clic para copiar",
        openInApp: "Abrir en aplicación"
    },
    status: {
        active: "Activo",
        inactive: "Inactivo"
    }
  },   
  
  highlights: {
    title: "Momentos clave",
    button: "Highlights",
    analyzing: "Analizando diálogo...",
    analyzed: "Highlights procesados",
    analyzeError: "Error al procesar highlights",
    noHighlights: "No se encontraron momentos clave",
    found: "Encontrado",
    reanalyze: "Reanalizar",
    newMessages: "nuevos mensajes",
    reanalyzing: "Reanalizando...",
    reanalyzed: "¡Reanálisis completado!",
    reanalyzeError: "Error durante el reanálisis",
    newMessagesDetected: "Se detectaron {count} nuevos mensajes desde el último análisis",
    stats: {
        title: "Estadísticas",
        total: "Total"
    },
    types: {
        pricing: "Precios",
        objection: "Objeciones",
        buying_signal: "Señales de compra"
    },
    confidence: "Confianza",
    scrollTo: "Ir al mensaje",
    filters: {
        all: "Todos",
        pricing: "Precios",
        objection: "Objeciones",
        buying_signal: "Señales"
    },
    noFilterResults: "No hay highlights de este tipo"
},
  
    // Lead Scoring
leadScoring: {
    title: "Lead Scoring",
    score: "Puntuación del Lead",
    temperature: {
        hot: "Caliente",
        warm: "Tibio",
        cold: "Frío",
        leadType: "lead"
    },
    factors: {
        satisfaction: "Satisfacción",
        contacts: "Contactos",
        points: "puntos"
    },
    recommendation: "Recomendación",
    urgentNotice: "¡Se recomienda envío urgente a CRM!",
    sendToCRM: "Enviar a CRM",
    sentToCRM: "Enviado a CRM",
    confirmSend: "¿Enviar lead {temperature} (Puntuación: {score}) a CRM?",
    sending: "Enviando datos a CRM...",
    successMessage: "¡Lead enviado a CRM! Puntuación: {score} ({temperature})",
    errorMessage: "Error al enviar a CRM: {error}",
    unknownError: "Error desconocido",
    crmIdLabel: "ID en CRM"
},

bantAnalysis: {
    title: "Calificación BANT",
    showAnalysis: "Mostrar análisis BANT",
    hideAnalysis: "Ocultar análisis",
    qualified: "Calificado",
    notQualified: "No calificado",
    qualificationLevel: {
        label: "Nivel de calificación",
        SQL: "SQL (Lead Calificado para Ventas)",
        MQL: "MQL (Lead Calificado para Marketing)",
        cold: "Lead Frío",                         // ⭐ AÑADIDO
        warm: "Lead Tibio",                        // ⭐ AÑADIDO
        hot: "Lead Caliente",                      // ⭐ AÑADIDO
        Unqualified: "No calificado"
    },
    totalScore: "Puntuación total",
    factors: {
        budget: {
            title: "💰 Presupuesto",
            score: "Puntuación",
            value: "Cantidad",
            range: "Rango",
            mentioned: "Mencionado",
            confidence: "Confianza",
            yes: "Sí",
            no: "No"
        },
        authority: {
            title: "👤 Autoridad",
            score: "Puntuación",
            role: "Rol",
            level: "Nivel",
            position: "Posición",
            confidence: "Confianza",
            roles: {
                decision_maker: "Tomador de decisiones",
                influencer: "Influyente",
                gatekeeper: "Guardián",
                user: "Usuario",
                unknown: "Desconocido"
            },
            levels: {
                c_level: "Nivel C",
                executive: "Ejecutivo",
                manager: "Gerente",
                user: "Usuario",
                specialist: "Especialista",
                unknown: "Desconocido"
            }
        },
        need: {
            title: "🎯 Necesidad",
            score: "Puntuación",
            severity: "Gravedad",
            painPoints: "Puntos de dolor",
            confidence: "Confianza",
            severityLevels: {
                critical: "Crítica",
                high: "Alta",
                medium: "Media",
                low: "Baja"
            }
        },
        timeline: {
            title: "⏰ Plazos",
            score: "Puntuación",
            urgency: "Urgencia",
            deadline: "Fecha límite",
            confidence: "Confianza",
            urgencyLevels: {
                immediate: "Inmediato",
                this_week: "Esta semana",
                this_month: "Este mes",
                this_quarter: "Este trimestre",
                short_term: "Corto plazo",
                medium_term: "Mediano plazo",
                long_term: "Largo plazo",
                later: "Más tarde",
                undefined: "Indefinido"
            }
        }
    },
    reasoning: "Razonamiento",
    description: "Descripción",
    confidence: "Confianza"
},

// Lead de prueba
testLead: {
    title: "🧪 Lead de prueba del sistema de monitoreo",
    name: "Prueba",
    comments: "Este es un lead de prueba para verificar la integración. Creado: {date}",
    testSuccess: "¡Conexión CRM exitosa! Lead de prueba creado.",
    specifyWebhook: "Especifique la URL del Webhook",
    testing: "Probando...",
    connectionError: "Error de conexión CRM"
},

// Estados CRM
crmStatuses: {
    loading: "Estados CRM cargados: {count}",
    loadError: "Error al cargar estados CRM"
},

// Configuración CRM en modal
crmSettings: {
    loaded: "Configuración CRM cargada",
    saveError: "Error al guardar configuración CRM",
    specifyUrl: "Especifique la URL del Webhook CRM",
    urlMustContain: "La URL del Webhook debe ser válida",
    testResultSuccess: "¡Éxito! ID del lead: {id}",
    testResultError: "Error: {error}"
},

// Integración CRM
crm: {
    title: "Configuración de Integración CRM",
    webhookUrl: "URL del Webhook CRM:",
    webhookHint: "Obtenga la URL del webhook en la configuración de su sistema CRM",
    autoSend: "Envío automático de leads calientes:",
    autoSendHint: "Enviar automáticamente leads con Lead Score ≥ valor mínimo a CRM",
    minScore: "Lead Score mínimo para envío automático:",
    scoreRange: "(50-100)",
    testConnection: "Probar Conexión",
    sendButton: "Enviar a CRM",
    sentButton: "Enviado a CRM"
  },
  
  crmConfirm: {
    title: "Confirmar acción",
    confirmMessage: "¿Enviar lead {temperature} (Score: {score}) al CRM?",
    cancelButton: "Cancelar",
    sendButton: "Enviar"
},

  // Monitoreo de email
   emailMonitoring: {
    tabs: {
        messengers: "Usuarios de Mensajería",
        email: "Correspondencia de Email"
    },
    table: {
        columns: {
            email: "Email",
            name: "Nombre",
            subject: "Asunto",
            status: "Estado",
            leadScore: "Lead Score",
            satisfaction: "Satisfacción",
            messages: "Mensajes",
            lastActivity: "Última Actividad",
            actions: "Acciones"
        },
        status: {
            new: "📥 Nuevo",
            unread: "🔵 No Leído",
            waiting: "⏳ Esperando Respuesta",
            conversation: "💬 Conversación",
            inactive: "💤 Inactivo"
        },
        actions: {
            viewDialog: "Diálogo",
            viewAnalysis: "Resultado",
            extractContacts: "Actualizar Contactos",
            runAnalysis: "Análisis",
            deleteRecord: "Eliminar"
        },
        noData: "No hay datos para mostrar",
        loading: "Cargando datos de email..."
    }
  }
},

// 🇫🇷 ФРАНЦУЗСКИЙ
fr: {
    // Заголовок
    header: {
        title: "Tableau de Bord",
        live: "En direct",
        settings: "Paramètres"
    },
    
    // Фильтры
    filters: {
        period: {
            label: "Période",
            options: {
                '1h': "Dernière heure",
                '24h': "Dernières 24 heures",
                '7d': "Dernière semaine",
                '30d': "Dernier mois",
                'custom': "Période personnalisée"
            },
            customStart: "Date de début",
            customEnd: "Date de fin"
        },
        configuration: {
            label: "Configuration",
            all: "Toutes les configurations"
        },
        platform: {
            label: "Plateforme",
            all: "Toutes les plateformes"
        },
        search: {
            placeholder: "Rechercher par IP, pays, ville..."
        },
        buttons: {
            refresh: "Actualiser",
            analyzeAll: "Analyser tout",
            analyzeByLanguage: "Analyser par langue",
            analyzeLabel: "Analyse des dialogues"
        }
    },
    
    analysisResultLanguage: {
    label: "Langue du résultat d'analyse",
    modalTitle: "Sélectionner la langue des résultats d'analyse",
    notification: "Langue des résultats d'analyse changée en : {language}",
    loadError: "Erreur de chargement de la langue d'analyse",
    setError: "Erreur lors de la définition de la langue",
    configError: "Configuration de langue non trouvée",
    containerError: "Conteneur de boutons non trouvé"
},
    // Карточки статистики
    stats: {
        totalUsers: {
            title: "Total des utilisateurs",
            trend: "pour la période"
        },
        activeSessions: {
            title: "Sessions actives",
            trend: "Stable"
        },
        avgSessionTime: {
            title: "Temps moyen de session",
            trend: "pour la période"
        },
        totalMessages: {
            title: "Total des messages",
            trend: "pour la période"
        }
    },
    
    // Графики
    charts: {
        activity: {
            title: "Activité dans le temps",
            refresh: "Actualiser le graphique",
            yAxis: "Nombre d'événements",
            currentHour: "Heure actuelle",
            events: "Événements"
        },
        geography: {
            title: "Géographie des utilisateurs",
            refresh: "Actualiser le graphique",
            noData: "Aucune donnée à afficher"
        },
        platforms: {
            title: "Répartition par plateformes",
            refresh: "Actualiser le graphique",
            noData: "Aucune donnée à afficher"
        }
    },
    
    // Таблица
    table: {
        title: "Utilisateurs",
        export: "Exporter",
        noData: "Aucune donnée à afficher",
        loading: "Chargement des données...",
        columns: {
            leadScore: "Score",
            contactName: "Nom",
            contactPhone: "Téléphone",
            contactEmail: "Email",
            contactMessengers: "Messageries",
            contactCompany: "Entreprise",
            sessionId: "ID de session",
            ipAddress: "Adresse IP",
            country: "Pays",
            city: "Ville",
            platform: "Plateforme",
            configuration: "Configuration",
            startTime: "Heure de début",
            duration: "Durée",
            messages: "Messages",
            satisfaction: "Satisfaction",
            crmStatus: "CRM", 
            status: "Statut",
            actions: "Actions"
        },
        status: {
            active: "Actif",
            inactive: "Inactif"
        },
        actions: {
            viewDialog: "Dialogue",
            analyze: "Analyser",
            viewAnalysis: "Résultat",
            extractContacts: "Extraire les contacts",
            updateContacts: "Mettre à jour les contacts",
            deleteRecord: "Supprimer"
        }
    },
    
    // Пагинация
    pagination: {
        previous: "Précédent",
        next: "Suivant"
    },
    
    // Модальные окна
    dialogs: {
        dialog: {
            title: "Dialogue",
            loading: "Chargement du dialogue...",
            notFound: "Dialogue non trouvé",
            error: "Erreur lors du chargement du dialogue",
            user: "Utilisateur",
            bot: "Bot"
        },
        analysis: {
            title: "Analyse du dialogue",
            loading: "Analyse du dialogue",
            error: "Erreur lors de l'analyse du dialogue",
            analyzingAll: "Analyse de tous les dialogues...",
            timeNotice: "Cela peut prendre quelques minutes"
        },
        language: {
            title: "Sélectionnez la langue pour l'analyse",
            russian: "Russe",
            english: "Anglais"
        },
        settings: {
            title: "Paramètres de surveillance",
            autoAnalysis: {
                title: "Analyse automatique des dialogues",
                enable: "Activer l'auto-analyse",
                delay: "Délai après inactivité",
                minutes: "minutes",
                serverMode: "Mode serveur",
                enabledNotice: "Auto-analyse serveur activée (vérification toutes les 5 minutes)",
                disabledNotice: "Auto-analyse serveur désactivée"
            },
            dbCleanup: {
    title: "Nettoyage automatique de la base de données",
    active: "Actif (tous les jours à 3h00)",
    monitoringData: "Conserver les données de surveillance",
    analysisResults: "Conserver les résultats d'analyse",
    dialogsData: "Conserver les dialogues",
    contactsData: "Conserver les données de contact",
    days: "jours"
},
            buttons: {
                save: "Enregistrer tous les paramètres",
                cancel: "Annuler"
            }
        }
    },
    
    // Форматирование
    formatting: {
        today: "Aujourd'hui",
        yesterday: "Hier",
        seconds: "sec",
        minutes: "min",
        hours: "h",
        unknown: "N/D",
        guest: "Invité"
    },
    
    // Ошибки
    errors: {
        loadData: "Impossible de charger les données. Vérifiez votre connexion.",
        connectionError: "Erreur de connexion au serveur"
    },
    
    // Анализ
    analysis: {
        emotionalTone: {
            title: "Ton émotionnel du dialogue",
            overall: "Ton général",
            satisfaction: "Satisfaction du client",
            positive: "Positif",
            negative: "Négatif",
            neutral: "Neutre"
        },
        needs: {
            title: "Besoins identifiés"
        },
        missedOpportunities: {
            title: "Opportunités manquées"
        },
        recommendations: {
            title: "Recommandations d'amélioration"
        },
        statistics: {
            title: "Statistiques générales",
            totalDialogs: "Dialogues analysés",
            avgSatisfaction: "Satisfaction moyenne",
            resolved: "Problèmes résolus"
        }
    },
    
    // Уведомления
        notifications: {
            settingsSaved: "Tous les paramètres ont été enregistrés avec succès",
            settingsError: "Erreur lors de l'enregistrement des paramètres",
            periodWarning: "La période de conservation de surveillance doit être entre 7 et 365 jours",
            analysisWarning: "La période de conservation d'analyse doit être entre 30 et 365 jours",
            copiedToClipboard: "Copié dans le presse-papiers",
            autoAnalysisEnabled: "Auto-analyse serveur activée (vérification toutes les 5 minutes)",
            autoAnalysisDisabled: "Auto-analyse serveur désactivée",
            clientDataNotFound: "Données client introuvables",
            deleting: "Suppression en cours...",
            deleteSuccess: "Enregistrement supprimé avec succès",
            deleteError: "Erreur lors de la suppression"
        },
        
        auth: {
        loginSuccess: "Connexion réussie!",
        logoutConfirm: "Êtes-vous sûr de vouloir vous déconnecter?",
        logoutSuccess: "Vous avez été déconnecté",
        logoutButton: "Déconnexion",
        notAuthorized: "Utilisateur non autorisé",
        accessDenied: "Accès refusé! Rôle requis: ",
        or: " ou ",
        invalidCredentials: "Nom d'utilisateur ou mot de passe invalide",
        loginError: "Erreur de connexion. Veuillez réessayer.",
        modalTitle: "Tableau de bord",
        modalSubtitle: "Entrez vos identifiants pour accéder",
        usernameLabel: "Nom d'utilisateur",
        usernamePlaceholder: "Entrez le nom d'utilisateur",
        passwordLabel: "Mot de passe",
        passwordPlaceholder: "Entrez le mot de passe",
        rememberMe: "Se souvenir de moi pendant 7 jours",
        loginButton: "Se connecter",
        secureConnection: "Connexion sécurisée"
    },
        
        deleteModal: {
    title: "Confirmation de suppression",
    messageSession: "Êtes-vous sûr de vouloir supprimer cet enregistrement?",
    messageEmail: "Êtes-vous sûr de vouloir supprimer cette conversation email?",
    cancel: "Annuler",
    confirm: "Supprimer"
},
    
    contacts: {
    title: "Informations de contact",
    name: "Nom",
    phone: "Téléphone",
    email: "Email",
    messengers: "Messageries",
    company: "Société",
    extracting: "Extraction des contacts...",
    extracted: "Contacts extraits",
    extractError: "Erreur lors de l'extraction des contacts",
    dataSource: "Source de données",
    aiConfidence: "Confiance de l'IA",
    extractedFromDialog: "du dialogue",
    extractedFromProfile: "du profil"
},

clientCard: {
    title: "Fiche Client",
    tabs: {
        overview: "Aperçu",
        dialog: "Dialogue",
        details: "Détails",
        history: "Historique",
        analysis: "Résultat d'Analyse"
    },
    quickActions: {
        analyze: "Effectuer une Analyse",
        extractContacts: "Extraire les Contacts"
    },
    overview: {
        messages: "Messages",
        duration: "Durée",
        satisfaction: "Satisfaction",
        geolocation: "Géolocalisation",
        ipAddress: "Adresse IP",
        country: "Pays",
        city: "Ville",
        professionalInfo: "Informations Professionnelles",
        company: "Entreprise",
        position: "Poste",
        location: "Localisation"
    },
    details: {
        technicalInfo: "Informations Techniques",
        sessionId: "ID de Session",
        platform: "Plateforme",
        configuration: "Configuration",
        language: "Langue",
        timestamps: "Horodatages",
        firstMessage: "Premier Message",
        lastActivity: "Dernière Activité",
        dataSource: "Source des Données de Contact",
        aiConfidence: "Confiance de l'IA"
    },
    history: {
        dialogStart: "Début du Dialogue",
        contactsExtracted: "Contacts Extraits",
        analysisCompleted: "Analyse Terminée",
        satisfactionLevel: "satisfaction",
        lastActivity: "Dernière Activité"
    },
    contact: {
        phone: "Téléphone",
        email: "E-mail",
        copyToClipboard: "Cliquer pour copier",
        openInApp: "Ouvrir dans l'application"
    },
    status: {
        active: "Actif",
        inactive: "Inactif"
    }
  },
  
  highlights: {
    title: "Moments clés",
    button: "Highlights",
    analyzing: "Analyse du dialogue...",
    analyzed: "Highlights traités",
    analyzeError: "Erreur de traitement des highlights",
    noHighlights: "Aucun moment clé trouvé",
    found: "Trouvé",
    reanalyze: "Réanalyser",
    newMessages: "nouveaux messages",
    reanalyzing: "Réanalyse en cours...",
    reanalyzed: "Réanalyse terminée !",
    reanalyzeError: "Erreur lors de la réanalyse",
    newMessagesDetected: "{count} nouveaux messages détectés depuis la dernière analyse",
    stats: {
        title: "Statistiques",
        total: "Total"
    },
    types: {
        pricing: "Prix",
        objection: "Objections",
        buying_signal: "Signaux d'achat"
    },
    confidence: "Confiance",
    scrollTo: "Aller au message",
    filters: {
        all: "Tous",
        pricing: "Prix",
        objection: "Objections",
        buying_signal: "Signaux"
    },
    noFilterResults: "Aucun highlight de ce type"
},
  
  // Lead Scoring
leadScoring: {
    title: "Lead Scoring",
    score: "Score du Lead",
    temperature: {
        hot: "Chaud",
        warm: "Tiède",
        cold: "Froid",
        leadType: "lead"
    },
    factors: {
        satisfaction: "Satisfaction",
        contacts: "Contacts",
        points: "points"
    },
    recommendation: "Recommandation",
    urgentNotice: "Envoi urgent au CRM recommandé !",
    sendToCRM: "Envoyer au CRM",
    sentToCRM: "Envoyé au CRM",
    confirmSend: "Envoyer le lead {temperature} (Score : {score}) au CRM ?",
    sending: "Envoi des données au CRM...",
    successMessage: "Lead envoyé au CRM ! Score : {score} ({temperature})",
    errorMessage: "Erreur d'envoi au CRM : {error}",
    unknownError: "Erreur inconnue",
    crmIdLabel: "ID dans le CRM"
},

bantAnalysis: {
    title: "Qualification BANT",
    showAnalysis: "Afficher l'analyse BANT",
    hideAnalysis: "Masquer l'analyse",
    qualified: "Qualifié",
    notQualified: "Non qualifié",
    qualificationLevel: {
        label: "Niveau de qualification",
        SQL: "SQL (Lead Qualifié pour les Ventes)",
        MQL: "MQL (Lead Qualifié pour le Marketing)",
        cold: "Lead Froid",                        // ⭐ AJOUTÉ
        warm: "Lead Tiède",                        // ⭐ AJOUTÉ
        hot: "Lead Chaud",                         // ⭐ AJOUTÉ
        Unqualified: "Non qualifié"
    },
    totalScore: "Score total",
    factors: {
        budget: {
            title: "💰 Budget",
            score: "Score",
            value: "Montant",
            range: "Fourchette",
            mentioned: "Mentionné",
            confidence: "Confiance",
            yes: "Oui",
            no: "Non"
        },
        authority: {
            title: "👤 Autorité",
            score: "Score",
            role: "Rôle",
            level: "Niveau",
            position: "Position",
            confidence: "Confiance",
            roles: {
                decision_maker: "Décideur",
                influencer: "Influenceur",
                gatekeeper: "Gardien",
                user: "Utilisateur",
                unknown: "Inconnu"
            },
            levels: {
                c_level: "Niveau C",
                executive: "Cadre",
                manager: "Manager",
                user: "Utilisateur",
                specialist: "Spécialiste",
                unknown: "Inconnu"
            }
        },
        need: {
            title: "🎯 Besoin",
            score: "Score",
            severity: "Gravité",
            painPoints: "Points de douleur",
            confidence: "Confiance",
            severityLevels: {
                critical: "Critique",
                high: "Élevée",
                medium: "Moyenne",
                low: "Faible"
            }
        },
        timeline: {
            title: "⏰ Délais",
            score: "Score",
            urgency: "Urgence",
            deadline: "Date limite",
            confidence: "Confiance",
            urgencyLevels: {
                immediate: "Immédiat",
                this_week: "Cette semaine",
                this_month: "Ce mois",
                this_quarter: "Ce trimestre",
                short_term: "Court terme",
                medium_term: "Moyen terme",
                long_term: "Long terme",
                later: "Plus tard",
                undefined: "Indéfini"
            }
        }
    },
    reasoning: "Raisonnement",
    description: "Description",
    confidence: "Confiance"
},

// Lead de test
testLead: {
    title: "🧪 Lead de test du système de surveillance",
    name: "Test",
    comments: "Ceci est un lead de test pour vérifier l'intégration. Créé : {date}",
    testSuccess: "Connexion CRM réussie ! Lead de test créé.",
    specifyWebhook: "Veuillez spécifier l'URL du Webhook",
    testing: "Test en cours...",
    connectionError: "Erreur de connexion CRM"
},

// Statuts CRM
crmStatuses: {
    loading: "Statuts CRM chargés : {count}",
    loadError: "Erreur lors du chargement des statuts CRM"
},

// Paramètres CRM dans la modale
crmSettings: {
    loaded: "Paramètres CRM chargés",
    saveError: "Erreur lors de l'enregistrement des paramètres CRM",
    specifyUrl: "Veuillez spécifier l'URL du Webhook CRM",
    urlMustContain: "L'URL du Webhook doit être valide",
    testResultSuccess: "Succès ! ID du lead : {id}",
    testResultError: "Erreur : {error}"
},

// Intégration CRM
crm: {
    title: "Paramètres d'Intégration CRM",
    webhookUrl: "URL du Webhook CRM :",
    webhookHint: "Obtenez l'URL du webhook dans les paramètres de votre système CRM",
    autoSend: "Envoi automatique des leads chauds :",
    autoSendHint: "Envoyer automatiquement les leads avec un Lead Score ≥ valeur minimale au CRM",
    minScore: "Lead Score minimum pour l'envoi automatique :",
    scoreRange: "(50-100)",
    testConnection: "Tester la Connexion",
    sendButton: "Envoyer au CRM",
    sentButton: "Envoyé au CRM"
  },
  
  crmConfirm: {
    title: "Confirmer l'action",
    confirmMessage: "Envoyer le lead {temperature} (Score: {score}) au CRM ?",
    cancelButton: "Annuler",
    sendButton: "Envoyer"
},
  
  emailMonitoring: {
    tabs: {
        messengers: "Utilisateurs de Messagerie",
        email: "Correspondance Email"
    },
    table: {
        columns: {
            email: "Email",
            name: "Nom",
            subject: "Sujet",
            status: "Statut",
            leadScore: "Lead Score",
            satisfaction: "Satisfaction",
            messages: "Messages",
            lastActivity: "Dernière Activité",
            actions: "Actions"
        },
        status: {
            new: "📥 Nouveau",
            unread: "🔵 Non Lu",
            waiting: "⏳ En Attente de Réponse",
            conversation: "💬 Conversation",
            inactive: "💤 Inactif"
        },
        actions: {
            viewDialog: "Dialogue",
            viewAnalysis: "Résultat",
            extractContacts: "Mettre à Jour les Contacts",
            runAnalysis: "Analyse",
            deleteRecord: "Supprimer"
        },
        noData: "Aucune donnée à afficher",
        loading: "Chargement des données email..."
    }
  }
},

// 🇩🇪 НЕМЕЦКИЙ
de: {
    // Заголовок
    header: {
        title: "Überwachungs-Dashboard",
        live: "Live",
        settings: "Einstellungen"
    },
    
    // Фильтры
    filters: {
        period: {
            label: "Zeitraum",
            options: {
                '1h': "Letzte Stunde",
                '24h': "Letzte 24 Stunden",
                '7d': "Letzte Woche",
                '30d': "Letzter Monat",
                'custom': "Benutzerdefinierter Zeitraum"
            },
            customStart: "Startdatum",
            customEnd: "Enddatum"
        },
        configuration: {
            label: "Konfiguration",
            all: "Alle Konfigurationen"
        },
        platform: {
            label: "Plattform",
            all: "Alle Plattformen"
        },
        search: {
            placeholder: "Suche nach IP, Land, Stadt..."
        },
        buttons: {
            refresh: "Aktualisieren",
            analyzeAll: "Alle analysieren",
            analyzeByLanguage: "Nach Sprache analysieren",
            analyzeLabel: "Dialoganalyse"
        }
    },
    
    analysisResultLanguage: {
    label: "Sprache der Analyseergebnisse",
    modalTitle: "Sprache der Analyseergebnisse auswählen",
    notification: "Sprache der Analyseergebnisse geändert zu: {language}",
    loadError: "Fehler beim Laden der Analysesprache",
    setError: "Fehler beim Festlegen der Sprache",
    configError: "Sprachkonfiguration nicht gefunden",
    containerError: "Schaltflächencontainer nicht gefunden"
},
    // Карточки статистики
    stats: {
        totalUsers: {
            title: "Gesamtbenutzer",
            trend: "für Zeitraum"
        },
        activeSessions: {
            title: "Aktive Sitzungen",
            trend: "Stabil"
        },
        avgSessionTime: {
            title: "Durchschnittliche Sitzungsdauer",
            trend: "für Zeitraum"
        },
        totalMessages: {
            title: "Gesamtnachrichten",
            trend: "für Zeitraum"
        }
    },
    
    // Графики
    charts: {
        activity: {
            title: "Aktivität über Zeit",
            refresh: "Diagramm aktualisieren",
            yAxis: "Anzahl der Ereignisse",
            currentHour: "Aktuelle Stunde",
            events: "Ereignisse"
        },
        geography: {
            title: "Benutzergeografie",
            refresh: "Diagramm aktualisieren",
            noData: "Keine Daten zum Anzeigen"
        },
        platforms: {
            title: "Plattformverteilung",
            refresh: "Diagramm aktualisieren",
            noData: "Keine Daten zum Anzeigen"
        }
    },
    
    // Таблица
    table: {
        title: "Benutzer",
        export: "Exportieren",
        noData: "Keine Daten zum Anzeigen",
        loading: "Daten werden geladen...",
        columns: {
            leadScore: "Bewertung",
            contactName: "Name",
            contactPhone: "Telefon",
            contactEmail: "E-Mail",
            contactMessengers: "Messenger",
            contactCompany: "Unternehmen",
            sessionId: "Sitzungs-ID",
            ipAddress: "IP-Adresse",
            country: "Land",
            city: "Stadt",
            platform: "Plattform",
            configuration: "Konfiguration",
            startTime: "Startzeit",
            duration: "Dauer",
            messages: "Nachrichten",
            satisfaction: "Zufriedenheit",
            crmStatus: "CRM", 
            status: "Status",
            actions: "Aktionen"
        },
        status: {
            active: "Aktiv",
            inactive: "Inaktiv"
        },
        actions: {
            viewDialog: "Dialog",
            analyze: "Analysieren",
            viewAnalysis: "Ergebnis",
            extractContacts: "Kontakte extrahieren",
            updateContacts: "Kontakte aktualisieren",
            deleteRecord: "Löschen"
        }
    },
    
    // Пагинация
    pagination: {
        previous: "Zurück",
        next: "Weiter"
    },
    
    // Модальные окна
    dialogs: {
        dialog: {
            title: "Dialog",
            loading: "Dialog wird geladen...",
            notFound: "Dialog nicht gefunden",
            error: "Fehler beim Laden des Dialogs",
            user: "Benutzer",
            bot: "Bot"
        },
        analysis: {
            title: "Dialoganalyse",
            loading: "Dialog wird analysiert",
            error: "Fehler bei der Dialoganalyse",
            analyzingAll: "Alle Dialoge werden analysiert...",
            timeNotice: "Dies kann einige Minuten dauern"
        },
        language: {
            title: "Sprache für Analyse auswählen",
            russian: "Russisch",
            english: "Englisch"
        },
        settings: {
            title: "Überwachungseinstellungen",
            autoAnalysis: {
                title: "Automatische Dialoganalyse",
                enable: "Auto-Analyse aktivieren",
                delay: "Verzögerung nach Inaktivität",
                minutes: "Minuten",
                serverMode: "Server-Modus",
                enabledNotice: "Server-Auto-Analyse aktiviert (Prüfung alle 5 Minuten)",
                disabledNotice: "Server-Auto-Analyse deaktiviert"
            },
            dbCleanup: {
    title: "Automatische Datenbankbereinigung",
    active: "Aktiv (täglich um 3:00 Uhr)",
    monitoringData: "Überwachungsdaten behalten",
    analysisResults: "Analyseergebnisse behalten",
    dialogsData: "Dialoge behalten",
    contactsData: "Kontaktdaten behalten",
    days: "Tage"
},
            buttons: {
                save: "Alle Einstellungen speichern",
                cancel: "Abbrechen"
            }
        }
    },
    
    // Форматирование
    formatting: {
        today: "Heute",
        yesterday: "Gestern",
        seconds: "Sek",
        minutes: "Min",
        hours: "Std",
        unknown: "N/V",
        guest: "Gast"
    },
    
    // Ошибки
    errors: {
        loadData: "Daten konnten nicht geladen werden. Überprüfen Sie Ihre Verbindung.",
        connectionError: "Serververbindungsfehler"
    },
    
    // Анализ
    analysis: {
        emotionalTone: {
            title: "Emotionaler Ton des Dialogs",
            overall: "Gesamtton",
            satisfaction: "Kundenzufriedenheit",
            positive: "Positiv",
            negative: "Negativ",
            neutral: "Neutral"
        },
        needs: {
            title: "Identifizierte Bedürfnisse"
        },
        missedOpportunities: {
            title: "Verpasste Gelegenheiten"
        },
        recommendations: {
            title: "Verbesserungsempfehlungen"
        },
        statistics: {
            title: "Gesamtstatistiken",
            totalDialogs: "Analysierte Dialoge",
            avgSatisfaction: "Durchschnittliche Zufriedenheit",
            resolved: "Gelöste Probleme"
        }
    },
    
    // Уведомления
        notifications: {
            settingsSaved: "Alle Einstellungen wurden erfolgreich gespeichert",
            settingsError: "Fehler beim Speichern der Einstellungen",
            periodWarning: "Die Überwachungsaufbewahrungsfrist muss zwischen 7 und 365 Tagen liegen",
            analysisWarning: "Die Analyseaufbewahrungsfrist muss zwischen 30 und 365 Tagen liegen",
            copiedToClipboard: "In die Zwischenablage kopiert",
            autoAnalysisEnabled: "Server-Auto-Analyse aktiviert (Prüfung alle 5 Minuten)",
            autoAnalysisDisabled: "Server-Auto-Analyse deaktiviert",
            clientDataNotFound: "Kundendaten nicht gefunden",
            deleting: "Eintrag wird gelöscht...",
            deleteSuccess: "Eintrag erfolgreich gelöscht",
            deleteError: "Fehler beim Löschen des Eintrags"
        },
        
        auth: {
        loginSuccess: "Anmeldung erfolgreich!",
        logoutConfirm: "Sind Sie sicher, dass Sie sich abmelden möchten?",
        logoutSuccess: "Sie wurden abgemeldet",
        logoutButton: "Abmelden",
        notAuthorized: "Benutzer nicht autorisiert",
        accessDenied: "Zugriff verweigert! Erforderliche Rolle: ",
        or: " oder ",
        invalidCredentials: "Ungültiger Benutzername oder Passwort",
        loginError: "Anmeldefehler. Bitte versuchen Sie es erneut.",
        modalTitle: "Monitoring Dashboard",
        modalSubtitle: "Geben Sie Ihre Anmeldedaten ein",
        usernameLabel: "Benutzername",
        usernamePlaceholder: "Benutzername eingeben",
        passwordLabel: "Passwort",
        passwordPlaceholder: "Passwort eingeben",
        rememberMe: "Angemeldet bleiben für 7 Tage",
        loginButton: "Anmelden",
        secureConnection: "Sichere Verbindung"
    },
        
        deleteModal: {
    title: "Löschbestätigung",
    messageSession: "Möchten Sie diesen Eintrag wirklich löschen?",
    messageEmail: "Möchten Sie diese E-Mail-Konversation wirklich löschen?",
    cancel: "Abbrechen",
    confirm: "Löschen"
},
    
    contacts: {
    title: "Kontaktinformationen",
    name: "Name",
    phone: "Telefon",
    email: "Email",
    messengers: "Messenger",
    company: "Firma",
    extracting: "Kontakte werden extrahiert...",
    extracted: "Kontakte extrahiert",
    extractError: "Fehler beim Extrahieren der Kontakte",
    dataSource: "Datenquelle",
    aiConfidence: "KI-Vertrauen",
    extractedFromDialog: "aus Dialog",
    extractedFromProfile: "aus Profil"
},

clientCard: {
    title: "Kundenkarte",
    tabs: {
        overview: "Übersicht",
        dialog: "Dialog",
        details: "Details",
        history: "Verlauf",
        analysis: "Analyseergebnis"
    },
    quickActions: {
        analyze: "Analyse Durchführen",
        extractContacts: "Kontakte Extrahieren"
    },
    overview: {
        messages: "Nachrichten",
        duration: "Dauer",
        satisfaction: "Zufriedenheit",
        geolocation: "Geolokalisierung",
        ipAddress: "IP-Adresse",
        country: "Land",
        city: "Stadt",
        professionalInfo: "Berufliche Informationen",
        company: "Unternehmen",
        position: "Position",
        location: "Standort"
    },
    details: {
        technicalInfo: "Technische Informationen",
        sessionId: "Sitzungs-ID",
        platform: "Plattform",
        configuration: "Konfiguration",
        language: "Sprache",
        timestamps: "Zeitstempel",
        firstMessage: "Erste Nachricht",
        lastActivity: "Letzte Aktivität",
        dataSource: "Kontaktdatenquelle",
        aiConfidence: "KI-Vertrauen"
    },
    history: {
        dialogStart: "Dialog Gestartet",
        contactsExtracted: "Kontakte Extrahiert",
        analysisCompleted: "Analyse Abgeschlossen",
        satisfactionLevel: "Zufriedenheit",
        lastActivity: "Letzte Aktivität"
    },
    contact: {
        phone: "Telefon",
        email: "E-Mail",
        copyToClipboard: "Zum Kopieren klicken",
        openInApp: "In App öffnen"
    },
    status: {
        active: "Aktiv",
        inactive: "Inaktiv"
    }
  },
  
  highlights: {
    title: "Schlüsselmomente",
    button: "Highlights",
    analyzing: "Dialog wird analysiert...",
    analyzed: "Highlights verarbeitet",
    analyzeError: "Fehler bei der Verarbeitung von Highlights",
    noHighlights: "Keine Schlüsselmomente gefunden",
    found: "Gefunden",
    reanalyze: "Neu analysieren",
    newMessages: "neue Nachrichten",
    reanalyzing: "Neuanalyse läuft...",
    reanalyzed: "Neuanalyse abgeschlossen!",
    reanalyzeError: "Fehler bei der Neuanalyse",
    newMessagesDetected: "{count} neue Nachrichten seit der letzten Analyse erkannt",
    stats: {
        title: "Statistiken",
        total: "Gesamt"
    },
    types: {
        pricing: "Preise",
        objection: "Einwände",
        buying_signal: "Kaufsignale"
    },
    confidence: "Vertrauen",
    scrollTo: "Zur Nachricht gehen",
    filters: {
        all: "Alle",
        pricing: "Preise",
        objection: "Einwände",
        buying_signal: "Signale"
    },
    noFilterResults: "Keine Highlights dieses Typs"
},
  
  // Lead Scoring
leadScoring: {
    title: "Lead Scoring",
    score: "Lead Score",
    temperature: {
        hot: "Heiß",
        warm: "Warm",
        cold: "Kalt",
        leadType: "Lead"
    },
    factors: {
        satisfaction: "Zufriedenheit",
        contacts: "Kontakte",
        points: "Punkte"
    },
    recommendation: "Empfehlung",
    urgentNotice: "Dringende CRM-Übermittlung empfohlen!",
    sendToCRM: "An CRM senden",
    sentToCRM: "An CRM gesendet",
    confirmSend: "{temperature} Lead (Score: {score}) an CRM senden?",
    sending: "Daten werden an CRM gesendet...",
    successMessage: "Lead an CRM gesendet! Score: {score} ({temperature})",
    errorMessage: "CRM-Sendefehler: {error}",
    unknownError: "Unbekannter Fehler",
    crmIdLabel: "CRM-ID"
},

bantAnalysis: {
    title: "BANT-Qualifizierung",
    showAnalysis: "BANT-Analyse anzeigen",
    hideAnalysis: "Analyse ausblenden",
    qualified: "Qualifiziert",
    notQualified: "Nicht qualifiziert",
    qualificationLevel: {
        label: "Qualifizierungsstufe",
        SQL: "SQL (Vertriebsqualifizierter Lead)",
        MQL: "MQL (Marketingqualifizierter Lead)",
        cold: "Kalter Lead",                       // ⭐ HINZUGEFÜGT
        warm: "Warmer Lead",                       // ⭐ HINZUGEFÜGT
        hot: "Heißer Lead",                        // ⭐ HINZUGEFÜGT
        Unqualified: "Nicht qualifiziert"
    },
    totalScore: "Gesamtpunktzahl",
    factors: {
        budget: {
            title: "💰 Budget",
            score: "Punktzahl",
            value: "Betrag",
            range: "Bereich",
            mentioned: "Erwähnt",
            confidence: "Vertrauen",
            yes: "Ja",
            no: "Nein"
        },
        authority: {
            title: "👤 Autorität",
            score: "Punktzahl",
            role: "Rolle",
            level: "Ebene",
            position: "Position",
            confidence: "Vertrauen",
            roles: {
                decision_maker: "Entscheidungsträger",
                influencer: "Beeinflusser",
                gatekeeper: "Torwächter",
                user: "Benutzer",
                unknown: "Unbekannt"
            },
            levels: {
                c_level: "C-Level",
                executive: "Führungskraft",
                manager: "Manager",
                user: "Benutzer",
                specialist: "Spezialist",
                unknown: "Unbekannt"
            }
        },
        need: {
            title: "🎯 Bedarf",
            score: "Punktzahl",
            severity: "Schweregrad",
            painPoints: "Schmerzpunkte",
            confidence: "Vertrauen",
            severityLevels: {
                critical: "Kritisch",
                high: "Hoch",
                medium: "Mittel",
                low: "Niedrig"
            }
        },
        timeline: {
            title: "⏰ Zeitrahmen",
            score: "Punktzahl",
            urgency: "Dringlichkeit",
            deadline: "Frist",
            confidence: "Vertrauen",
            urgencyLevels: {
                immediate: "Sofort",
                this_week: "Diese Woche",
                this_month: "Diesen Monat",
                this_quarter: "Dieses Quartal",
                short_term: "Kurzfristig",
                medium_term: "Mittelfristig",
                long_term: "Langfristig",
                later: "Später",
                undefined: "Undefiniert"
            }
        }
    },
    reasoning: "Begründung",
    description: "Beschreibung",
    confidence: "Vertrauen"
},

// Test-Lead
testLead: {
    title: "🧪 Test-Lead vom Überwachungssystem",
    name: "Test",
    comments: "Dies ist ein Test-Lead zur Überprüfung der Integration. Erstellt: {date}",
    testSuccess: "CRM-Verbindung erfolgreich! Test-Lead erstellt.",
    specifyWebhook: "Bitte Webhook-URL angeben",
    testing: "Wird getestet...",
    connectionError: "CRM-Verbindungsfehler"
},

// CRM-Status
crmStatuses: {
    loading: "CRM-Status geladen: {count}",
    loadError: "Fehler beim Laden der CRM-Status"
},

// CRM-Einstellungen im Modal
crmSettings: {
    loaded: "CRM-Einstellungen geladen",
    saveError: "Fehler beim Speichern der CRM-Einstellungen",
    specifyUrl: "Bitte CRM-Webhook-URL angeben",
    urlMustContain: "Webhook-URL muss gültig sein",
    testResultSuccess: "Erfolg! Lead-ID: {id}",
    testResultError: "Fehler: {error}"
},

// CRM-Integration
crm: {
    title: "CRM-Integrationseinstellungen",
    webhookUrl: "CRM-Webhook-URL:",
    webhookHint: "Holen Sie sich die Webhook-URL aus den Einstellungen Ihres CRM-Systems",
    autoSend: "Heiße Leads automatisch senden:",
    autoSendHint: "Leads mit Lead Score ≥ Mindestwert automatisch an CRM senden",
    minScore: "Minimaler Lead Score für automatischen Versand:",
    scoreRange: "(50-100)",
    testConnection: "Verbindung testen",
    sendButton: "An CRM senden",
    sentButton: "An CRM gesendet"
   },
   
   crmConfirm: {
    title: "Aktion bestätigen",
    confirmMessage: "{temperature} Lead (Score: {score}) an CRM senden?",
    cancelButton: "Abbrechen",
    sendButton: "Senden"
},
   
   emailMonitoring: {
    tabs: {
        messengers: "Messenger-Benutzer",
        email: "E-Mail-Korrespondenz"
    },
    table: {
        columns: {
            email: "E-Mail",
            name: "Name",
            subject: "Betreff",
            status: "Status",
            leadScore: "Lead Score",
            satisfaction: "Zufriedenheit",
            messages: "Nachrichten",
            lastActivity: "Letzte Aktivität",
            actions: "Aktionen"
        },
        status: {
            new: "📥 Neu",
            unread: "🔵 Ungelesen",
            waiting: "⏳ Wartet auf Antwort",
            conversation: "💬 Unterhaltung",
            inactive: "💤 Inaktiv"
        },
        actions: {
            viewDialog: "Dialog",
            viewAnalysis: "Ergebnis",
            extractContacts: "Kontakte Aktualisieren",
            runAnalysis: "Analyse",
            deleteRecord: "Löschen"
        },
        noData: "Keine Daten zum Anzeigen",
        loading: "E-Mail-Daten werden geladen..."
    }
  }
},

// 🇮🇹 ИТАЛЬЯНСКИЙ
it: {
    // Заголовок
    header: {
        title: "Dashboard di Monitoraggio",
        live: "Dal vivo",
        settings: "Impostazioni"
    },
    
    // Фильтры
    filters: {
        period: {
            label: "Periodo",
            options: {
                '1h': "Ultima ora",
                '24h': "Ultime 24 ore",
                '7d': "Ultima settimana",
                '30d': "Ultimo mese",
                'custom': "Periodo personalizzato"
            },
            customStart: "Data di inizio",
            customEnd: "Data di fine"
        },
        configuration: {
            label: "Configurazione",
            all: "Tutte le configurazioni"
        },
        platform: {
            label: "Piattaforma",
            all: "Tutte le piattaforme"
        },
        search: {
            placeholder: "Cerca per IP, paese, città..."
        },
        buttons: {
            refresh: "Aggiorna",
            analyzeAll: "Analizza tutto",
            analyzeByLanguage: "Analizza per lingua",
            analyzeLabel: "Analisi dialoghi"
        }
    },
    
    analysisResultLanguage: {
    label: "Lingua dei risultati dell'analisi",
    modalTitle: "Seleziona la lingua dei risultati dell'analisi",
    notification: "Lingua dei risultati dell'analisi cambiata in: {language}",
    loadError: "Errore nel caricamento della lingua di analisi",
    setError: "Errore nell'impostazione della lingua",
    configError: "Configurazione lingua non trovata",
    containerError: "Contenitore pulsanti non trovato"
},
    // Карточки статистики
    stats: {
        totalUsers: {
            title: "Utenti totali",
            trend: "per periodo"
        },
        activeSessions: {
            title: "Sessioni attive",
            trend: "Stabile"
        },
        avgSessionTime: {
            title: "Tempo medio di sessione",
            trend: "per periodo"
        },
        totalMessages: {
            title: "Messaggi totali",
            trend: "per periodo"
        }
    },
    
    // Графики
    charts: {
        activity: {
            title: "Attività nel tempo",
            refresh: "Aggiorna grafico",
            yAxis: "Numero di eventi",
            currentHour: "Ora corrente",
            events: "Eventi"
        },
        geography: {
            title: "Geografia degli utenti",
            refresh: "Aggiorna grafico",
            noData: "Nessun dato da visualizzare"
        },
        platforms: {
            title: "Distribuzione per piattaforme",
            refresh: "Aggiorna grafico",
            noData: "Nessun dato da visualizzare"
        }
    },
    
    // Таблица
    table: {
        title: "Utenti",
        export: "Esporta",
        noData: "Nessun dato da visualizzare",
        loading: "Caricamento dati...",
        columns: {
            leadScore: "Punteggio",
            contactName: "Nome",
            contactPhone: "Telefono",
            contactEmail: "Email",
            contactMessengers: "Messaggistica",
            contactCompany: "Azienda",
            sessionId: "ID sessione",
            ipAddress: "Indirizzo IP",
            country: "Paese",
            city: "Città",
            platform: "Piattaforma",
            configuration: "Configurazione",
            startTime: "Ora di inizio",
            duration: "Durata",
            messages: "Messaggi",
            satisfaction: "Soddisfazione",
            crmStatus: "CRM", 
            status: "Stato",
            actions: "Azioni"
        },
        status: {
            active: "Attivo",
            inactive: "Inattivo"
        },
        actions: {
            viewDialog: "Dialogo",
            analyze: "Analizza",
            viewAnalysis: "Risultato",
            extractContacts: "Estrai contatti",
            updateContacts: "Aggiorna contatti",
            deleteRecord: "Elimina"
        }
    },
    
    // Пагинация
    pagination: {
        previous: "Precedente",
        next: "Successivo"
    },
    
    // Модальные окна
    dialogs: {
        dialog: {
            title: "Dialogo",
            loading: "Caricamento dialogo...",
            notFound: "Dialogo non trovato",
            error: "Errore nel caricamento del dialogo",
            user: "Utente",
            bot: "Bot"
        },
        analysis: {
            title: "Analisi del dialogo",
            loading: "Analisi del dialogo",
            error: "Errore nell'analisi del dialogo",
            analyzingAll: "Analisi di tutti i dialoghi...",
            timeNotice: "Questo potrebbe richiedere alcuni minuti"
        },
        language: {
            title: "Seleziona la lingua per l'analisi",
            russian: "Russo",
            english: "Inglese"
        },
        settings: {
            title: "Impostazioni di monitoraggio",
            autoAnalysis: {
                title: "Analisi automatica dei dialoghi",
                enable: "Attiva auto-analisi",
                delay: "Ritardo dopo inattività",
                minutes: "minuti",
                serverMode: "Modalità server",
                enabledNotice: "Auto-analisi server attivata (controllo ogni 5 minuti)",
                disabledNotice: "Auto-analisi server disattivata"
            },
            dbCleanup: {
    title: "Pulizia automatica del database",
    active: "Attiva (ogni giorno alle 3:00)",
    monitoringData: "Conserva dati di monitoraggio",
    analysisResults: "Conserva risultati analisi",
    dialogsData: "Conserva dialoghi",
    contactsData: "Conserva dati di contatto",
    days: "giorni"
},
            buttons: {
                save: "Salva tutte le impostazioni",
                cancel: "Annulla"
            }
        }
    },
    
    // Форматирование
    formatting: {
        today: "Oggi",
        yesterday: "Ieri",
        seconds: "sec",
        minutes: "min",
        hours: "h",
        unknown: "N/D",
        guest: "Ospite"
    },
    
    // Ошибки
    errors: {
        loadData: "Impossibile caricare i dati. Controlla la tua connessione.",
        connectionError: "Errore di connessione al server"
    },
    
    // Анализ
    analysis: {
        emotionalTone: {
            title: "Tono emotivo del dialogo",
            overall: "Tono generale",
            satisfaction: "Soddisfazione del cliente",
            positive: "Positivo",
            negative: "Negativo",
            neutral: "Neutrale"
        },
        needs: {
            title: "Esigenze identificate"
        },
        missedOpportunities: {
            title: "Opportunità mancate"
        },
        recommendations: {
            title: "Raccomandazioni di miglioramento"
        },
        statistics: {
            title: "Statistiche generali",
            totalDialogs: "Dialoghi analizzati",
            avgSatisfaction: "Soddisfazione media",
            resolved: "Problemi risolti"
        }
    },
    
   // Уведомления
        notifications: {
            settingsSaved: "Tutte le impostazioni sono state salvate con successo",
            settingsError: "Errore nel salvataggio delle impostazioni",
            periodWarning: "Il periodo di conservazione del monitoraggio deve essere tra 7 e 365 giorni",
            analysisWarning: "Il periodo di conservazione dell'analisi deve essere tra 30 e 365 giorni",
            copiedToClipboard: "Copiato negli appunti",
            autoAnalysisEnabled: "Auto-analisi server attivata (controllo ogni 5 minuti)",
            autoAnalysisDisabled: "Auto-analisi server disattivata",
            clientDataNotFound: "Dati cliente non trovati",
            deleting: "Eliminazione in corso...",
            deleteSuccess: "Record eliminato con successo",
            deleteError: "Errore durante l'eliminazione"
        },
        
        auth: {
        loginSuccess: "Accesso riuscito!",
        logoutConfirm: "Sei sicuro di voler uscire?",
        logoutSuccess: "Hai effettuato il logout",
        logoutButton: "Esci",
        notAuthorized: "Utente non autorizzato",
        accessDenied: "Accesso negato! Ruolo richiesto: ",
        or: " o ",
        invalidCredentials: "Nome utente o password non validi",
        loginError: "Errore di accesso. Riprova.",
        modalTitle: "Dashboard di Monitoraggio",
        modalSubtitle: "Inserisci le tue credenziali per accedere",
        usernameLabel: "Nome utente",
        usernamePlaceholder: "Inserisci nome utente",
        passwordLabel: "Password",
        passwordPlaceholder: "Inserisci password",
        rememberMe: "Ricordami per 7 giorni",
        loginButton: "Accedi",
        secureConnection: "Connessione sicura"
    },
        
        deleteModal: {
    title: "Conferma eliminazione",
    messageSession: "Sei sicuro di voler eliminare questo record?",
    messageEmail: "Sei sicuro di voler eliminare questa conversazione email?",
    cancel: "Annulla",
    confirm: "Elimina"
},
    
    contacts: {
    title: "Informazioni di contatto",
    name: "Nome",
    phone: "Telefono",
    email: "Email",
    messengers: "Messaggistica",
    company: "Azienda",
    extracting: "Estrazione contatti...",
    extracted: "Contatti estratti",
    extractError: "Errore nell'estrazione dei contatti",
    dataSource: "Fonte dati",
    aiConfidence: "Fiducia dell'IA",
    extractedFromDialog: "dal dialogo",
    extractedFromProfile: "dal profilo"
},

clientCard: {
    title: "Scheda Cliente",
    tabs: {
        overview: "Panoramica",
        dialog: "Dialogo",
        details: "Dettagli",
        history: "Cronologia",
        analysis: "Risultato Analisi"
    },
    quickActions: {
        analyze: "Esegui Analisi",
        extractContacts: "Estrai Contatti"
    },
    overview: {
        messages: "Messaggi",
        duration: "Durata",
        satisfaction: "Soddisfazione",
        geolocation: "Geolocalizzazione",
        ipAddress: "Indirizzo IP",
        country: "Paese",
        city: "Città",
        professionalInfo: "Informazioni Professionali",
        company: "Azienda",
        position: "Posizione",
        location: "Posizione"
    },
    details: {
        technicalInfo: "Informazioni Tecniche",
        sessionId: "ID Sessione",
        platform: "Piattaforma",
        configuration: "Configurazione",
        language: "Lingua",
        timestamps: "Timestamp",
        firstMessage: "Primo Messaggio",
        lastActivity: "Ultima Attività",
        dataSource: "Fonte Dati Contatto",
        aiConfidence: "Fiducia IA"
    },
    history: {
        dialogStart: "Inizio Dialogo",
        contactsExtracted: "Contatti Estratti",
        analysisCompleted: "Analisi Completata",
        satisfactionLevel: "soddisfazione",
        lastActivity: "Ultima Attività"
    },
    contact: {
        phone: "Telefono",
        email: "Email",
        copyToClipboard: "Clicca per copiare",
        openInApp: "Apri nell'app"
    },
    status: {
        active: "Attivo",
        inactive: "Inattivo"
    }
  },
  
  highlights: {
    title: "Momenti chiave",
    button: "Highlights",
    analyzing: "Analisi del dialogo...",
    analyzed: "Highlights elaborati",
    analyzeError: "Errore nell'elaborazione degli highlights",
    noHighlights: "Nessun momento chiave trovato",
    found: "Trovato",
    reanalyze: "Rianalizza",
    newMessages: "nuovi messaggi",
    reanalyzing: "Rianalisi in corso...",
    reanalyzed: "Rianalisi completata!",
    reanalyzeError: "Errore durante la rianalisi",
    newMessagesDetected: "Rilevati {count} nuovi messaggi dall'ultima analisi",
    stats: {
        title: "Statistiche",
        total: "Totale"
    },
    types: {
        pricing: "Prezzi",
        objection: "Obiezioni",
        buying_signal: "Segnali di acquisto"
    },
    confidence: "Fiducia",
    scrollTo: "Vai al messaggio",
    filters: {
        all: "Tutti",
        pricing: "Prezzi",
        objection: "Obiezioni",
        buying_signal: "Segnali"
    },
    noFilterResults: "Nessun highlight di questo tipo"
},
  
  // Lead Scoring
leadScoring: {
    title: "Lead Scoring",
    score: "Punteggio Lead",
    temperature: {
        hot: "Caldo",
        warm: "Tiepido",
        cold: "Freddo",
        leadType: "lead"
    },
    factors: {
        satisfaction: "Soddisfazione",
        contacts: "Contatti",
        points: "punti"
    },
    recommendation: "Raccomandazione",
    urgentNotice: "Si raccomanda l'invio urgente al CRM!",
    sendToCRM: "Invia al CRM",
    sentToCRM: "Inviato al CRM",
    confirmSend: "Inviare lead {temperature} (Punteggio: {score}) al CRM?",
    sending: "Invio dati al CRM...",
    successMessage: "Lead inviato al CRM! Punteggio: {score} ({temperature})",
    errorMessage: "Errore nell'invio al CRM: {error}",
    unknownError: "Errore sconosciuto",
    crmIdLabel: "ID nel CRM"
},

bantAnalysis: {
    title: "Qualificazione BANT",
    showAnalysis: "Mostra analisi BANT",
    hideAnalysis: "Nascondi analisi",
    qualified: "Qualificato",
    notQualified: "Non qualificato",
    qualificationLevel: {
        label: "Livello di qualificazione",
        SQL: "SQL (Lead Qualificato per le Vendite)",
        MQL: "MQL (Lead Qualificato per il Marketing)",
        cold: "Lead Freddo",                       // ⭐ AGGIUNTO
        warm: "Lead Tiepido",                      // ⭐ AGGIUNTO
        hot: "Lead Caldo",                         // ⭐ AGGIUNTO
        Unqualified: "Non qualificato"
    },
    totalScore: "Punteggio totale",
    factors: {
        budget: {
            title: "💰 Budget",
            score: "Punteggio",
            value: "Importo",
            range: "Fascia",
            mentioned: "Menzionato",
            confidence: "Confidenza",
            yes: "Sì",
            no: "No"
        },
        authority: {
            title: "👤 Autorità",
            score: "Punteggio",
            role: "Ruolo",
            level: "Livello",
            position: "Posizione",
            confidence: "Confidenza",
            roles: {
                decision_maker: "Decisore",
                influencer: "Influenzatore",
                gatekeeper: "Guardiano",
                user: "Utente",
                unknown: "Sconosciuto"
            },
            levels: {
                c_level: "Livello C",
                executive: "Dirigente",
                manager: "Manager",
                user: "Utente",
                specialist: "Specialista",
                unknown: "Sconosciuto"
            }
        },
        need: {
            title: "🎯 Necessità",
            score: "Punteggio",
            severity: "Gravità",
            painPoints: "Punti critici",
            confidence: "Confidenza",
            severityLevels: {
                critical: "Critica",
                high: "Alta",
                medium: "Media",
                low: "Bassa"
            }
        },
        timeline: {
            title: "⏰ Tempistiche",
            score: "Punteggio",
            urgency: "Urgenza",
            deadline: "Scadenza",
            confidence: "Confidenza",
            urgencyLevels: {
                immediate: "Immediato",
                this_week: "Questa settimana",
                this_month: "Questo mese",
                this_quarter: "Questo trimestre",
                short_term: "Breve termine",
                medium_term: "Medio termine",
                long_term: "Lungo termine",
                later: "Più tardi",
                undefined: "Non definito"
            }
        }
    },
    reasoning: "Ragionamento",
    description: "Descrizione",
    confidence: "Confidenza"
},

// Lead di test
testLead: {
    title: "🧪 Lead di test dal sistema di monitoraggio",
    name: "Test",
    comments: "Questo è un lead di test per verificare l'integrazione. Creato: {date}",
    testSuccess: "Connessione CRM riuscita! Lead di test creato.",
    specifyWebhook: "Specificare l'URL del Webhook",
    testing: "Test in corso...",
    connectionError: "Errore di connessione CRM"
},

// Stati CRM
crmStatuses: {
    loading: "Stati CRM caricati: {count}",
    loadError: "Errore nel caricamento degli stati CRM"
},

// Impostazioni CRM nel modale
crmSettings: {
    loaded: "Impostazioni CRM caricate",
    saveError: "Errore nel salvataggio delle impostazioni CRM",
    specifyUrl: "Specificare l'URL del Webhook CRM",
    urlMustContain: "L'URL del Webhook deve essere valido",
    testResultSuccess: "Successo! ID del lead: {id}",
    testResultError: "Errore: {error}"
},

// Integrazione CRM
crm: {
    title: "Impostazioni Integrazione CRM",
    webhookUrl: "URL Webhook CRM:",
    webhookHint: "Ottenere l'URL del webhook dalle impostazioni del vostro sistema CRM",
    autoSend: "Invio automatico lead caldi:",
    autoSendHint: "Inviare automaticamente i lead con Lead Score ≥ valore minimo al CRM",
    minScore: "Lead Score minimo per l'invio automatico:",
    scoreRange: "(50-100)",
    testConnection: "Test Connessione",
    sendButton: "Invia al CRM",
    sentButton: "Inviato al CRM"
   },
   
   crmConfirm: {
    title: "Conferma azione",
    confirmMessage: "Inviare lead {temperature} (Score: {score}) al CRM?",
    cancelButton: "Annulla",
    sendButton: "Invia"
},
   
   emailMonitoring: {
    tabs: {
        messengers: "Utenti di Messaggistica",
        email: "Corrispondenza Email"
    },
    table: {
        columns: {
            email: "Email",
            name: "Nome",
            subject: "Oggetto",
            status: "Stato",
            leadScore: "Lead Score",
            satisfaction: "Soddisfazione",
            messages: "Messaggi",
            lastActivity: "Ultima Attività",
            actions: "Azioni"
        },
        status: {
            new: "📥 Nuovo",
            unread: "🔵 Non Letto",
            waiting: "⏳ In Attesa di Risposta",
            conversation: "💬 Conversazione",
            inactive: "💤 Inattivo"
        },
        actions: {
            viewDialog: "Dialogo",
            viewAnalysis: "Risultato",
            extractContacts: "Aggiorna Contatti",
            runAnalysis: "Analisi",
            deleteRecord: "Elimina"
        },
        noData: "Nessun dato da visualizzare",
        loading: "Caricamento dati email..."
    }
   }
},

// 🇵🇹 ПОРТУГАЛЬСКИЙ
pt: {
    // Заголовок
    header: {
        title: "Painel de Monitoramento",
        live: "Ao vivo",
        settings: "Configurações"
    },
    
    // Фильтры
    filters: {
        period: {
            label: "Período",
            options: {
                '1h': "Última hora",
                '24h': "Últimas 24 horas",
                '7d': "Última semana",
                '30d': "Último mês",
                'custom': "Período personalizado"
            },
            customStart: "Data de início",
            customEnd: "Data de fim"
        },
        configuration: {
            label: "Configuração",
            all: "Todas as configurações"
        },
        platform: {
            label: "Plataforma",
            all: "Todas as plataformas"
        },
        search: {
            placeholder: "Pesquisar por IP, país, cidade..."
        },
        buttons: {
            refresh: "Atualizar",
            analyzeAll: "Analisar tudo",
            analyzeByLanguage: "Analisar por idioma",
            analyzeLabel: "Análise de diálogos"
        }
    },
    
    analysisResultLanguage: {
    label: "Idioma do resultado da análise",
    modalTitle: "Selecionar idioma dos resultados da análise",
    notification: "Idioma dos resultados da análise alterado para: {language}",
    loadError: "Erro ao carregar o idioma de análise",
    setError: "Erro ao definir o idioma",
    configError: "Configuração de idioma não encontrada",
    containerError: "Contêiner de botões não encontrado"
},
    // Карточки статистики
    stats: {
        totalUsers: {
            title: "Total de usuários",
            trend: "por período"
        },
        activeSessions: {
            title: "Sessões ativas",
            trend: "Estável"
        },
        avgSessionTime: {
            title: "Tempo médio de sessão",
            trend: "por período"
        },
        totalMessages: {
            title: "Total de mensagens",
            trend: "por período"
        }
    },
    
    // Графики
    charts: {
        activity: {
            title: "Atividade ao longo do tempo",
            refresh: "Atualizar gráfico",
            yAxis: "Número de eventos",
            currentHour: "Hora atual",
            events: "Eventos"
        },
        geography: {
            title: "Geografia dos usuários",
            refresh: "Atualizar gráfico",
            noData: "Sem dados para exibir"
        },
        platforms: {
            title: "Distribuição por plataformas",
            refresh: "Atualizar gráfico",
            noData: "Sem dados para exibir"
        }
    },
    
    // Таблица
    table: {
        title: "Usuários",
        export: "Exportar",
        noData: "Sem dados para exibir",
        loading: "Carregando dados...",
        columns: {
            leadScore: "Pontuação",
            contactName: "Nome",
            contactPhone: "Telefone",
            contactEmail: "E-mail",
            contactMessengers: "Mensageiros",
            contactCompany: "Empresa",
            sessionId: "ID da sessão",
            ipAddress: "Endereço IP",
            country: "País",
            city: "Cidade",
            platform: "Plataforma",
            configuration: "Configuração",
            startTime: "Hora de início",
            duration: "Duração",
            messages: "Mensagens",
            satisfaction: "Satisfação",
            crmStatus: "CRM", 
            status: "Status",
            actions: "Ações"
        },
        status: {
            active: "Ativo",
            inactive: "Inativo"
        },
        actions: {
            viewDialog: "Diálogo",
            analyze: "Analisar",
            viewAnalysis: "Resultado",
            extractContacts: "Extrair contatos",
            updateContacts: "Atualizar contatos",
            deleteRecord: "Excluir"
        }
    },
    
    // Пагинация
    pagination: {
        previous: "Anterior",
        next: "Próximo"
    },
    
    // Модальные окна
    dialogs: {
        dialog: {
            title: "Diálogo",
            loading: "Carregando diálogo...",
            notFound: "Diálogo não encontrado",
            error: "Erro ao carregar o diálogo",
            user: "Usuário",
            bot: "Bot"
        },
        analysis: {
            title: "Análise do diálogo",
            loading: "Analisando diálogo",
            error: "Erro ao analisar o diálogo",
            analyzingAll: "Analisando todos os diálogos...",
            timeNotice: "Isso pode levar alguns minutos"
        },
        language: {
            title: "Selecione o idioma para análise",
            russian: "Russo",
            english: "Inglês"
        },
        settings: {
            title: "Configurações de monitoramento",
            autoAnalysis: {
                title: "Análise automática de diálogos",
                enable: "Ativar auto-análise",
                delay: "Atraso após inatividade",
                minutes: "minutos",
                serverMode: "Modo servidor",
                enabledNotice: "Auto-análise do servidor ativada (verificação a cada 5 minutos)",
                disabledNotice: "Auto-análise do servidor desativada"
            },
            dbCleanup: {
    title: "Limpeza automática do banco de dados",
    active: "Ativa (diariamente às 3:00)",
    monitoringData: "Manter dados de monitoramento",
    analysisResults: "Manter resultados de análise",
    dialogsData: "Manter diálogos",
    contactsData: "Manter dados de contato",
    days: "dias"
},
            buttons: {
                save: "Salvar todas as configurações",
                cancel: "Cancelar"
            }
        }
    },
    
    // Форматирование
    formatting: {
        today: "Hoje",
        yesterday: "Ontem",
        seconds: "seg",
        minutes: "min",
        hours: "h",
        unknown: "N/D",
        guest: "Convidado"
    },
    
    // Ошибки
    errors: {
        loadData: "Não foi possível carregar os dados. Verifique sua conexão.",
        connectionError: "Erro de conexão com o servidor"
    },
    
    // Анализ
    analysis: {
        emotionalTone: {
            title: "Tom emocional do diálogo",
            overall: "Tom geral",
            satisfaction: "Satisfação do cliente",
            positive: "Positivo",
            negative: "Negativo",
            neutral: "Neutro"
        },
        needs: {
            title: "Necessidades identificadas"
        },
        missedOpportunities: {
            title: "Oportunidades perdidas"
        },
        recommendations: {
            title: "Recomendações de melhoria"
        },
        statistics: {
            title: "Estatísticas gerais",
            totalDialogs: "Diálogos analisados",
            avgSatisfaction: "Satisfação média",
            resolved: "Problemas resolvidos"
        }
    },
    
    // Уведомления
        notifications: {
            settingsSaved: "Todas as configurações foram salvas com sucesso",
            settingsError: "Erro ao salvar as configurações",
            periodWarning: "O período de retenção de monitoramento deve estar entre 7 e 365 dias",
            analysisWarning: "O período de retenção de análise deve estar entre 30 e 365 dias",
            copiedToClipboard: "Copiado para a área de transferência",
            autoAnalysisEnabled: "Auto-análise do servidor ativada (verificação a cada 5 minutos)",
            autoAnalysisDisabled: "Auto-análise do servidor desativada",
            clientDataNotFound: "Dados do cliente não encontrados",
            deleting: "Excluindo registro...",
            deleteSuccess: "Registro excluído com sucesso",
            deleteError: "Erro ao excluir registro"
        },
        
        auth: {
        loginSuccess: "Login bem-sucedido!",
        logoutConfirm: "Tem certeza de que deseja sair?",
        logoutSuccess: "Você saiu do sistema",
        logoutButton: "Sair",
        notAuthorized: "Usuário não autorizado",
        accessDenied: "Acesso negado! Função necessária: ",
        or: " ou ",
        invalidCredentials: "Nome de usuário ou senha inválidos",
        loginError: "Erro de login. Tente novamente.",
        modalTitle: "Painel de Monitoramento",
        modalSubtitle: "Digite suas credenciais para acessar",
        usernameLabel: "Nome de usuário",
        usernamePlaceholder: "Digite o nome de usuário",
        passwordLabel: "Senha",
        passwordPlaceholder: "Digite a senha",
        rememberMe: "Lembrar-me por 7 dias",
        loginButton: "Entrar",
        secureConnection: "Conexão segura"
    },
        
        deleteModal: {
    title: "Confirmação de exclusão",
    messageSession: "Tem certeza de que deseja excluir este registro?",
    messageEmail: "Tem certeza de que deseja excluir esta conversa de email?",
    cancel: "Cancelar",
    confirm: "Excluir"
},
    
    contacts: {
    title: "Informações de contato",
    name: "Nome",
    phone: "Telefone",
    email: "Email",
    messengers: "Mensageiros",
    company: "Empresa",
    extracting: "Extraindo contatos...",
    extracted: "Contatos extraídos",
    extractError: "Erro ao extrair contatos",
    dataSource: "Fonte de dados",
    aiConfidence: "Confiança da IA",
    extractedFromDialog: "do diálogo",
    extractedFromProfile: "do perfil"
},

clientCard: {
    title: "Cartão do Cliente",
    tabs: {
        overview: "Visão Geral",
        dialog: "Diálogo",
        details: "Detalhes",
        history: "Histórico",
        analysis: "Resultado da Análise"
    },
    quickActions: {
        analyze: "Executar Análise",
        extractContacts: "Extrair Contatos"
    },
    overview: {
        messages: "Mensagens",
        duration: "Duração",
        satisfaction: "Satisfação",
        geolocation: "Geolocalização",
        ipAddress: "Endereço IP",
        country: "País",
        city: "Cidade",
        professionalInfo: "Informações Profissionais",
        company: "Empresa",
        position: "Cargo",
        location: "Localização"
    },
    details: {
        technicalInfo: "Informações Técnicas",
        sessionId: "ID da Sessão",
        platform: "Plataforma",
        configuration: "Configuração",
        language: "Idioma",
        timestamps: "Carimbos de Tempo",
        firstMessage: "Primeira Mensagem",
        lastActivity: "Última Atividade",
        dataSource: "Fonte de Dados de Contato",
        aiConfidence: "Confiança da IA"
    },
    history: {
        dialogStart: "Início do Diálogo",
        contactsExtracted: "Contatos Extraídos",
        analysisCompleted: "Análise Concluída",
        satisfactionLevel: "satisfação",
        lastActivity: "Última Atividade"
    },
    contact: {
        phone: "Telefone",
        email: "E-mail",
        copyToClipboard: "Clique para copiar",
        openInApp: "Abrir no aplicativo"
    },
    status: {
        active: "Ativo",
        inactive: "Inativo"
    }
  },
  
  highlights: {
    title: "Momentos-chave",
    button: "Highlights",
    analyzing: "Analisando diálogo...",
    analyzed: "Highlights processados",
    analyzeError: "Erro ao processar highlights",
    noHighlights: "Nenhum momento-chave encontrado",
    found: "Encontrado",
    reanalyze: "Reanalisar",
    newMessages: "novas mensagens",
    reanalyzing: "Reanalisando...",
    reanalyzed: "Reanálise concluída!",
    reanalyzeError: "Erro durante a reanálise",
    newMessagesDetected: "{count} novas mensagens detectadas desde a última análise",
    stats: {
        title: "Estatísticas",
        total: "Total"
    },
    types: {
        pricing: "Preços",
        objection: "Objeções",
        buying_signal: "Sinais de compra"
    },
    confidence: "Confiança",
    scrollTo: "Ir para mensagem",
    filters: {
        all: "Todos",
        pricing: "Preços",
        objection: "Objeções",
        buying_signal: "Sinais"
    },
    noFilterResults: "Nessun highlight di questo tipo"
},
  
  // Lead Scoring
leadScoring: {
    title: "Lead Scoring",
    score: "Pontuação do Lead",
    temperature: {
        hot: "Quente",
        warm: "Morno",
        cold: "Frio",
        leadType: "lead"
    },
    factors: {
        satisfaction: "Satisfação",
        contacts: "Contatos",
        points: "pontos"
    },
    recommendation: "Recomendação",
    urgentNotice: "Envio urgente para CRM recomendado!",
    sendToCRM: "Enviar para CRM",
    sentToCRM: "Enviado para CRM",
    confirmSend: "Enviar lead {temperature} (Pontuação: {score}) para CRM?",
    sending: "Enviando dados para CRM...",
    successMessage: "Lead enviado para CRM! Pontuação: {score} ({temperature})",
    errorMessage: "Erro ao enviar para CRM: {error}",
    unknownError: "Erro desconhecido",
    crmIdLabel: "ID no CRM"
},

bantAnalysis: {
    title: "Qualificação BANT",
    showAnalysis: "Mostrar análise BANT",
    hideAnalysis: "Ocultar análise",
    qualified: "Qualificado",
    notQualified: "Não qualificado",
    qualificationLevel: {
        label: "Nível de qualificação",
        SQL: "SQL (Lead Qualificado para Vendas)",
        MQL: "MQL (Lead Qualificado para Marketing)",
        cold: "Lead Frio",                         // ⭐ ADICIONADO
        warm: "Lead Morno",                        // ⭐ ADICIONADO
        hot: "Lead Quente",                        // ⭐ ADICIONADO
        Unqualified: "Não qualificado"
    },
    totalScore: "Pontuação total",
    factors: {
        budget: {
            title: "💰 Orçamento",
            score: "Pontuação",
            value: "Valor",
            range: "Faixa",
            mentioned: "Mencionado",
            confidence: "Confiança",
            yes: "Sim",
            no: "Não"
        },
        authority: {
            title: "👤 Autoridade",
            score: "Pontuação",
            role: "Papel",
            level: "Nível",
            position: "Posição",
            confidence: "Confiança",
            roles: {
                decision_maker: "Tomador de decisão",
                influencer: "Influenciador",
                gatekeeper: "Guardião",
                user: "Usuário",
                unknown: "Desconhecido"
            },
            levels: {
                c_level: "Nível C",
                executive: "Executivo",
                manager: "Gerente",
                user: "Usuário",
                specialist: "Especialista",
                unknown: "Desconhecido"
            }
        },
        need: {
            title: "🎯 Necessidade",
            score: "Pontuação",
            severity: "Gravidade",
            painPoints: "Pontos de dor",
            confidence: "Confiança",
            severityLevels: {
                critical: "Crítica",
                high: "Alta",
                medium: "Média",
                low: "Baixa"
            }
        },
        timeline: {
            title: "⏰ Prazos",
            score: "Pontuação",
            urgency: "Urgência",
            deadline: "Prazo final",
            confidence: "Confiança",
            urgencyLevels: {
                immediate: "Imediato",
                this_week: "Esta semana",
                this_month: "Este mês",
                this_quarter: "Este trimestre",
                short_term: "Curto prazo",
                medium_term: "Médio prazo",
                long_term: "Longo prazo",
                later: "Mais tarde",
                undefined: "Indefinido"
            }
        }
    },
    reasoning: "Raciocínio",
    description: "Descrição",
    confidence: "Confiança"
},

// Lead de teste
testLead: {
    title: "🧪 Lead de teste do sistema de monitoramento",
    name: "Teste",
    comments: "Este é um lead de teste para verificar a integração. Criado: {date}",
    testSuccess: "Conexão CRM bem-sucedida! Lead de teste criado.",
    specifyWebhook: "Especifique a URL do Webhook",
    testing: "Testando...",
    connectionError: "Erro de conexão CRM"
},

// Status CRM
crmStatuses: {
    loading: "Status CRM carregados: {count}",
    loadError: "Erro ao carregar status CRM"
},

// Configurações CRM no modal
crmSettings: {
    loaded: "Configurações CRM carregadas",
    saveError: "Erro ao salvar configurações CRM",
    specifyUrl: "Especifique a URL do Webhook CRM",
    urlMustContain: "A URL do Webhook deve ser válida",
    testResultSuccess: "Sucesso! ID do lead: {id}",
    testResultError: "Erro: {error}"
},

// Integração CRM
crm: {
    title: "Configurações de Integração CRM",
    webhookUrl: "URL do Webhook CRM:",
    webhookHint: "Obtenha a URL do webhook nas configurações do seu sistema CRM",
    autoSend: "Envio automático de leads quentes:",
    autoSendHint: "Enviar automaticamente leads com Lead Score ≥ valor mínimo para CRM",
    minScore: "Lead Score mínimo para envio automático:",
    scoreRange: "(50-100)",
    testConnection: "Testar Conexão",
    sendButton: "Enviar para CRM",
    sentButton: "Enviado para CRM"
   },
   
   crmConfirm: {
    title: "Confirmar ação",
    confirmMessage: "Enviar lead {temperature} (Score: {score}) para o CRM?",
    cancelButton: "Cancelar",
    sendButton: "Enviar"
},
   
   emailMonitoring: {
    tabs: {
        messengers: "Utilizadores de Mensagens",
        email: "Correspondência de Email"
    },
    table: {
        columns: {
            email: "Email",
            name: "Nome",
            subject: "Assunto",
            status: "Estado",
            leadScore: "Lead Score",
            satisfaction: "Satisfação",
            messages: "Mensagens",
            lastActivity: "Última Atividade",
            actions: "Ações"
        },
        status: {
            new: "📥 Novo",
            unread: "🔵 Não Lido",
            waiting: "⏳ Aguardando Resposta",
            conversation: "💬 Conversa",
            inactive: "💤 Inativo"
        },
        actions: {
            viewDialog: "Diálogo",
            viewAnalysis: "Resultado",
            extractContacts: "Atualizar Contactos",
            runAnalysis: "Análise",
            deleteRecord: "Excluir"
        },
        noData: "Sem dados para exibir",
        loading: "Carregando dados de email..."
    }
  }
},

// 🇨🇳 КИТАЙСКИЙ
zh: {
    // Заголовок
    header: {
        title: "监控面板",
        live: "实时",
        settings: "设置"
    },
    
    // Фильтры
    filters: {
        period: {
            label: "时间段",
            options: {
                '1h': "最近一小时",
                '24h': "最近24小时",
                '7d': "最近一周",
                '30d': "最近一个月",
                'custom': "自定义时间段"
            },
            customStart: "开始日期",
            customEnd: "结束日期"
        },
        configuration: {
            label: "配置",
            all: "所有配置"
        },
        platform: {
            label: "平台",
            all: "所有平台"
        },
        search: {
            placeholder: "搜索 IP、国家、城市..."
        },
        buttons: {
            refresh: "刷新",
            analyzeAll: "分析全部",
            analyzeByLanguage: "按语言分析",
            analyzeLabel: "对话分析"
        }
    },
    
    analysisResultLanguage: {
    label: "分析结果语言",
    modalTitle: "选择分析结果语言",
    notification: "分析结果语言已更改为：{language}",
    loadError: "加载分析语言时出错",
    setError: "设置语言时出错",
    configError: "未找到语言配置",
    containerError: "未找到按钮容器"
},
    // Карточки статистики
    stats: {
        totalUsers: {
            title: "用户总数",
            trend: "期间"
        },
        activeSessions: {
            title: "活跃会话",
            trend: "稳定"
        },
        avgSessionTime: {
            title: "平均会话时间",
            trend: "期间"
        },
        totalMessages: {
            title: "消息总数",
            trend: "期间"
        }
    },
    
    // Графики
    charts: {
        activity: {
            title: "时间活动",
            refresh: "刷新图表",
            yAxis: "事件数量",
            currentHour: "当前小时",
            events: "事件"
        },
        geography: {
            title: "用户地理位置",
            refresh: "刷新图表",
            noData: "没有数据显示"
        },
        platforms: {
            title: "平台分布",
            refresh: "刷新图表",
            noData: "没有数据显示"
        }
    },
    
    // Таблица
    table: {
        title: "用户",
        export: "导出",
        noData: "没有数据显示",
        loading: "加载数据中...",
        columns: {
            leadScore: "评分",
            contactName: "姓名",
            contactPhone: "电话",
            contactEmail: "电子邮件",
            contactMessengers: "即时通讯",
            contactCompany: "公司",
            sessionId: "会话ID",
            ipAddress: "IP地址",
            country: "国家",
            city: "城市",
            platform: "平台",
            configuration: "配置",
            startTime: "开始时间",
            duration: "时长",
            messages: "消息",
            satisfaction: "满意度",
            crmStatus: "CRM", 
            status: "状态",
            actions: "操作"
        },
        status: {
            active: "活跃",
            inactive: "非活跃"
        },
        actions: {
            viewDialog: "对话",
            analyze: "分析",
            viewAnalysis: "结果",
            extractContacts: "提取联系人",
            updateContacts: "更新联系人",
            deleteRecord: "删除"
        }
    },
    
    // Пагинация
    pagination: {
        previous: "上一页",
        next: "下一页"
    },
    
    // Модальные окна
    dialogs: {
        dialog: {
            title: "对话",
            loading: "加载对话中...",
            notFound: "未找到对话",
            error: "加载对话时出错",
            user: "用户",
            bot: "机器人"
        },
        analysis: {
            title: "对话分析",
            loading: "分析对话中",
            error: "分析对话时出错",
            analyzingAll: "分析所有对话中...",
            timeNotice: "这可能需要几分钟时间"
        },
        language: {
            title: "选择分析语言",
            russian: "俄语",
            english: "英语"
        },
        settings: {
            title: "监控设置",
            autoAnalysis: {
                title: "自动对话分析",
                enable: "启用自动分析",
                delay: "不活动后的延迟",
                minutes: "分钟",
                serverMode: "服务器模式",
                enabledNotice: "服务器自动分析已启用（每5分钟检查一次）",
                disabledNotice: "服务器自动分析已禁用"
            },
            dbCleanup: {
    title: "自动数据库清理",
    active: "活动（每天3:00）",
    monitoringData: "保留监控数据",
    analysisResults: "保留分析结果",
    dialogsData: "保留对话",
    contactsData: "保留联系数据",
    days: "天"
},
            buttons: {
                save: "保存所有设置",
                cancel: "取消"
            }
        }
    },
    
    // Форматирование
    formatting: {
        today: "今天",
        yesterday: "昨天",
        seconds: "秒",
        minutes: "分",
        hours: "时",
        unknown: "不适用",
        guest: "访客"
    },
    
    // Ошибки
    errors: {
        loadData: "无法加载数据。请检查您的连接。",
        connectionError: "服务器连接错误"
    },
    
    // Анализ
    analysis: {
        emotionalTone: {
            title: "对话情感基调",
            overall: "整体基调",
            satisfaction: "客户满意度",
            positive: "积极",
            negative: "消极",
            neutral: "中立"
        },
        needs: {
            title: "识别的需求"
        },
        missedOpportunities: {
            title: "错失的机会"
        },
        recommendations: {
            title: "改进建议"
        },
        statistics: {
            title: "总体统计",
            totalDialogs: "已分析对话",
            avgSatisfaction: "平均满意度",
            resolved: "已解决问题"
        }
    },
    
    // Уведомления
        notifications: {
            settingsSaved: "所有设置已成功保存",
            settingsError: "保存设置时出错",
            periodWarning: "监控保留期必须在7到365天之间",
            analysisWarning: "分析保留期必须在30到365天之间",
            copiedToClipboard: "已复制到剪贴板",
            autoAnalysisEnabled: "服务器自动分析已启用（每5分钟检查一次）",
            autoAnalysisDisabled: "服务器自动分析已禁用",
            clientDataNotFound: "未找到客户数据",
            deleting: "正在删除记录...",
            deleteSuccess: "记录删除成功",
            deleteError: "删除记录时出错"
        },
        
        auth: {
        loginSuccess: "登录成功！",
        logoutConfirm: "您确定要退出吗？",
        logoutSuccess: "您已退出系统",
        logoutButton: "退出",
        notAuthorized: "用户未授权",
        accessDenied: "访问被拒绝！需要角色：",
        or: " 或 ",
        invalidCredentials: "用户名或密码无效",
        loginError: "登录错误。请重试。",
        modalTitle: "监控仪表板",
        modalSubtitle: "输入您的凭据以访问",
        usernameLabel: "用户名",
        usernamePlaceholder: "输入用户名",
        passwordLabel: "密码",
        passwordPlaceholder: "输入密码",
        rememberMe: "记住我7天",
        loginButton: "登录",
        secureConnection: "安全连接"
    },
        
        deleteModal: {
    title: "删除确认",
    messageSession: "您确定要删除此记录吗？",
    messageEmail: "您确定要删除此邮件对话吗？",
    cancel: "取消",
    confirm: "删除"
},
    
    contacts: {
    title: "联系信息",
    name: "姓名",
    phone: "电话",
    email: "电子邮件",
    messengers: "即时通讯",
    company: "公司",
    extracting: "正在提取联系人...",
    extracted: "联系人已提取",
    extractError: "提取联系人时出错",
    dataSource: "数据来源",
    aiConfidence: "AI置信度",
    extractedFromDialog: "来自对话",
    extractedFromProfile: "来自个人资料"
},

clientCard: {
    title: "客户卡片",
    tabs: {
        overview: "概览",
        dialog: "对话",
        details: "详情",
        history: "历史",
        analysis: "分析结果"
    },
    quickActions: {
        analyze: "执行分析",
        extractContacts: "提取联系人"
    },
    overview: {
        messages: "消息",
        duration: "持续时间",
        satisfaction: "满意度",
        geolocation: "地理位置",
        ipAddress: "IP地址",
        country: "国家",
        city: "城市",
        professionalInfo: "专业信息",
        company: "公司",
        position: "职位",
        location: "位置"
    },
    details: {
        technicalInfo: "技术信息",
        sessionId: "会话ID",
        platform: "平台",
        configuration: "配置",
        language: "语言",
        timestamps: "时间戳",
        firstMessage: "第一条消息",
        lastActivity: "最后活动",
        dataSource: "联系人数据来源",
        aiConfidence: "AI置信度"
    },
    history: {
        dialogStart: "对话开始",
        contactsExtracted: "联系人已提取",
        analysisCompleted: "分析完成",
        satisfactionLevel: "满意度",
        lastActivity: "最后活动"
    },
    contact: {
        phone: "电话",
        email: "电子邮件",
        copyToClipboard: "点击复制",
        openInApp: "在应用中打开"
    },
    status: {
        active: "活跃",
        inactive: "非活跃"
    }
  },
  highlights: {
    title: "关键时刻",
    button: "Highlights",
    analyzing: "正在分析对话...",
    analyzed: "Highlights已处理",
    analyzeError: "处理highlights时出错",
    noHighlights: "未找到关键时刻",
    found: "找到",
    reanalyze: "重新分析",
    newMessages: "条新消息",
    reanalyzing: "重新分析中...",
    reanalyzed: "重新分析完成！",
    reanalyzeError: "重新分析时出错",
    newMessagesDetected: "自上次分析以来检测到 {count} 条新消息",
    stats: {
        title: "统计",
        total: "总计"
    },
    types: {
        pricing: "价格",
        objection: "异议",
        buying_signal: "购买信号"
    },
    confidence: "置信度",
    scrollTo: "转到消息",
    filters: {
        all: "全部",
        pricing: "价格",
        objection: "异议",
        buying_signal: "信号"
    },
    noFilterResults: "没有此类型的重点"
},
  
  // Lead Scoring
leadScoring: {
    title: "潜在客户评分与",
    score: "潜在客户分数",
    temperature: {
        hot: "热",
        warm: "温",
        cold: "冷",
        leadType: "潜在客户"
    },
    factors: {
        satisfaction: "满意度",
        contacts: "联系人",
        points: "分"
    },
    recommendation: "建议",
    urgentNotice: "建议紧急发送到CRM！",
    sendToCRM: "发送到CRM",
    sentToCRM: "已发送到CRM",
    confirmSend: "发送{temperature}潜在客户（分数：{score}）到CRM？",
    sending: "正在发送数据到CRM...",
    successMessage: "潜在客户已发送到CRM！分数：{score}（{temperature}）",
    errorMessage: "CRM发送错误：{error}",
    unknownError: "未知错误",
    crmIdLabel: "CRM ID"
},

bantAnalysis: {
    title: "BANT资格认证",
    showAnalysis: "显示BANT分析",
    hideAnalysis: "隐藏分析",
    qualified: "合格",
    notQualified: "不合格",
    qualificationLevel: {
        label: "资格等级",
        SQL: "SQL（销售合格线索）",
        MQL: "MQL（营销合格线索）",
        cold: "冷线索",                             // ⭐ 已添加
        warm: "温线索",                             // ⭐ 已添加
        hot: "热线索",                              // ⭐ 已添加
        Unqualified: "不合格"
    },
    totalScore: "总分",
    factors: {
        budget: {
            title: "💰 预算",
            score: "得分",
            value: "金额",
            range: "范围",
            mentioned: "提及",
            confidence: "置信度",
            yes: "是",
            no: "否"
        },
        authority: {
            title: "👤 权限",
            score: "得分",
            role: "角色",
            level: "级别",
            position: "职位",
            confidence: "置信度",
            roles: {
                decision_maker: "决策者",
                influencer: "影响者",
                gatekeeper: "把关者",
                user: "用户",
                unknown: "未知"
            },
            levels: {
                c_level: "C级高管",
                executive: "高管",
                manager: "经理",
                user: "用户",
                specialist: "专家",
                unknown: "未知"
            }
        },
        need: {
            title: "🎯 需求",
            score: "得分",
            severity: "严重程度",
            painPoints: "痛点",
            confidence: "置信度",
            severityLevels: {
                critical: "严重",
                high: "高",
                medium: "中",
                low: "低"
            }
        },
        timeline: {
            title: "⏰ 时间表",
            score: "得分",
            urgency: "紧急程度",
            deadline: "截止日期",
            confidence: "置信度",
            urgencyLevels: {
                immediate: "立即",
                this_week: "本周",
                this_month: "本月",
                this_quarter: "本季度",
                short_term: "短期",
                medium_term: "中期",
                long_term: "长期",
                later: "稍后",
                undefined: "未定义"
            }
        }
    },
    reasoning: "推理",
    description: "描述",
    confidence: "置信度"
},

// 测试潜在客户
testLead: {
    title: "🧪 来自监控系统的测试潜在客户",
    name: "测试",
    comments: "这是用于验证集成的测试潜在客户。创建时间：{date}",
    testSuccess: "CRM连接成功！测试潜在客户已创建。",
    specifyWebhook: "请指定Webhook URL",
    testing: "测试中...",
    connectionError: "CRM连接错误"
},

// CRM状态
crmStatuses: {
    loading: "CRM状态已加载：{count}",
    loadError: "加载CRM状态时出错"
},

// 模态框中的CRM设置
crmSettings: {
    loaded: "CRM设置已加载",
    saveError: "保存CRM设置时出错",
    specifyUrl: "请指定CRM Webhook URL",
    urlMustContain: "Webhook URL必须有效",
    testResultSuccess: "成功！潜在客户ID：{id}",
    testResultError: "错误：{error}"
},

// CRM集成
crm: {
    title: "CRM集成设置",
    webhookUrl: "CRM Webhook URL：",
    webhookHint: "从您的CRM系统设置中获取webhook URL",
    autoSend: "自动发送热门潜在客户：",
    autoSendHint: "自动将潜在客户分数≥最小值的潜在客户发送到CRM",
    minScore: "自动发送的最低潜在客户分数：",
    scoreRange: "(50-100)",
    testConnection: "测试连接",
    sendButton: "发送到CRM",
    sentButton: "已发送到CRM"
   },
   
   crmConfirm: {
    title: "确认操作",
    confirmMessage: "将{temperature}潜在客户（分数：{score}）发送到CRM？",
    cancelButton: "取消",
    sendButton: "发送"
},
   
   emailMonitoring: {
    tabs: {
        messengers: "即时通讯用户",
        email: "邮件往来"
    },
    table: {
        columns: {
            email: "邮箱",
            name: "姓名",
            subject: "主题",
            status: "状态",
            leadScore: "潜在客户评分",
            satisfaction: "满意度",
            messages: "消息数",
            lastActivity: "最后活动",
            actions: "操作"
        },
        status: {
            new: "📥 新邮件",
            unread: "🔵 未读",
            waiting: "⏳ 等待回复",
            conversation: "💬 对话中",
            inactive: "💤 未活动"
        },
        actions: {
            viewDialog: "对话",
            viewAnalysis: "结果",
            extractContacts: "更新联系人",
            runAnalysis: "分析",
            deleteRecord: "删除"
        },
        noData: "没有数据显示",
        loading: "正在加载邮件数据..."
    }
  }
},

// 🇯🇵 ЯПОНСКИЙ
ja: {
    // Заголовок
    header: {
        title: "モニタリングダッシュボード",
        live: "ライブ",
        settings: "設定"
    },
    
    // Фильтры
    filters: {
        period: {
            label: "期間",
            options: {
                '1h': "過去1時間",
                '24h': "過去24時間",
                '7d': "過去1週間",
                '30d': "過去1ヶ月",
                'custom': "カスタム期間"
            },
            customStart: "開始日",
            customEnd: "終了日"
        },
        configuration: {
            label: "設定",
            all: "すべての設定"
        },
        platform: {
            label: "プラットフォーム",
            all: "すべてのプラットフォーム"
        },
        search: {
            placeholder: "IP、国、都市で検索..."
        },
        buttons: {
            refresh: "更新",
            analyzeAll: "すべて分析",
            analyzeByLanguage: "言語別に分析",
            analyzeLabel: "対話分析"
        }
    },
    
    analysisResultLanguage: {
    label: "分析結果の言語",
    modalTitle: "分析結果の言語を選択",
    notification: "分析結果の言語を{language}に変更しました",
    loadError: "分析言語の読み込みエラー",
    setError: "言語設定エラー",
    configError: "言語設定が見つかりません",
    containerError: "ボタンコンテナが見つかりません"
},
    // Карточки статистики
    stats: {
        totalUsers: {
            title: "総ユーザー数",
            trend: "期間中"
        },
        activeSessions: {
            title: "アクティブセッション",
            trend: "安定"
        },
        avgSessionTime: {
            title: "平均セッション時間",
            trend: "期間中"
        },
        totalMessages: {
            title: "総メッセージ数",
            trend: "期間中"
        }
    },
    
    // Графики
    charts: {
        activity: {
            title: "時間別アクティビティ",
            refresh: "チャートを更新",
            yAxis: "イベント数",
            currentHour: "現在の時間",
            events: "イベント"
        },
        geography: {
            title: "ユーザーの地理",
            refresh: "チャートを更新",
            noData: "表示するデータがありません"
        },
        platforms: {
            title: "プラットフォーム分布",
            refresh: "チャートを更新",
            noData: "表示するデータがありません"
        }
    },
    
    // Таблица
    table: {
        title: "ユーザー",
        export: "エクスポート",
        noData: "表示するデータがありません",
        loading: "データを読み込み中...",
        columns: {
            leadScore: "スコア",
            contactName: "名前",
            contactPhone: "電話番号",
            contactEmail: "メール",
            contactMessengers: "メッセンジャー",
            contactCompany: "会社",
            sessionId: "セッションID",
            ipAddress: "IPアドレス",
            country: "国",
            city: "都市",
            platform: "プラットフォーム",
            configuration: "設定",
            startTime: "開始時刻",
            duration: "期間",
            messages: "メッセージ",
            satisfaction: "満足度",
            crmStatus: "CRM", 
            status: "ステータス",
            actions: "アクション"
        },
        status: {
            active: "アクティブ",
            inactive: "非アクティブ"
        },
        actions: {
            viewDialog: "対話",
            analyze: "分析",
            viewAnalysis: "結果",
            extractContacts: "連絡先を抽出",
            updateContacts: "連絡先を更新",
            deleteRecord: "削除"
        }
    },
    
    // Пагинация
    pagination: {
        previous: "前へ",
        next: "次へ"
    },
    
    // Модальные окна
    dialogs: {
        dialog: {
            title: "対話",
            loading: "対話を読み込み中...",
            notFound: "対話が見つかりません",
            error: "対話の読み込みエラー",
            user: "ユーザー",
            bot: "ボット"
        },
        analysis: {
            title: "対話分析",
            loading: "対話を分析中",
            error: "対話の分析エラー",
            analyzingAll: "すべての対話を分析中...",
            timeNotice: "これには数分かかる場合があります"
        },
        language: {
            title: "分析言語を選択",
            russian: "ロシア語",
            english: "英語"
        },
        settings: {
            title: "モニタリング設定",
            autoAnalysis: {
                title: "自動対話分析",
                enable: "自動分析を有効化",
                delay: "非アクティブ後の遅延",
                minutes: "分",
                serverMode: "サーバーモード",
                enabledNotice: "サーバー自動分析が有効（5分ごとにチェック）",
                disabledNotice: "サーバー自動分析が無効"
            },
            dbCleanup: {
    title: "自動データベースクリーンアップ",
    active: "アクティブ（毎日3:00）",
    monitoringData: "監視データを保持",
    analysisResults: "分析結果を保持",
    dialogsData: "ダイアログを保持",
    contactsData: "連絡先データを保持",
    days: "日"
},
            buttons: {
                save: "すべての設定を保存",
                cancel: "キャンセル"
            }
        }
    },
    
    // Форматирование
    formatting: {
        today: "今日",
        yesterday: "昨日",
        seconds: "秒",
        minutes: "分",
        hours: "時",
        unknown: "N/A",
        guest: "ゲスト"
    },
    
    // Ошибки
    errors: {
        loadData: "データを読み込めませんでした。接続を確認してください。",
        connectionError: "サーバー接続エラー"
    },
    
    // Анализ
    analysis: {
        emotionalTone: {
            title: "対話の感情的なトーン",
            overall: "全体的なトーン",
            satisfaction: "顧客満足度",
            positive: "ポジティブ",
            negative: "ネガティブ",
            neutral: "ニュートラル"
        },
        needs: {
            title: "特定されたニーズ"
        },
        missedOpportunities: {
            title: "逃した機会"
        },
        recommendations: {
            title: "改善の推奨事項"
        },
        statistics: {
            title: "全体統計",
            totalDialogs: "分析された対話",
            avgSatisfaction: "平均満足度",
            resolved: "解決された問題"
        }
    },
    
    // Уведомления
        notifications: {
            settingsSaved: "すべての設定が正常に保存されました",
            settingsError: "設定の保存エラー",
            periodWarning: "モニタリング保持期間は7〜365日である必要があります",
            analysisWarning: "分析保持期間は30〜365日である必要があります",
            copiedToClipboard: "クリップボードにコピーされました",
            autoAnalysisEnabled: "サーバー自動分析が有効（5分ごとにチェック）",
            autoAnalysisDisabled: "サーバー自動分析が無効",
            clientDataNotFound: "クライアントデータが見つかりません",
            deleting: "レコードを削除中...",
            deleteSuccess: "レコードが正常に削除されました",
            deleteError: "削除中にエラーが発生しました"
        },
        
        auth: {
        loginSuccess: "ログイン成功！",
        logoutConfirm: "ログアウトしてもよろしいですか？",
        logoutSuccess: "ログアウトしました",
        logoutButton: "ログアウト",
        notAuthorized: "ユーザーは承認されていません",
        accessDenied: "アクセスが拒否されました！必要な役割：",
        or: " または ",
        invalidCredentials: "ユーザー名またはパスワードが無効です",
        loginError: "ログインエラー。もう一度お試しください。",
        modalTitle: "監視ダッシュボード",
        modalSubtitle: "アクセスするには認証情報を入力してください",
        usernameLabel: "ユーザー名",
        usernamePlaceholder: "ユーザー名を入力",
        passwordLabel: "パスワード",
        passwordPlaceholder: "パスワードを入力",
        rememberMe: "7日間ログイン状態を保持",
        loginButton: "ログイン",
        secureConnection: "セキュア接続"
    },
        
        deleteModal: {
    title: "削除の確認",
    messageSession: "このレコードを削除してもよろしいですか？",
    messageEmail: "このメール会話を削除してもよろしいですか？",
    cancel: "キャンセル",
    confirm: "削除"
},
    
    contacts: {
    title: "連絡先情報",
    name: "名前",
    phone: "電話番号",
    email: "メールアドレス",
    messengers: "メッセンジャー",
    company: "会社",
    extracting: "連絡先を抽出中...",
    extracted: "連絡先が抽出されました",
    extractError: "連絡先の抽出エラー",
    dataSource: "データソース",
    aiConfidence: "AI信頼度",
    extractedFromDialog: "対話から",
    extractedFromProfile: "プロフィールから"
},

clientCard: {
    title: "クライアントカード",
    tabs: {
        overview: "概要",
        dialog: "対話",
        details: "詳細",
        history: "履歴",
        analysis: "分析結果"
    },
    quickActions: {
        analyze: "分析を実行",
        extractContacts: "連絡先を抽出"
    },
    overview: {
        messages: "メッセージ",
        duration: "期間",
        satisfaction: "満足度",
        geolocation: "ジオロケーション",
        ipAddress: "IPアドレス",
        country: "国",
        city: "都市",
        professionalInfo: "専門情報",
        company: "会社",
        position: "役職",
        location: "場所"
    },
    details: {
        technicalInfo: "技術情報",
        sessionId: "セッションID",
        platform: "プラットフォーム",
        configuration: "設定",
        language: "言語",
        timestamps: "タイムスタンプ",
        firstMessage: "最初のメッセージ",
        lastActivity: "最後のアクティビティ",
        dataSource: "連絡先データソース",
        aiConfidence: "AI信頼度"
    },
    history: {
        dialogStart: "対話開始",
        contactsExtracted: "連絡先抽出済み",
        analysisCompleted: "分析完了",
        satisfactionLevel: "満足度",
        lastActivity: "最後のアクティビティ"
    },
    contact: {
        phone: "電話",
        email: "メール",
        copyToClipboard: "クリックしてコピー",
        openInApp: "アプリで開く"
    },
    status: {
        active: "アクティブ",
        inactive: "非アクティブ"
    }
  },
  
  highlights: {
    title: "重要な瞬間",
    button: "Highlights",
    analyzing: "ダイアログを分析中...",
    analyzed: "Highlightsが処理されました",
    analyzeError: "Highlightsの処理エラー",
    noHighlights: "重要な瞬間が見つかりません",
    found: "見つかりました",
    reanalyze: "再分析",
    newMessages: "件の新しいメッセージ",
    reanalyzing: "再分析中...",
    reanalyzed: "再分析完了！",
    reanalyzeError: "再分析中にエラーが発生しました",
    newMessagesDetected: "前回の分析以降、{count} 件の新しいメッセージが検出されました",
    stats: {
        title: "統計",
        total: "合計"
    },
    types: {
        pricing: "価格",
        objection: "異議",
        buying_signal: "購入シグナル"
    },
    confidence: "信頼度",
    scrollTo: "メッセージに移動",
    filters: {
        all: "すべて",
        pricing: "価格",
        objection: "異議",
        buying_signal: "シグナル"
    },
    noFilterResults: "このタイプのハイライトはありません"
},
  
  // Lead Scoring
leadScoring: {
    title: "リードスコアリング",
    score: "リードスコア",
    temperature: {
        hot: "ホット",
        warm: "ウォーム",
        cold: "コールド",
        leadType: "リード"
    },
    factors: {
        satisfaction: "満足度",
        contacts: "連絡先",
        points: "ポイント"
    },
    recommendation: "推奨事項",
    urgentNotice: "CRMへの緊急送信を推奨します！",
    sendToCRM: "CRMに送信",
    sentToCRM: "CRMに送信済み",
    confirmSend: "{temperature}リード（スコア：{score}）をCRMに送信しますか？",
    sending: "CRMにデータを送信中...",
    successMessage: "リードをCRMに送信しました！スコア：{score}（{temperature}）",
    errorMessage: "CRM送信エラー：{error}",
    unknownError: "不明なエラー",
    crmIdLabel: "CRM ID"
},

bantAnalysis: {
    title: "BANT認定",
    showAnalysis: "BANT分析を表示",
    hideAnalysis: "分析を隠す",
    qualified: "認定済み",
    notQualified: "未認定",
    qualificationLevel: {
        label: "認定レベル",
        SQL: "SQL（営業認定リード）",
        MQL: "MQL（マーケティング認定リード）",
        cold: "コールドリード",                      // ⭐ 追加済み
        warm: "ウォームリード",                      // ⭐ 追加済み
        hot: "ホットリード",                        // ⭐ 追加済み
        Unqualified: "未認定"
    },
    totalScore: "総スコア",
    factors: {
        budget: {
            title: "💰 予算",
            score: "スコア",
            value: "金額",
            range: "範囲",
            mentioned: "言及",
            confidence: "信頼度",
            yes: "はい",
            no: "いいえ"
        },
        authority: {
            title: "👤 権限",
            score: "スコア",
            role: "役割",
            level: "レベル",
            position: "役職",
            confidence: "信頼度",
            roles: {
                decision_maker: "意思決定者",
                influencer: "影響者",
                gatekeeper: "ゲートキーパー",
                user: "ユーザー",
                unknown: "不明"
            },
            levels: {
                c_level: "Cレベル",
                executive: "役員",
                manager: "マネージャー",
                user: "ユーザー",
                specialist: "スペシャリスト",
                unknown: "不明"
            }
        },
        need: {
            title: "🎯 ニーズ",
            score: "スコア",
            severity: "深刻度",
            painPoints: "ペインポイント",
            confidence: "信頼度",
            severityLevels: {
                critical: "重大",
                high: "高",
                medium: "中",
                low: "低"
            }
        },
        timeline: {
            title: "⏰ タイムライン",
            score: "スコア",
            urgency: "緊急度",
            deadline: "期限",
            confidence: "信頼度",
            urgencyLevels: {
                immediate: "即時",
                this_week: "今週",
                this_month: "今月",
                this_quarter: "今四半期",
                short_term: "短期",
                medium_term: "中期",
                long_term: "長期",
                later: "後で",
                undefined: "未定義"
            }
        }
    },
    reasoning: "理由",
    description: "説明",
    confidence: "信頼度"
},

// テストリード
testLead: {
    title: "🧪 監視システムからのテストリード",
    name: "テスト",
    comments: "これは統合を確認するためのテストリードです。作成日：{date}",
    testSuccess: "CRM接続成功！テストリードが作成されました。",
    specifyWebhook: "Webhook URLを指定してください",
    testing: "テスト中...",
    connectionError: "CRM接続エラー"
},

// CRMステータス
crmStatuses: {
    loading: "CRMステータスが読み込まれました：{count}",
    loadError: "CRMステータスの読み込みエラー"
},

// モーダルのCRM設定
crmSettings: {
    loaded: "CRM設定が読み込まれました",
    saveError: "CRM設定の保存エラー",
    specifyUrl: "CRM Webhook URLを指定してください",
    urlMustContain: "Webhook URLは有効である必要があります",
    testResultSuccess: "成功！リードID：{id}",
    testResultError: "エラー：{error}"
},

// CRM統合
crm: {
    title: "CRM統合設定",
    webhookUrl: "CRM Webhook URL：",
    webhookHint: "CRMシステムの設定からwebhook URLを取得してください",
    autoSend: "ホットリードの自動送信：",
    autoSendHint: "リードスコア≥最小値のリードを自動的にCRMに送信",
    minScore: "自動送信の最小リードスコア：",
    scoreRange: "(50-100)",
    testConnection: "接続テスト",
    sendButton: "CRMに送信",
    sentButton: "CRMに送信済み"
   },
   
   crmConfirm: {
    title: "アクションを確認",
    confirmMessage: "{temperature}リード（スコア：{score}）をCRMに送信しますか？",
    cancelButton: "キャンセル",
    sendButton: "送信"
},
   
   emailMonitoring: {
    tabs: {
        messengers: "メッセンジャーユーザー",
        email: "メールのやり取り"
    },
    table: {
        columns: {
            email: "メール",
            name: "名前",
            subject: "件名",
            status: "ステータス",
            leadScore: "リードスコア",
            satisfaction: "満足度",
            messages: "メッセージ数",
            lastActivity: "最終アクティビティ",
            actions: "アクション"
        },
        status: {
            new: "📥 新規",
            unread: "🔵 未読",
            waiting: "⏳ 返信待ち",
            conversation: "💬 会話中",
            inactive: "💤 非アクティブ"
        },
        actions: {
            viewDialog: "ダイアログ",
            viewAnalysis: "結果",
            extractContacts: "連絡先を更新",
            runAnalysis: "分析",
            deleteRecord: "削除"
        },
        noData: "表示するデータがありません",
        loading: "メールデータを読み込み中..."
    }
   }
},

// 🇰🇷 КОРЕЙСКИЙ
ko: {
    // Заголовок
    header: {
        title: "모니터링 대시보드",
        live: "라이브",
        settings: "설정"
    },
    
    // Фильтры
    filters: {
        period: {
            label: "기간",
            options: {
                '1h': "지난 1시간",
                '24h': "지난 24시간",
                '7d': "지난 주",
                '30d': "지난 달",
                'custom': "사용자 정의 기간"
            },
            customStart: "시작 날짜",
            customEnd: "종료 날짜"
        },
        configuration: {
            label: "구성",
            all: "모든 구성"
        },
        platform: {
            label: "플랫폼",
            all: "모든 플랫폼"
        },
        search: {
            placeholder: "IP, 국가, 도시로 검색..."
        },
        buttons: {
            refresh: "새로고침",
            analyzeAll: "모두 분석",
            analyzeByLanguage: "언어별 분석",
            analyzeLabel: "대화 분석"
        }
    },
    
    analysisResultLanguage: {
    label: "분석 결과 언어",
    modalTitle: "분석 결과 언어 선택",
    notification: "분석 결과 언어가 {language}로 변경되었습니다",
    loadError: "분석 언어 로드 오류",
    setError: "언어 설정 오류",
    configError: "언어 구성을 찾을 수 없습니다",
    containerError: "버튼 컨테이너를 찾을 수 없습니다"
},
    // Карточки статистики
    stats: {
        totalUsers: {
            title: "총 사용자",
            trend: "기간 동안"
        },
        activeSessions: {
            title: "활성 세션",
            trend: "안정적"
        },
        avgSessionTime: {
            title: "평균 세션 시간",
            trend: "기간 동안"
        },
        totalMessages: {
            title: "총 메시지",
            trend: "기간 동안"
        }
    },
    
    // Графики
    charts: {
        activity: {
            title: "시간별 활동",
            refresh: "차트 새로고침",
            yAxis: "이벤트 수",
            currentHour: "현재 시간",
            events: "이벤트"
        },
        geography: {
            title: "사용자 지역",
            refresh: "차트 새로고침",
            noData: "표시할 데이터가 없습니다"
        },
        platforms: {
            title: "플랫폼 분포",
            refresh: "차트 새로고침",
            noData: "표시할 데이터가 없습니다"
        }
    },
    
    // Таблица
    table: {
        title: "사용자",
        export: "내보내기",
        noData: "표시할 데이터가 없습니다",
        loading: "데이터 로딩 중...",
        columns: {
            leadScore: "점수",
            contactName: "이름",
            contactPhone: "전화번호",
            contactEmail: "이메일",
            contactMessengers: "메신저",
            contactCompany: "회사",
            sessionId: "세션 ID",
            ipAddress: "IP 주소",
            country: "국가",
            city: "도시",
            platform: "플랫폼",
            configuration: "구성",
            startTime: "시작 시간",
            duration: "기간",
            messages: "메시지",
            satisfaction: "만족도",
            crmStatus: "CRM", 
            status: "상태",
            actions: "작업"
        },
        status: {
            active: "활성",
            inactive: "비활성"
        },
        actions: {
            viewDialog: "대화",
            analyze: "분석",
            viewAnalysis: "결과",
            extractContacts: "연락처 추출",
            updateContacts: "연락처 업데이트",
            deleteRecord: "삭제"
        }
    },
    
    // Пагинация
    pagination: {
        previous: "이전",
        next: "다음"
    },
    
    // Модальные окна
    dialogs: {
        dialog: {
            title: "대화",
            loading: "대화 로딩 중...",
            notFound: "대화를 찾을 수 없습니다",
            error: "대화 로드 오류",
            user: "사용자",
            bot: "봇"
        },
        analysis: {
            title: "대화 분석",
            loading: "대화 분석 중",
            error: "대화 분석 오류",
            analyzingAll: "모든 대화 분석 중...",
            timeNotice: "몇 분 정도 걸릴 수 있습니다"
        },
        language: {
            title: "분석 언어 선택",
            russian: "러시아어",
            english: "영어"
        },
        settings: {
            title: "모니터링 설정",
            autoAnalysis: {
                title: "자동 대화 분석",
                enable: "자동 분석 활성화",
                delay: "비활성 후 지연",
                minutes: "분",
                serverMode: "서버 모드",
                enabledNotice: "서버 자동 분석 활성화됨 (5분마다 확인)",
                disabledNotice: "서버 자동 분석 비활성화됨"
            },
            dbCleanup: {
    title: "자동 데이터베이스 정리",
    active: "활성 (매일 오전 3시)",
    monitoringData: "모니터링 데이터 보관",
    analysisResults: "분석 결과 보관",
    dialogsData: "대화 보관",
    contactsData: "연락처 데이터 보관",
    days: "일"
},
            buttons: {
                save: "모든 설정 저장",
                cancel: "취소"
            }
        }
    },
    
    // Форматирование
    formatting: {
        today: "오늘",
        yesterday: "어제",
        seconds: "초",
        minutes: "분",
        hours: "시",
        unknown: "N/A",
        guest: "게스트"
    },
    
    // Ошибки
    errors: {
        loadData: "데이터를 로드할 수 없습니다. 연결을 확인하세요.",
        connectionError: "서버 연결 오류"
    },
    
    // Анализ
    analysis: {
        emotionalTone: {
            title: "대화의 감정적 톤",
            overall: "전체적인 톤",
            satisfaction: "고객 만족도",
            positive: "긍정적",
            negative: "부정적",
            neutral: "중립적"
        },
        needs: {
            title: "식별된 요구사항"
        },
        missedOpportunities: {
            title: "놓친 기회"
        },
        recommendations: {
            title: "개선 권장사항"
        },
        statistics: {
            title: "전체 통계",
            totalDialogs: "분석된 대화",
            avgSatisfaction: "평균 만족도",
            resolved: "해결된 문제"
        }
    },
    
    // Уведомления
        notifications: {
            settingsSaved: "모든 설정이 성공적으로 저장되었습니다",
            settingsError: "설정 저장 오류",
            periodWarning: "모니터링 보관 기간은 7일에서 365일 사이여야 합니다",
            analysisWarning: "분석 보관 기간은 30일에서 365일 사이여야 합니다",
            copiedToClipboard: "클립보드에 복사됨",
            autoAnalysisEnabled: "서버 자동 분석 활성화됨 (5분마다 확인)",
            autoAnalysisDisabled: "서버 자동 분석 비활성화됨",
            clientDataNotFound: "클라이언트 데이터를 찾을 수 없습니다",
            deleting: "기록 삭제 중...",
            deleteSuccess: "기록이 성공적으로 삭제되었습니다",
            deleteError: "삭제 중 오류가 발생했습니다"
        },
        
        auth: {
        loginSuccess: "로그인 성공!",
        logoutConfirm: "로그아웃 하시겠습니까?",
        logoutSuccess: "로그아웃되었습니다",
        logoutButton: "로그아웃",
        notAuthorized: "사용자가 승인되지 않았습니다",
        accessDenied: "액세스가 거부되었습니다! 필요한 역할: ",
        or: " 또는 ",
        invalidCredentials: "잘못된 사용자 이름 또는 비밀번호",
        loginError: "로그인 오류. 다시 시도하세요.",
        modalTitle: "모니터링 대시보드",
        modalSubtitle: "액세스하려면 자격 증명을 입력하세요",
        usernameLabel: "사용자 이름",
        usernamePlaceholder: "사용자 이름 입력",
        passwordLabel: "비밀번호",
        passwordPlaceholder: "비밀번호 입력",
        rememberMe: "7일 동안 로그인 유지",
        loginButton: "로그인",
        secureConnection: "보안 연결"
    },
        
        deleteModal: {
    title: "삭제 확인",
    messageSession: "이 기록을 삭제하시겠습니까?",
    messageEmail: "이 이메일 대화를 삭제하시겠습니까?",
    cancel: "취소",
    confirm: "삭제"
},
    
    contacts: {
    title: "연락처 정보",
    name: "이름",
    phone: "전화번호",
    email: "이메일",
    messengers: "메신저",
    company: "회사",
    extracting: "연락처 추출 중...",
    extracted: "연락처가 추출되었습니다",
    extractError: "연락처 추출 오류",
    dataSource: "데이터 소스",
    aiConfidence: "AI 신뢰도",
    extractedFromDialog: "대화에서",
    extractedFromProfile: "프로필에서"
},

clientCard: {
    title: "고객 카드",
    tabs: {
        overview: "개요",
        dialog: "대화",
        details: "세부사항",
        history: "기록",
        analysis: "분석 결과"
    },
    quickActions: {
        analyze: "분석 실행",
        extractContacts: "연락처 추출"
    },
    overview: {
        messages: "메시지",
        duration: "기간",
        satisfaction: "만족도",
        geolocation: "위치정보",
        ipAddress: "IP 주소",
        country: "국가",
        city: "도시",
        professionalInfo: "전문 정보",
        company: "회사",
        position: "직책",
        location: "위치"
    },
    details: {
        technicalInfo: "기술 정보",
        sessionId: "세션 ID",
        platform: "플랫폼",
        configuration: "구성",
        language: "언어",
        timestamps: "타임스탬프",
        firstMessage: "첫 메시지",
        lastActivity: "마지막 활동",
        dataSource: "연락처 데이터 소스",
        aiConfidence: "AI 신뢰도"
    },
    history: {
        dialogStart: "대화 시작",
        contactsExtracted: "연락처 추출됨",
        analysisCompleted: "분석 완료",
        satisfactionLevel: "만족도",
        lastActivity: "마지막 활동"
    },
    contact: {
        phone: "전화",
        email: "이메일",
        copyToClipboard: "복사하려면 클릭",
        openInApp: "앱에서 열기"
    },
    status: {
        active: "활성",
        inactive: "비활성"
    }
  },
  
  highlights: {
    title: "주요 순간",
    button: "Highlights",
    analyzing: "대화 분석 중...",
    analyzed: "Highlights 처리됨",
    analyzeError: "Highlights 처리 오류",
    noHighlights: "주요 순간을 찾을 수 없습니다",
    found: "발견됨",
    reanalyze: "재분석",
    newMessages: "개의 새 메시지",
    reanalyzing: "재분석 중...",
    reanalyzed: "재분석 완료!",
    reanalyzeError: "재분석 중 오류 발생",
    newMessagesDetected: "마지막 분석 이후 {count}개의 새 메시지가 감지되었습니다",
    stats: {
        title: "통계",
        total: "총"
    },
    types: {
        pricing: "가격",
        objection: "이의",
        buying_signal: "구매 신호"
    },
    confidence: "신뢰도",
    scrollTo: "메시지로 이동",
    filters: {
        all: "모두",
        pricing: "가격",
        objection: "이의",
        buying_signal: "신호"
    },
    noFilterResults: "이 유형의 하이라이트가 없습니다"
},
  
  // Lead Scoring
leadScoring: {
    title: "리드 스코어링",
    score: "리드 점수",
    temperature: {
        hot: "핫",
        warm: "웜",
        cold: "콜드",
        leadType: "리드"
    },
    factors: {
        satisfaction: "만족도",
        contacts: "연락처",
        points: "점"
    },
    recommendation: "권장사항",
    urgentNotice: "CRM으로 긴급 전송을 권장합니다!",
    sendToCRM: "CRM으로 보내기",
    sentToCRM: "CRM으로 전송됨",
    confirmSend: "{temperature} 리드 (점수: {score})를 CRM으로 보내시겠습니까?",
    sending: "CRM으로 데이터 전송 중...",
    successMessage: "리드가 CRM으로 전송되었습니다! 점수: {score} ({temperature})",
    errorMessage: "CRM 전송 오류: {error}",
    unknownError: "알 수 없는 오류",
    crmIdLabel: "CRM ID"
},

bantAnalysis: {
    title: "BANT 자격",
    showAnalysis: "BANT 분석 표시",
    hideAnalysis: "분석 숨기기",
    qualified: "자격 있음",
    notQualified: "자격 없음",
    qualificationLevel: {
        label: "자격 수준",
        SQL: "SQL (영업 적격 리드)",
        MQL: "MQL (마케팅 적격 리드)",
        cold: "콜드 리드",                          // ⭐ 추가됨
        warm: "웜 리드",                            // ⭐ 추가됨
        hot: "핫 리드",                             // ⭐ 추가됨
        Unqualified: "자격 없음"
    },
    totalScore: "총점",
    factors: {
        budget: {
            title: "💰 예산",
            score: "점수",
            value: "금액",
            range: "범위",
            mentioned: "언급됨",
            confidence: "신뢰도",
            yes: "예",
            no: "아니오"
        },
        authority: {
            title: "👤 권한",
            score: "점수",
            role: "역할",
            level: "수준",
            position: "직위",
            confidence: "신뢰도",
            roles: {
                decision_maker: "의사 결정자",
                influencer: "영향력자",
                gatekeeper: "게이트키퍼",
                user: "사용자",
                unknown: "알 수 없음"
            },
            levels: {
                c_level: "C레벨",
                executive: "임원",
                manager: "관리자",
                user: "사용자",
                specialist: "전문가",
                unknown: "알 수 없음"
            }
        },
        need: {
            title: "🎯 필요",
            score: "점수",
            severity: "심각도",
            painPoints: "문제점",
            confidence: "신뢰도",
            severityLevels: {
                critical: "치명적",
                high: "높음",
                medium: "중간",
                low: "낮음"
            }
        },
        timeline: {
            title: "⏰ 일정",
            score: "점수",
            urgency: "긴급도",
            deadline: "마감일",
            confidence: "신뢰도",
            urgencyLevels: {
                immediate: "즉시",
                this_week: "이번 주",
                this_month: "이번 달",
                this_quarter: "이번 분기",
                short_term: "단기",
                medium_term: "중기",
                long_term: "장기",
                later: "나중에",
                undefined: "정의되지 않음"
            }
        }
    },
    reasoning: "근거",
    description: "설명",
    confidence: "신뢰도"
},

// 테스트 리드
testLead: {
    title: "🧪 모니터링 시스템의 테스트 리드",
    name: "테스트",
    comments: "통합을 확인하기 위한 테스트 리드입니다. 생성됨: {date}",
    testSuccess: "CRM 연결 성공! 테스트 리드가 생성되었습니다.",
    specifyWebhook: "Webhook URL을 지정하세요",
    testing: "테스트 중...",
    connectionError: "CRM 연결 오류"
},

// CRM 상태
crmStatuses: {
    loading: "CRM 상태 로드됨: {count}",
    loadError: "CRM 상태 로드 오류"
},

// 모달의 CRM 설정
crmSettings: {
    loaded: "CRM 설정이 로드되었습니다",
    saveError: "CRM 설정 저장 오류",
    specifyUrl: "CRM Webhook URL을 지정하세요",
    urlMustContain: "Webhook URL은 유효해야 합니다",
    testResultSuccess: "성공! 리드 ID: {id}",
    testResultError: "오류: {error}"
},

// CRM 통합
crm: {
    title: "CRM 통합 설정",
    webhookUrl: "CRM Webhook URL:",
    webhookHint: "CRM 시스템 설정에서 webhook URL을 가져오세요",
    autoSend: "핫 리드 자동 전송:",
    autoSendHint: "리드 점수 ≥ 최소값인 리드를 자동으로 CRM으로 전송",
    minScore: "자동 전송을 위한 최소 리드 점수:",
    scoreRange: "(50-100)",
    testConnection: "연결 테스트",
    sendButton: "CRM으로 보내기",
    sentButton: "CRM으로 전송됨"
   },
   
   crmConfirm: {
    title: "작업 확인",
    confirmMessage: "{temperature} 리드(점수: {score})를 CRM으로 보내시겠습니까?",
    cancelButton: "취소",
    sendButton: "보내기"
},
   
   emailMonitoring: {
    tabs: {
        messengers: "메신저 사용자",
        email: "이메일 대화"
    },
    table: {
        columns: {
            email: "이메일",
            name: "이름",
            subject: "제목",
            status: "상태",
            leadScore: "리드 스코어",
            satisfaction: "만족도",
            messages: "메시지",
            lastActivity: "마지막 활동",
            actions: "작업"
        },
        status: {
            new: "📥 신규",
            unread: "🔵 읽지 않음",
            waiting: "⏳ 응답 대기 중",
            conversation: "💬 대화 중",
            inactive: "💤 비활성"
        },
        actions: {
            viewDialog: "대화",
            viewAnalysis: "결과",
            extractContacts: "연락처 업데이트",
            runAnalysis: "분석",
            deleteRecord: "삭제"
        },
        noData: "표시할 데이터가 없습니다",
        loading: "이메일 데이터 로딩 중..."
    }
  }
},

// 🇺🇦 УКРАИНСКИЙ
ua: {
    // Заголовок
    header: {
        title: "Панель Моніторингу",
        live: "Наживо",
        settings: "Налаштування"
    },
    
    // Фильтры
    filters: {
        period: {
            label: "Період",
            options: {
                '1h': "Остання година",
                '24h': "Останні 24 години",
                '7d': "Останній тиждень",
                '30d': "Останній місяць",
                'custom': "Довільний період"
            },
            customStart: "Дата початку",
            customEnd: "Дата закінчення"
        },
        configuration: {
            label: "Конфігурація",
            all: "Всі конфігурації"
        },
        platform: {
            label: "Платформа",
            all: "Всі платформи"
        },
        search: {
            placeholder: "Пошук за IP, країною, містом..."
        },
        buttons: {
            refresh: "Оновити",
            analyzeAll: "Аналіз всіх",
            analyzeByLanguage: "Аналіз за мовою",
            analyzeLabel: "Аналіз діалогів"
        }
    },
    
    analysisResultLanguage: {
    label: "Мова результату аналізу",
    modalTitle: "Виберіть мову результатів аналізу",
    notification: "Мову результатів аналізу змінено на: {language}",
    loadError: "Помилка завантаження мови аналізу",
    setError: "Помилка встановлення мови",
    configError: "Конфігурацію мов не знайдено",
    containerError: "Контейнер для кнопок не знайдено"
},
    // Карточки статистики
    stats: {
        totalUsers: {
            title: "Всього користувачів",
            trend: "за період"
        },
        activeSessions: {
            title: "Активні сесії",
            trend: "Стабільно"
        },
        avgSessionTime: {
            title: "Середній час сесії",
            trend: "за період"
        },
        totalMessages: {
            title: "Всього повідомлень",
            trend: "за період"
        }
    },
    
    // Графики
    charts: {
        activity: {
            title: "Активність за часом",
            refresh: "Оновити графік",
            yAxis: "Кількість подій",
            currentHour: "Поточна година",
            events: "Події"
        },
        geography: {
            title: "Географія користувачів",
            refresh: "Оновити графік",
            noData: "Немає даних для відображення"
        },
        platforms: {
            title: "Розподіл за платформами",
            refresh: "Оновити графік",
            noData: "Немає даних для відображення"
        }
    },
    
    // Таблица
    table: {
        title: "Користувачі",
        export: "Експорт",
        noData: "Немає даних для відображення",
        loading: "Завантаження даних...",
        columns: {
            leadScore: "Оцінка",
            contactName: "Ім'я",
            contactPhone: "Телефон",
            contactEmail: "Email",
            contactMessengers: "Месенджери",
            contactCompany: "Компанія",
            sessionId: "ID сесії",
            ipAddress: "IP адреса",
            country: "Країна",
            city: "Місто",
            platform: "Платформа",
            configuration: "Конфігурація",
            startTime: "Час початку",
            duration: "Тривалість",
            messages: "Повідомлень",
            satisfaction: "Задоволеність",
            crmStatus: "CRM", 
            status: "Статус",
            actions: "Дії"
        },
        status: {
            active: "Активний",
            inactive: "Неактивний"
        },
        actions: {
            viewDialog: "Діалог",
            analyze: "Аналіз",
            viewAnalysis: "Результат",
            extractContacts: "Витягти контакти",
            updateContacts: "Оновити контакти",
            deleteRecord: "Видалити"
        }
    },
    
    // Пагинация
    pagination: {
        previous: "Назад",
        next: "Вперед"
    },
    
    // Модальные окна
    dialogs: {
        dialog: {
            title: "Діалог",
            loading: "Завантаження діалогу...",
            notFound: "Діалог не знайдено",
            error: "Помилка завантаження діалогу",
            user: "Користувач",
            bot: "Бот"
        },
        analysis: {
            title: "Аналіз діалогу",
            loading: "Аналізуємо діалог",
            error: "Помилка при аналізі діалогу",
            analyzingAll: "Аналізуємо всі діалоги...",
            timeNotice: "Це може зайняти кілька хвилин"
        },
       language: {
           title: "Виберіть мову для аналізу",
           russian: "Російська",
           english: "Англійська"
       },
       settings: {
           title: "Налаштування моніторингу",
           autoAnalysis: {
               title: "Автоматичний аналіз діалогів",
               enable: "Увімкнути автоаналіз",
               delay: "Затримка після неактивності",
               minutes: "хвилин",
               serverMode: "Серверний режим",
               enabledNotice: "Серверний автоаналіз увімкнено (перевірка кожні 5 хвилин)",
               disabledNotice: "Серверний автоаналіз вимкнено"
           },
           dbCleanup: {
    title: "Автоматичне очищення бази даних",
    active: "Активне (щодня о 3:00)",
    monitoringData: "Зберігати дані моніторингу",
    analysisResults: "Зберігати результати аналізів",
    dialogsData: "Зберігати діалоги",
    contactsData: "Зберігати контактні дані",
    days: "днів"
},
           buttons: {
               save: "Зберегти всі налаштування",
               cancel: "Скасувати"
           }
       }
   },
   
   // Форматирование
   formatting: {
       today: "Сьогодні",
       yesterday: "Вчора",
       seconds: "сек",
       minutes: "хв",
       hours: "год",
       unknown: "Н/Д",
       guest: "Гість"
   },
   
   // Ошибки
   errors: {
       loadData: "Не вдалося завантажити дані. Перевірте підключення.",
       connectionError: "Помилка підключення до сервера"
   },
   
   // Анализ
   analysis: {
       emotionalTone: {
           title: "Емоційний тон діалогу",
           overall: "Загальний тон",
           satisfaction: "Задоволеність клієнта",
           positive: "Позитивний",
           negative: "Негативний",
           neutral: "Нейтральний"
       },
       needs: {
           title: "Виявлені потреби"
       },
       missedOpportunities: {
           title: "Втрачені можливості"
       },
       recommendations: {
           title: "Рекомендації щодо покращення"
       },
       statistics: {
           title: "Загальна статистика",
           totalDialogs: "Проаналізовано діалогів",
           avgSatisfaction: "Середня задоволеність",
           resolved: "Вирішено питань"
       }
   },
   
   // Уведомления
        notifications: {
            settingsSaved: "Всі налаштування успішно збережено",
            settingsError: "Помилка збереження налаштувань",
            periodWarning: "Період зберігання моніторингу має бути від 7 до 365 днів",
            analysisWarning: "Період зберігання аналізів має бути від 30 до 365 днів",
            copiedToClipboard: "Скопійовано в буфер обміну",
            autoAnalysisEnabled: "Серверний автоаналіз увімкнено (перевірка кожні 5 хвилин)",
            autoAnalysisDisabled: "Серверний автоаналіз вимкнено",
            clientDataNotFound: "Дані клієнта не знайдено",
            deleting: "Видалення запису...",
            deleteSuccess: "Запис успішно видалено",
            deleteError: "Помилка при видаленні запису"
        },
        
        auth: {
        loginSuccess: "Вхід виконано успішно!",
        logoutConfirm: "Ви впевнені, що хочете вийти?",
        logoutSuccess: "Ви вийшли з системи",
        logoutButton: "Вихід",
        notAuthorized: "Користувач не авторизований",
        accessDenied: "Доступ заборонено! Потрібна роль: ",
        or: " або ",
        invalidCredentials: "Невірне ім'я користувача або пароль",
        loginError: "Помилка входу. Спробуйте ще раз.",
        modalTitle: "Панель моніторингу",
        modalSubtitle: "Введіть облікові дані для доступу",
        usernameLabel: "Ім'я користувача",
        usernamePlaceholder: "Введіть логін",
        passwordLabel: "Пароль",
        passwordPlaceholder: "Введіть пароль",
        rememberMe: "Запам'ятати мене на 7 днів",
        loginButton: "Увійти",
        secureConnection: "Захищене з'єднання"
    },
        
        deleteModal: {
    title: "Підтвердження видалення",
    messageSession: "Ви впевнені, що хочете видалити цей запис?",
    messageEmail: "Ви впевнені, що хочете видалити це листування?",
    cancel: "Скасувати",
    confirm: "Видалити"
},
   
   contacts: {
    title: "Контактні дані",
    name: "Ім'я",
    phone: "Телефон",
    email: "Email",
    messengers: "Месенджери",
    company: "Компанія",
    extracting: "Витягування контактів...",
    extracted: "Контакти витягнуто",
    extractError: "Помилка витягування контактів",
    dataSource: "Джерело даних",
    aiConfidence: "Впевненість AI",
    extractedFromDialog: "з діалогу",
    extractedFromProfile: "з профілю"
},

clientCard: {
    title: "Картка клієнта",
    tabs: {
        overview: "Огляд",
        dialog: "Діалог",
        details: "Деталі",
        history: "Історія",
        analysis: "Результат аналізу"
    },
    quickActions: {
        analyze: "Провести аналіз",
        extractContacts: "Витягти контакти"
    },
    overview: {
        messages: "Повідомлень",
        duration: "Тривалість",
        satisfaction: "Задоволеність",
        geolocation: "Геолокація",
        ipAddress: "IP адреса",
        country: "Країна",
        city: "Місто",
        professionalInfo: "Професійна інформація",
        company: "Компанія",
        position: "Посада",
        location: "Місцезнаходження"
    },
    details: {
        technicalInfo: "Технічна інформація",
        sessionId: "ID сесії",
        platform: "Платформа",
        configuration: "Конфігурація",
        language: "Мова",
        timestamps: "Часові мітки",
        firstMessage: "Перше повідомлення",
        lastActivity: "Остання активність",
        dataSource: "Джерело контактних даних",
        aiConfidence: "Впевненість AI"
    },
    history: {
        dialogStart: "Початок діалогу",
        contactsExtracted: "Контакти витягнуто",
        analysisCompleted: "Проведено аналіз",
        satisfactionLevel: "задоволеність",
        lastActivity: "Остання активність"
    },
    contact: {
        phone: "Телефон",
        email: "Email",
        copyToClipboard: "Натисніть для копіювання",
        openInApp: "Відкрити в додатку"
    },
    status: {
        active: "Активний",
        inactive: "Неактивний"
    }
  },
  
  highlights: {
    title: "Ключові моменти",
    button: "Highlights",
    analyzing: "Аналізуємо діалог...",
    analyzed: "Highlights оброблені",
    analyzeError: "Помилка обробки highlights",
    noHighlights: "Ключові моменти не знайдені",
    found: "Знайдено",
    reanalyze: "Повторний аналіз",
    newMessages: "нових повідомлень",
    reanalyzing: "Повторний аналіз...",
    reanalyzed: "Повторний аналіз завершено!",
    reanalyzeError: "Помилка під час повторного аналізу",
    newMessagesDetected: "Виявлено {count} нових повідомлень після останнього аналізу",
    stats: {
        title: "Статистика",
        total: "Всього"
    },
    types: {
        pricing: "Ціни",
        objection: "Заперечення",
        buying_signal: "Сигнали купівлі"
    },
    confidence: "Впевненість",
    scrollTo: "Перейти до повідомлення",
    filters: {
        all: "Всі",
        pricing: "Ціни",
        objection: "Заперечення",
        buying_signal: "Сигнали"
    },
    noFilterResults: "Немає highlights цього типу"
},
  
  // Lead Scoring
leadScoring: {
    title: "Lead Scoring",
    score: "Lead Score",
    temperature: {
        hot: "Гарячий",
        warm: "Теплий",
        cold: "Холодний",
        leadType: "лід"
    },
    factors: {
        satisfaction: "Задоволеність",
        contacts: "Контакти",
        points: "балів"
    },
    recommendation: "Рекомендація",
    urgentNotice: "Рекомендується термінова відправка в CRM!",
    sendToCRM: "Відправити в CRM",
    sentToCRM: "Відправлено в CRM",
    confirmSend: "Відправити {temperature} лід (Score: {score}) в CRM?",
    sending: "Відправка даних в CRM...",
    successMessage: "Лід відправлено в CRM! Score: {score} ({temperature})",
    errorMessage: "Помилка відправки в CRM: {error}",
    unknownError: "Невідома помилка",
    crmIdLabel: "ID в CRM"
},

bantAnalysis: {
    title: "BANT-кваліфікація",
    showAnalysis: "Показати аналіз BANT",
    hideAnalysis: "Приховати аналіз",
    qualified: "Кваліфіковано",
    notQualified: "Не кваліфіковано",
    qualificationLevel: {
        label: "Рівень кваліфікації",
        SQL: "SQL (Кваліфікований лід для продажів)",
        MQL: "MQL (Кваліфікований лід для маркетингу)",
        cold: "Холодний лід",                       // ⭐ ДОДАНО
        warm: "Теплий лід",                         // ⭐ ДОДАНО
        hot: "Гарячий лід",                         // ⭐ ДОДАНО
        Unqualified: "Не кваліфіковано"
    },
    totalScore: "Загальний бал",
    factors: {
        budget: {
            title: "💰 Бюджет",
            score: "Бал",
            value: "Сума",
            range: "Діапазон",
            mentioned: "Згадування",
            confidence: "Впевненість",
            yes: "Так",
            no: "Ні"
        },
        authority: {
            title: "👤 Повноваження",
            score: "Бал",
            role: "Роль",
            level: "Рівень",
            position: "Посада",
            confidence: "Впевненість",
            roles: {
                decision_maker: "Особа, що приймає рішення",
                influencer: "Впливова особа",
                gatekeeper: "Контролююча особа",
                user: "Користувач",
                unknown: "Невідомо"
            },
            levels: {
                c_level: "C-рівень керівник",
                executive: "Керівник",
                manager: "Менеджер",
                user: "Користувач",
                specialist: "Спеціаліст",
                unknown: "Невідомо"
            }
        },
        need: {
            title: "🎯 Потреба",
            score: "Бал",
            severity: "Критичність",
            painPoints: "Больові точки",
            confidence: "Впевненість",
            severityLevels: {
                critical: "Критична",
                high: "Висока",
                medium: "Середня",
                low: "Низька"
            }
        },
        timeline: {
            title: "⏰ Терміни",
            score: "Бал",
            urgency: "Термiновість",
            deadline: "Дедлайн",
            confidence: "Впевненість",
            urgencyLevels: {
                immediate: "Негайно",
                this_week: "Цього тижня",
                this_month: "Цього місяця",
                this_quarter: "Цього кварталу",
                short_term: "Короткий термін",
                medium_term: "Середній термін",
                long_term: "Довгий термін",
                later: "Пізніше",
                undefined: "Не визначено"
            }
        }
    },
    reasoning: "Обґрунтування",
    description: "Опис",
    confidence: "Впевненість"
},

// Тестовий лід
testLead: {
    title: "🧪 Тестовий лід від системи моніторингу",
    name: "Тест",
    comments: "Це тестовий лід для перевірки інтеграції. Створено: {date}",
    testSuccess: "Підключення до CRM успішне! Тестовий лід створено.",
    specifyWebhook: "Вкажіть Webhook URL",
    testing: "Тестування...",
    connectionError: "Помилка підключення до CRM"
},

// Статуси CRM
crmStatuses: {
    loading: "Завантажено статуси CRM: {count}",
    loadError: "Помилка завантаження статусів CRM"
},

// Налаштування CRM в модальному вікні
crmSettings: {
    loaded: "Налаштування CRM завантажено",
    saveError: "Помилка збереження налаштувань CRM",
    specifyUrl: "Вкажіть Webhook URL для CRM",
    urlMustContain: "Webhook URL має бути коректним",
    testResultSuccess: "Успішно! ID ліда: {id}",
    testResultError: "Помилка: {error}"
},

// CRM інтеграція
crm: {
    title: "Налаштування інтеграції з CRM",
    webhookUrl: "Webhook URL для CRM:",
    webhookHint: "Отримайте webhook URL в налаштуваннях вашої CRM системи",
    autoSend: "Автоматична відправка гарячих лідів:",
    autoSendHint: "Автоматично відправляти в CRM ліди з Lead Score ≥ мінімального значення",
    minScore: "Мінімальний Lead Score для автовідправки:",
    scoreRange: "(50-100)",
    testConnection: "Тест підключення",
    sendButton: "Відправити в CRM",
    sentButton: "Відправлено в CRM"
    },
    
    crmConfirm: {
    title: "Підтвердіть дію",
    confirmMessage: "Відправити {temperature} лід (Score: {score}) в CRM?",
    cancelButton: "Скасувати",
    sendButton: "Відправити"
},

    
  emailMonitoring: {
    tabs: {
        messengers: "Користувачі месенджерів",
        email: "Email листування"
    },
    table: {
        columns: {
            email: "Email",
            name: "Ім'я",
            subject: "Тема",
            status: "Статус",
            leadScore: "Lead Score",
            satisfaction: "Задоволеність",
            messages: "Повідомлень",
            lastActivity: "Остання активність",
            actions: "Дії"
        },
        status: {
            new: "📥 Нове",
            unread: "🔵 Непрочитане",
            waiting: "⏳ Очікує відповіді",
            conversation: "💬 Листування",
            inactive: "💤 Неактивне"
        },
        actions: {
            viewDialog: "Діалог",
            viewAnalysis: "Результат",
            extractContacts: "Оновити контакти",
            runAnalysis: "Аналіз",
            deleteRecord: "Видалити"
        },
        noData: "Немає даних для відображення",
        loading: "Завантаження даних email..."
    }
   }
  }
};

// ===============================================
// ФУНКЦИИ РАБОТЫ С КОНФИГУРАЦИЕЙ
// ===============================================
const MonitoringConfigManager = {
    // Получить текущий язык
    getLanguage() {
        return MonitoringConfig.language || 'ru';
    },
    
    // Установить язык
    setLanguage(lang) {
        if (MonitoringTranslations[lang]) {
            MonitoringConfig.language = lang;
            console.log('✅ Язык изменен на:', lang);
            return true;
        }
        console.error('❌ Неподдерживаемый язык:', lang);
        return false;
    },
    
    // Получить перевод
    getTranslation(path) {
        const lang = this.getLanguage();
        const translations = MonitoringTranslations[lang] || MonitoringTranslations.ru;
        
        // Разбираем путь и получаем значение
        const keys = path.split('.');
        let result = translations;
        
        for (const key of keys) {
            result = result[key];
            if (!result) {
                console.warn('⚠️ Перевод не найден:', path, 'для языка:', lang);
                return path;
            }
        }
        
        return result;
    },
    
    // Получить доступные конфигурации
    getEnabledConfigurations() {
        const enabled = {};
        Object.keys(MonitoringConfig.availableConfigurations).forEach(key => {
            const config = MonitoringConfig.availableConfigurations[key];
            if (config.enabled) {
                enabled[key] = config;
            }
        });
        return enabled;
    },
    
    // Получить доступные платформы
    getEnabledPlatforms() {
        const enabled = {};
        Object.keys(MonitoringConfig.availablePlatforms).forEach(key => {
            const platform = MonitoringConfig.availablePlatforms[key];
            if (platform.enabled) {
                enabled[key] = platform;
            }
        });
        return enabled;
    },
    
    // Проверить видимость элемента
    isVisible(section, element) {
        return MonitoringConfig.display[section] && MonitoringConfig.display[section][element];
    },
    
    // Получить настройки отображения
    getDisplaySettings() {
        return MonitoringConfig.display;
    },
    
    // Получить технические настройки
    getTechnicalSettings() {
        return MonitoringConfig.technical;
    },
    
    // Экспорт конфигурации
    exportConfig() {
        return JSON.stringify(MonitoringConfig, null, 2);
    },
    
    // Импорт конфигурации
    importConfig(configString) {
        try {
            const newConfig = JSON.parse(configString);
            Object.assign(MonitoringConfig, newConfig);
            console.log('✅ Конфигурация импортирована');
            return true;
        } catch (error) {
            console.error('❌ Ошибка импорта конфигурации:', error);
            return false;
        }
    }
};

// Экспорт в глобальную область
window.MonitoringConfig = MonitoringConfig;
window.MonitoringTranslations = MonitoringTranslations;
window.MonitoringConfigManager = MonitoringConfigManager;

console.log('✅ Конфигурация мониторинга загружена. Язык:', MonitoringConfig.language);