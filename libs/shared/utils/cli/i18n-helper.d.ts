/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * CLI i18n Helper
 *
 * Provides translation functions for CLI messages
 */
import { Language, translations } from '../../../../libs/core/domain/reporting/i18n';
/**
 * Get user's preferred language from:
 * 1. Environment variable MCP_VERIFY_LANG
 * 2. Config file (~/.mcp-verify/config.json)
 * 3. System locale
 * 4. Default to 'en'
 */
export declare function detectLanguage(): Language;
/**
 * Initialize language (call once at startup)
 */
export declare function initLanguage(): Language;
/**
 * Get current language
 */
export declare function getCurrentLanguage(): Language;
/**
 * Set language manually
 */
export declare function setLanguage(lang: Language): void;
/**
 * Translate a key with optional parameters
 * Usage: t('welcome_user', { name: 'Fink' }) -> "Welcome, Fink!"
 */
export declare function t(key: keyof typeof translations.en, params?: Record<string, string | number>): string;
/**
 * Save language preference to config
 */
export declare function saveLanguagePreference(lang: Language): void;
//# sourceMappingURL=i18n-helper.d.ts.map