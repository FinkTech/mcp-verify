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
import * as os from 'os';
import * as fs from 'fs';
import * as path from 'path';

let currentLanguage: Language = 'en';

/**
 * Get user's preferred language from:
 * 1. Environment variable MCP_VERIFY_LANG
 * 2. Config file (~/.mcp-verify/config.json)
 * 3. System locale
 * 4. Default to 'en'
 */
export function detectLanguage(): Language {
  // 1. Check environment variable
  const envLang = process.env.MCP_VERIFY_LANG;
  if (envLang === 'es' || envLang === 'en') {
    return envLang;
  }

  // 2. Check config file
  try {
    const configDir = path.join(os.homedir(), '.mcp-verify');
    const configFile = path.join(configDir, 'config.json');
    if (fs.existsSync(configFile)) {
      const config = JSON.parse(fs.readFileSync(configFile, 'utf-8'));
      if (config.language === 'es' || config.language === 'en') {
        return config.language;
      }
    }
  } catch (e) {
    // Ignore config file errors
  }

  // 3. Check system locale
  const locale = Intl.DateTimeFormat().resolvedOptions().locale;
  if (locale.startsWith('es')) {
    return 'es';
  }

  // 4. Default to English
  return 'en';
}

/**
 * Initialize language (call once at startup)
 */
export function initLanguage(): Language {
  currentLanguage = detectLanguage();
  return currentLanguage;
}

/**
 * Get current language
 */
export function getCurrentLanguage(): Language {
  return currentLanguage;
}

/**
 * Set language manually
 */
export function setLanguage(lang: Language): void {
  currentLanguage = lang;
}

/**
 * Translate a key with optional parameters
 * Usage: t('welcome_user', { name: 'Fink' }) -> "Welcome, Fink!"
 */
export function t(key: keyof typeof translations.en, params?: Record<string, string | number>, lang?: Language): string {
  const targetLang = lang || currentLanguage;
  let translation = (translations[targetLang] as typeof translations.en)[key];
  if (!translation) {
    // Fallback to English if translation missing
    translation = translations.en[key] || key;
  }

  if (params) {
    Object.keys(params).forEach(param => {
      translation = translation.replace(new RegExp(`{${param}}`, 'g'), String(params[param]));
    });
  }

  return translation;
}

/**
 * Save language preference to config
 */
export function saveLanguagePreference(lang: Language): void {
  try {
    const configDir = path.join(os.homedir(), '.mcp-verify');
    const configFile = path.join(configDir, 'config.json');

    if (!fs.existsSync(configDir)) {
      fs.mkdirSync(configDir, { recursive: true });
    }

    let config: Record<string, unknown> = {};
    if (fs.existsSync(configFile)) {
      config = JSON.parse(fs.readFileSync(configFile, 'utf-8'));
    }

    config.language = lang;
    fs.writeFileSync(configFile, JSON.stringify(config, null, 2));
  } catch (e) {
    // Silently fail - not critical
  }
}
