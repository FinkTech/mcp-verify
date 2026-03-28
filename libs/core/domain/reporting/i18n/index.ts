/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * i18next Translation System
 *
 * Sistema limpio de traducciones usando i18next
 */

import i18next from 'i18next';

// Por ahora importamos el viejo sistema
import { translations as oldTranslations } from '../i18n.js';

export type Language = 'en' | 'es' | 'fr' | 'de' | 'pt' | 'it' | 'ja' | 'zh' | 'ko' | 'ru';

/**
 * Initialize i18next with translations
 */
export async function initI18n(defaultLang: Language = 'en'): Promise<void> {
  await i18next.init({
    lng: defaultLang,
    fallbackLng: 'en',
    resources: {
      en: {
        translation: oldTranslations.en || {}
      },
      es: {
        translation: oldTranslations.es || {}
      }
    },
    interpolation: {
      escapeValue: false // React already escapes
    }
  });
}

/**
 * Get translation
 */
export function t(key: string, options?: Record<string, unknown>): string {
  if (!i18next.isInitialized) {
    // Fallback si no está inicializado
    return key;
  }
  return i18next.t(key, options);
}

/**
 * Change language
 */
export function changeLanguage(lang: Language): Promise<any> {
  return i18next.changeLanguage(lang);
}

/**
 * Get current language
 */
export function getCurrentLanguage(): Language {
  return (i18next.language || 'en') as Language;
}

/**
 * Get available languages
 */
export function getAvailableLanguages(): Language[] {
  return ['en', 'es', 'fr', 'de', 'pt', 'it', 'ja', 'zh', 'ko', 'ru'];
}
