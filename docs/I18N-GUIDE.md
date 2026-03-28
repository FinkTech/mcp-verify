# 🌍 Internationalization (i18n) Guide

## Overview

MCP Verify now supports **multiple languages** (English and Spanish) with an extensible i18n system.

---

## 🎯 Current Status

### ✅ What's Translated

**HTML Reports:**
- All UI text (headers, labels, buttons)
- Status messages
- Table headers

**CLI Interface:**
- Welcome banner
- Interactive shell title
- Command descriptions
- (Ready to expand to all messages)

### 📍 Current Languages

- **English (en)** - Default
- **Español (es)** - Complete

---

## 🚀 Quick Start

### For Users

#### Check Current Language
```bash
# Start interactive mode
mcp-verify

# You'll see:
Language:   EN (type "lang" to change)
```

#### Change Language
```bash
# In interactive mode
mcp-verify> lang

# Or directly
mcp-verify> language
```

You'll see:
```
🌍 Language / Idioma

Current / Actual: English (en)

Available languages / Idiomas disponibles:
  1. ✓ English (en)
  2.   Español (es)

Select / Selecciona (1-2): 2

✓ Idioma cambiado a Español
```

#### Set via Environment Variable
```bash
# English
export MCP_VERIFY_LANG=en
mcp-verify

# Spanish
export MCP_VERIFY_LANG=es
mcp-verify
```

#### Persisted Setting
Language preference is saved to: `~/.mcp-verify/config.json`

---

## 👩‍💻 For Developers

### Architecture

```
libs/
├── core/domain/reporting/
│   └── i18n.ts                    # Translation dictionary
└── shared/utils/cli/
    └── i18n-helper.ts             # Helper functions
```

### Adding New Translations

#### 1. Add to Dictionary

Edit `libs/core/domain/reporting/i18n.ts`:

```typescript
export const translations = {
  en: {
    // ... existing
    my_new_message: 'Hello World',
  },
  es: {
    // ... existing
    my_new_message: 'Hola Mundo',
  }
};
```

#### 2. Use in Code

```typescript
import { t } from '../../../../libs/shared/utils/cli/i18n-helper';

// Instead of:
console.log('Hello World');

// Use:
console.log(t('my_new_message'));
```

### Helper Functions

```typescript
import {
  initLanguage,       // Initialize (call once at startup)
  getCurrentLanguage, // Get current language
  setLanguage,        // Change language
  saveLanguagePreference, // Save to config
  t                   // Translate key
} from '../../../../libs/shared/utils/cli/i18n-helper';

// Initialize (already done in index.ts)
initLanguage();

// Get current
const lang = getCurrentLanguage(); // 'en' or 'es'

// Translate
const message = t('welcome_title');

// Change
setLanguage('es');
saveLanguagePreference('es'); // Persist
```

### Language Detection Priority

1. **Environment variable** `MCP_VERIFY_LANG`
2. **Config file** `~/.mcp-verify/config.json`
3. **System locale** (via `Intl.DateTimeFormat`)
4. **Default** to English

---

## 📝 Translation Guidelines

### 1. Keep Keys Semantic
```typescript
// ✅ GOOD
cmd_validate: 'Run validation scan'
error_connection_failed: 'Connection Failed'

// ❌ BAD
text1: 'Run validation scan'
msg: 'Connection Failed'
```

### 2. Use Context Prefixes
```typescript
// Commands
cmd_validate, cmd_stress, cmd_help

// Errors
error_connection_failed, error_timeout

// Tips
tip_check_server, tip_verify_url

// Doctor
doctor_title, doctor_results
```

### 3. Maintain Parity
Every English key **must** have a Spanish equivalent (and vice versa).

```typescript
// ✅ GOOD - Both languages
en: { greeting: 'Hello' }
es: { greeting: 'Hola' }

// ❌ BAD - Missing Spanish
en: { greeting: 'Hello' }
es: { } // Missing!
```

### 4. Handle Plurals
```typescript
// Use functions when needed
tools: (count: number) => count === 1 ? 'tool' : 'tools'
herramientas: (count: number) => count === 1 ? 'herramienta' : 'herramientas'

// Or use separate keys
tool_singular: 'tool'
tool_plural: 'tools'
```

### 5. Interpolation
For dynamic values, use template strings:

```typescript
// In translations
server_found: 'Found server at'

// In code
console.log(t('server_found') + ' ' + url);
```

---

## 🔧 Current Implementation Status

### ✅ Translated
- Welcome banner
- Interactive shell title
- Command descriptions (in interactive mode)
- Language selector
- HTML report (fully translated)

### ✅ Fully Translated
All user-facing messages have been translated:
- ✅ Validation spinner messages
- ✅ Error messages with contextual tips
- ✅ Help command details
- ✅ Examples command output
- ✅ Doctor command diagnostics
- ✅ Mock server messages
- ✅ Proxy server messages
- ✅ Validator logger messages
- ✅ Stress test output
- ✅ Playground interface
- ✅ Interactive mode commands

---

## 🎯 How to Expand i18n

### Step-by-Step: Translate Validation Messages

**Current code (hardcoded English):**
```typescript
spinner.text = 'Testing protocol handshake...';
```

**Step 1:** Add to `i18n.ts`
```typescript
en: {
  // ... existing
  spinner_testing_handshake: 'Testing protocol handshake...',
}
es: {
  // ... existing
  spinner_testing_handshake: 'Probando handshake de protocolo...',
}
```

**Step 2:** Use `t()` in code
```typescript
import { t } from '../../../../libs/shared/utils/cli/i18n-helper';

spinner.text = t('spinner_testing_handshake');
```

**Step 3:** Build and test
```bash
npm run build

# Test in English
export MCP_VERIFY_LANG=en
npm run dev

# Test in Spanish
export MCP_VERIFY_LANG=es
npm run dev
```

---

## 🌐 Adding a New Language

Want to add Portuguese, French, or another language?

### 1. Update Type
```typescript
// i18n.ts
export type Language = 'en' | 'es' | 'pt' | 'fr';
```

### 2. Add Translations
```typescript
export const translations = {
  en: { /* ... */ },
  es: { /* ... */ },
  pt: {
    title: 'Relatório de Validação MCP',
    welcome_title: 'Validador Automatizado para Model Context Protocol',
    // ... all keys
  }
};
```

### 3. Update Language Selector
```typescript
// index.ts - in lang command
console.log('  1. English (en)');
console.log('  2. Español (es)');
console.log('  3. Português (pt)'); // New!
```

### 4. Add Detection
```typescript
// i18n-helper.ts
const locale = Intl.DateTimeFormat().resolvedOptions().locale;
if (locale.startsWith('es')) return 'es';
if (locale.startsWith('pt')) return 'pt'; // New!
```

---

## 🧪 Testing

### Manual Testing
```bash
# Test English
export MCP_VERIFY_LANG=en
npm run dev
> lang # Try changing language
> help # Check command descriptions

# Test Spanish
export MCP_VERIFY_LANG=es
npm run dev
> lang
> help
```

### Automated Testing (Future)
```typescript
describe('i18n', () => {
  it('should load English by default', () => {
    const lang = initLanguage();
    expect(lang).toBe('en');
  });

  it('should translate keys', () => {
    setLanguage('en');
    expect(t('welcome_title')).toBe('Automated Validator for Model Context Protocol');

    setLanguage('es');
    expect(t('welcome_title')).toBe('Validador Automatizado para Model Context Protocol');
  });
});
```

---

## 📊 Translation Coverage

| Component | English | Spanish | Status |
|-----------|---------|---------|--------|
| HTML Report | ✅ 100% | ✅ 100% | Complete |
| CLI Welcome | ✅ 100% | ✅ 100% | Complete |
| CLI Commands | ✅ 100% | ✅ 100% | Complete |
| Validation Messages | ✅ 100% | ✅ 100% | Complete |
| Error Messages | ✅ 100% | ✅ 100% | Complete |
| Stress Test Messages | ✅ 100% | ✅ 100% | Complete |
| Playground Messages | ✅ 100% | ✅ 100% | Complete |
| Proxy Messages | ✅ 100% | ✅ 100% | Complete |
| Doctor Diagnostics | ✅ 100% | ✅ 100% | Complete |
| Examples Command | ✅ 100% | ✅ 100% | Complete |
| Interactive Mode | ✅ 100% | ✅ 100% | Complete |
| Library Messages (Mock, Proxy, Validator) | ✅ 100% | ✅ 100% | Complete |

**Overall:** ✅ **100% translated**

---

## 🎨 Best Practices

### DO ✅
- Use semantic keys (`cmd_validate` not `text1`)
- Keep translations short and clear
- Test both languages after changes
- Maintain parity between languages
- Use `t()` for all user-facing text

### DON'T ❌
- Hardcode strings in multiple places
- Leave translation keys untranslated
- Break lines in the middle of sentences
- Use machine translation without review
- Forget to update both languages

---

## 🐛 Common Issues

### "Translation key not found"
**Cause:** Key doesn't exist in dictionary

**Solution:** Add it to `i18n.ts` in both `en` and `es`

### "Language not changing"
**Cause:** Config file has wrong permissions or language not saved

**Solution:**
```bash
# Check config
cat ~/.mcp-verify/config.json

# Manually set
echo '{"language":"es"}' > ~/.mcp-verify/config.json
```

### "Fallback to English"
**Cause:** Spanish translation missing

**Solution:** Automatic fallback is working! Add the Spanish translation.

---

## 📚 Resources

- [i18n Best Practices](https://www.i18next.com/principles/best-practices)
- [Internationalization Guidelines](https://www.w3.org/International/questions/qa-i18n)
- [JavaScript Intl API](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Intl)

---

## 🤝 Contributing Translations

Want to contribute translations?

1. Fork the repo
2. Add translations to `libs/core/domain/reporting/i18n.ts`
3. Test locally
4. Submit PR with:
   - Updated i18n.ts
   - Test results
   - Native speaker review (if possible)

**Translation PRs are highly welcome!** 🌍

---

**Status:** ✅ COMPLETE
**Last Updated:** 2026-01-20
**Milestone Achieved:** 100% English and Spanish translation coverage across entire codebase
