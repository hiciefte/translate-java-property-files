# Adding New Locales to the Translation System

This guide provides step-by-step instructions for adding support for a new language to the translation system.

## Overview

Adding a new locale involves updating configuration files, adding translation glossary entries, and verifying the integration. The process typically takes 15-30 minutes and requires no code changes.

## Prerequisites

- Access to the project repository
- Basic understanding of YAML and JSON formats
- Knowledge of the target language (or access to a native speaker for glossary translations)
- ISO 639-1 language code for the new locale (e.g., `th` for Thai, `de` for German)

## Step-by-Step Guide

### Step 1: Determine the Locale Code

Choose the appropriate ISO 639-1 language code for your new locale:

- **Simple codes**: 2-letter codes for most languages (e.g., `de` for German, `th` for Thai)
- **Region-specific codes**: Use underscore or hyphen for regional variants:
  - `pt_PT` for European Portuguese
  - `pt_BR` for Brazilian Portuguese
  - `zh-Hans` for Simplified Chinese
  - `zh-Hant` for Traditional Chinese

**Supported formats:**
- `xx` - Two lowercase letters (e.g., `de`, `fr`, `es`)
- `xx_YY` - Language with underscore and uppercase region (e.g., `pt_BR`, `af_ZA`)
- `xx-Yyyy` - Language with hyphen and mixed-case script/region (e.g., `zh-Hans`, `zh-Hant`)

### Step 2: Update Configuration Files

#### 2.1. Update `docker/config.docker.yaml`

This is the primary configuration file used by the Docker-based translation service.

1. Open `docker/config.docker.yaml`

2. Add your new locale to the `supported_locales` list. Position it logically (e.g., group Asian languages together, European languages together):

```yaml
supported_locales:
  # ... existing locales ...
  - code: "ta"
    name: "Tamil"
  - code: "th"          # ← New locale
    name: "Thai"        # ← Display name
  - code: "pcm"
    name: "Nigerian Pidgin"
  # ... more locales ...
```

3. Add language-specific style rules in the `style_rules` section. These rules guide the AI translator to produce high-quality translations:

```yaml
style_rules:
  # ... existing rules ...
  th:
    - "Use Thai script throughout."
    - "Maintain formal and polite tone appropriate for financial applications."
    - "Use polite particles (ครับ/ค่ะ) where appropriate for user interactions."
    - "Technical crypto terms may be transliterated when no established Thai term exists."
    - "Ensure consistent transliteration of technical terms across the application."
  # ... more rules ...
```

**Style Rule Guidelines:**
- **Script/Writing System**: Specify which script to use (e.g., "Use Devanagari script throughout" for Hindi)
- **Formality Level**: Define appropriate tone (formal, polite, casual) based on the application context
- **Cultural Considerations**: Include language-specific politeness markers or cultural norms
- **Technical Terms**: Guidance on transliteration vs. translation of technical/crypto terminology
- **Consistency**: Rules to ensure consistent terminology across the application

**Examples from other languages:**
- Hindi: "Use formal pronouns (आप) rather than informal (तुम/तू)"
- German: "Use the formal 'Sie' form of address"
- Spanish: "When referring to 'billetera' (wallet), use feminine pronouns"
- Chinese: "Use Chinese punctuation marks (。，、；：？！) rather than Western punctuation"

#### 2.2. Update `config.yaml` (Local Development)

If you're using local development (not Docker), also update `config.yaml` with the same changes:

```yaml
supported_locales:
  - code: "th"
    name: "Thai"

style_rules:
  th:
    - "Use Thai script throughout."
    # ... same rules as above ...
```

**Note:** `config.yaml` is typically gitignored for security reasons. Update it manually on your local machine.

### Step 3: Add Glossary Translations

The glossary ensures consistent translation of key terminology across all translations.

1. Open `glossary.json`

2. Add a new section for your locale with translations for common terms. Place it in alphabetical order by language code:

```json
{
  "ta": {
    "account": "கணக்கு",
    "wallet": "பணப்பை",
    // ... Tamil translations ...
  },
  "th": {
    "account": "บัญชี",
    "account_age": "อายุบัญชี",
    "arbitrator": "ผู้ชี้ขาด",
    "backup seed words": "สำรองคำกุญแจ",
    "backup seeds": "สำรองข้อมูลคำกุญแจ",
    "balance": "ยอดคงเหลือ",
    "bonded_bsq": "BSQ ที่ผูกพัน",
    "burned_bsq": "BSQ ที่เผาทำลาย",
    "chat_leave": "ออกจากแชท",
    "commit_hash": "แฮชคอมมิต",
    "community": "ชุมชน",
    "confirmations": "การยืนยัน",
    "content": "เนื้อหา",
    "fee": "ค่าธรรมเนียม",
    "guide": "คู่มือ",
    "initialize": "เริ่มต้น",
    "learn_more": "เรียนรู้เพิ่มเติม",
    "moderator": "ผู้ดูแล",
    "offer_accepted": "ข้อเสนอได้รับการยอมรับ",
    "overview": "ภาพรวม",
    "profile": "โปรไฟล์",
    "receive": "รับ",
    "reputation": "ชื่อเสียง",
    "seed phrase": "คำกุญแจ",
    "send": "ส่ง",
    "trade": "การซื้อขาย",
    "transaction_id": "รหัสธุรกรรม",
    "wallet": "กระเป๋าเงิน"
  },
  "hi": {
    "account": "खाता",
    // ... Hindi translations ...
  }
}
```

**Glossary Guidelines:**
- Translate approximately 40-60 common terms
- Include key domain-specific terminology (crypto, wallet, trading terms)
- Maintain consistency with other languages (same set of English keys)
- For technical terms without established translations, consider keeping them in English or providing transliterations
- Validate JSON syntax after adding entries

**Common terms to include:**
- Financial: account, balance, fee, transaction, payment
- Trading: trade, offer, buyer, seller, market
- Crypto-specific: wallet, seed phrase, confirmations, blockchain terms
- UI elements: profile, settings, overview, guide, send, receive
- Actions: initialize, verify, confirm, cancel, delete
- Roles: moderator, mediator, arbitrator

### Step 4: Validate Your Changes

#### 4.1. Validate JSON Syntax

Ensure `glossary.json` is valid JSON:

```bash
python -m json.tool glossary.json > /dev/null && echo "JSON is valid"
```

#### 4.2. Run Unit Tests

Verify that the configuration loads correctly:

```bash
# Activate virtual environment
source venv/bin/activate

# Run tests
python -m pytest tests/unit/test_app_config.py -v
```

All tests should pass, confirming that:
- The new locale is recognized
- Configuration loads without errors
- Language mappings are created correctly

#### 4.3. Verify Integration

Test that your new locale is properly integrated:

```bash
python -c "
from src.app_config import load_app_config
config = load_app_config()

# Check if locale is recognized
locale_code = 'th'  # Replace with your locale code
print(f'Locale present: {locale_code in config.language_codes}')
print(f'Language name: {config.language_codes.get(locale_code)}')
print(f'Name-to-code mapping: {config.name_to_code.get(\"thai\")}')  # Replace with your language name
print(f'Style rules present: {locale_code in config.precomputed_style_rules_text}')
"
```

Expected output:
```
Locale present: True
Language name: Thai
Name-to-code mapping: th
Style rules present: True
```

### Step 5: Test Translation Pipeline

#### 5.1. Create Test Files

For a complete end-to-end test, you can create sample `.properties` files:

```bash
# In the target project's i18n folder
cd /path/to/bisq2/i18n/src/main/resources

# Create a test file with your new locale code
echo "test.key=Test value" > test_th.properties
```

#### 5.2. Run Translation (Dry Run)

Test the translation pipeline in dry-run mode:

```bash
# Update docker/config.docker.yaml temporarily
# Set: dry_run: true

# Run the translator
docker compose run --rm translator
```

Verify in the logs that:
- Your new locale files are detected
- Glossary terms are loaded
- Style rules are applied
- No validation errors occur

### Step 6: Commit Your Changes

Once verified, commit your changes:

```bash
git add docker/config.docker.yaml glossary.json
git commit -m "Add [Language Name] ([code]) as a new supported locale

Added [Language] language support with comprehensive configuration.

Changes:
- Added locale (code: '[code]', name: '[Language]') to supported_locales
- Added [N] style rules for [language-specific considerations]
- Added [N] glossary translations for common terms

All tests pass and locale is fully integrated."
```

## Reference: Real-World Example

Here's the complete commit that added Thai language support, which you can use as a reference:

**Commit: `db38f90ce`** - "Add Thai (th) as a new supported locale"

### Configuration Changes

**`docker/config.docker.yaml`:**
```yaml
supported_locales:
  - code: "th"
    name: "Thai"

style_rules:
  th:
    - "Use Thai script throughout."
    - "Maintain formal and polite tone appropriate for financial applications."
    - "Use polite particles (ครับ/ค่ะ) where appropriate for user interactions."
    - "Technical crypto terms may be transliterated when no established Thai term exists."
    - "Ensure consistent transliteration of technical terms across the application."
```

### Glossary Entries

57 Thai translations were added to `glossary.json`, including:
- `"wallet": "กระเป๋าเงิน"`
- `"account": "บัญชี"`
- `"trade": "การซื้อขาย"`
- `"seed phrase": "คำกุญแจ"`
- `"reputation": "ชื่อเสียง"`

## Troubleshooting

### Common Issues

#### Issue: Configuration doesn't load
**Symptoms:** Error when running tests or translation pipeline
**Solution:**
- Verify YAML indentation is correct (use spaces, not tabs)
- Ensure locale code follows supported format
- Check that all required fields are present (code, name)

#### Issue: JSON validation fails
**Symptoms:** `python -m json.tool glossary.json` reports errors
**Solution:**
- Check for missing commas between entries
- Ensure proper quote escaping in translations
- Verify the JSON structure matches existing entries
- Use a JSON validator or IDE with JSON support

#### Issue: Locale not detected
**Symptoms:** Translation pipeline doesn't recognize new locale files
**Solution:**
- Verify locale code format matches regex: `_[a-z]{2,3}(?:[-_][A-Za-z]{2,4})?\.properties$`
- Check that files are named correctly (e.g., `default_th.properties`)
- Ensure the locale is in the `supported_locales` list

#### Issue: Style rules not applied
**Symptoms:** AI translations don't follow specified guidelines
**Solution:**
- Verify style rules are under the correct locale code in the YAML
- Check indentation matches other locale rules
- Ensure rules are clear and specific
- Test with verbose logging enabled to see what's being sent to the AI

### Getting Help

If you encounter issues:

1. Check existing locale configurations for reference
2. Review test output for specific error messages
3. Validate YAML and JSON syntax using online validators
4. Consult the project's main README.md for general troubleshooting
5. Check the `docs/` directory for additional documentation

## Supported Locale Formats

The system recognizes the following locale code patterns in filenames:

| Pattern | Example | Description |
|---------|---------|-------------|
| `_xx` | `_de.properties` | Simple 2-letter code |
| `_xxx` | `_pcm.properties` | 3-letter code (rare) |
| `_xx_YY` | `_pt_BR.properties` | Language + region (uppercase) |
| `_xx-Yyyy` | `_zh-Hans.properties` | Language + script/region (mixed case) |
| `_xx_Yyyy` | `_af_ZA.properties` | Alternative underscore format |

**Regex pattern:** `_[a-z]{2,3}(?:[-_][A-Za-z]{2,4})?\.properties$`

## Best Practices

### Style Rules
- Keep rules concise and actionable (5-7 rules per language)
- Focus on aspects the AI can control (tone, script, terminology)
- Include cultural context that affects translation choices
- Reference similar languages as examples when creating new rules

### Glossary Translations
- Aim for 40-60 key terms minimum
- Prioritize domain-specific terminology over common words
- Consult native speakers for accuracy and naturalness
- Maintain consistency with existing translations in the target language
- Document any non-standard transliterations or choices

### Testing
- Always run the full test suite before committing
- Test with actual `.properties` files when possible
- Verify both detection and translation of new locale files
- Check that glossary terms are correctly substituted in translations

### Documentation
- Update this guide if you discover edge cases or improvements
- Document any language-specific quirks or considerations
- Share learnings with the team for future locale additions

## Appendix: Complete Checklist

Use this checklist when adding a new locale:

- [ ] Determined correct ISO 639-1 language code
- [ ] Updated `docker/config.docker.yaml`:
  - [ ] Added locale to `supported_locales`
  - [ ] Added comprehensive style rules
- [ ] Updated `config.yaml` (if using local development)
- [ ] Updated `glossary.json`:
  - [ ] Added 40-60 common terms
  - [ ] Included domain-specific terminology
  - [ ] Validated JSON syntax
- [ ] Tested configuration:
  - [ ] JSON validation passed
  - [ ] Unit tests passed (45/45)
  - [ ] Integration verification completed
- [ ] Tested translation pipeline:
  - [ ] Created test `.properties` files
  - [ ] Ran dry-run translation
  - [ ] Verified locale detection
  - [ ] Checked glossary application
- [ ] Committed changes with descriptive message
- [ ] Documented any language-specific considerations

## See Also

- [Main README](../README.md) - Project overview and setup
- [New Project Deployment](./new-project-deployment.md) - Server deployment guide
- [Repository Structure](./repository-structure.md) - Project organization
- [Configuration Reference](../docker/config.docker.yaml) - All configuration options
