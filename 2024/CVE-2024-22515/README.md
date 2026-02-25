# CVE-2024-22515: File Upload Vulnerability in Agent DVR

## Information

### Description
In iSpyConnect.com Agent DVR 5.1.6.0, there is a lack of verification of file type for sound file uploads. This allows an authenticated user to upload any file type through the upload audio component simply by toggling to all files in the file open dialog.

### Additional Information
This vulnerability may be chained with my previously submitted exploit, allowing both arbitrary file upload, and arbitrary file execution.

### Affected Versions
- **Versions Affected:** 5.1.6.0 (Note: Other versions may also be impacted)

### Fixed Version
- **Version Fixed:** 5.1.7.0

### Researcher
- **Researcher:** Dylan W. Como

### Disclosure
- **Disclosure Link:** [GitHub Repository](https://github.com/Orange-418/AgentDVR-5.1.6.0-File-Upload-and-Remote-Code-Execution)

### References
- **NIST CVE Link:** [NVD - CVE-2024-22515](https://nvd.nist.gov/vuln/detail/CVE-2024-22515)

## Proof-of-Concept Exploit
For those interested in understanding the technical details or replicating the security findings under controlled conditions, the proof-of-concept exploit is available at the following link:

- [GitHub PoC Repository](https://github.com/Orange-418/AgentDVR-5.1.6.0-File-Upload-and-Remote-Code-Execution)
