# CVE-2024-22514: Remote Code Execution in Agent DVR

## Information

### Description
iSpyConnect.com Agent DVR 5.1.6.0 contains a vulnerability which allows the file triggered by alert commands to be redirected. The modification can allow the commands function to trigger any file on the system under the permissions context of the program (root by default). This is done by editing the EXE param path in the objects.xml backup file, to create a modified objects.xml file, which can then be restored to through the dashboard. The restored dashboard will retain the new path placed in the objects.xml file which can then be triggered by alert commands.

### Additional Information
This attack may be chained with an additional CVE I will submit which includes an arbitrary file upload vulnerability. By chaining these two together, any arbitrary file may be uploaded and executed remotely by an authenticated user.

### Affected Versions
- **Versions Affected:** 5.1.6.0 (Other versions may also be impacted)

### Fixed Version
- **Version Fixed:** 5.1.7.0

### Researcher
- **Identified by:** Dylan W. Como

### Disclosure
- **Disclosure Link:** [GitHub Repository](https://github.com/Orange-418/AgentDVR-5.1.6.0-File-Upload-and-Remote-Code-Execution)

### References
- **NIST CVE Link:** [NVD - CVE-2024-22514](https://nvd.nist.gov/vuln/detail/CVE-2024-22514)

## Proof-of-Concept Exploit
For detailed technical insights or to replicate the security findings in a controlled environment, refer to the proof-of-concept exploit available at:

- [GitHub PoC Repository](https://github.com/Orange-418/AgentDVR-5.1.6.0-File-Upload-and-Remote-Code-Execution)
