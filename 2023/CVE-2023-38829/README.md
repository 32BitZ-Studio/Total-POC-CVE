# CVE-2023-38829-NETIS-WF2409E

# NETIS SYSTEMS Router WF2409E Command Injection PoC

## Vulnerability Description:
The ping and traceroute functions of the NETIS SYSTEMS Router WF2409E (version V3.6.42541) are susceptible to command injection attacks. Malicious input can be crafted in the parameters of these functions through the Web admin management interface, allowing arbitrary commands to be executed with the privileges of the affected process.

## PoC Steps:

1. Identify the Target:
   - Ensure you have access to the NETIS SYSTEMS Router WF2409E (version V3.6.42541) Web admin management interface.

2. Open the Ping Function:
   - Log in to the router's web interface.
   - Navigate to the "Diagnostic Tools" section.
   - Select the "Ping" function.

3. Craft Malicious Input:
   - In the "Ping" function input field, inject a command. For example:
  ```
  ;ls /* -al|ps
  ```

4. Execute the Command:
   - Submit the crafted input.
   - Observe the output. If the directory listing of the router's filesystem is displayed, the command injection is successful.

5. Open the Traceroute Function:
   - Navigate back to the "Diagnostic Tools" section.
   - Select the "Traceroute" function.

6. Craft Malicious Input:
   - In the "Traceroute" function input field, inject a command. For example:
     ```
     | ls
     ```

7. Execute the Command:
   - Submit the crafted input.
   - Check if the output includes the result of the `ls` command. If so, the command injection is demonstrated.

[![Watch the video](https://img.youtube.com/vi/OFTjmFGjiVs/maxresdefault.jpg)](https://youtu.be/OFTjmFGjiVs)



## Notes:
- This PoC is for educational and responsible disclosure purposes only.
- Do not use this PoC on systems you don't have permission to test.
- Ensure you have proper authorization before attempting any security testing.
