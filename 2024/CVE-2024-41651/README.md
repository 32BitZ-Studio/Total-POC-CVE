# Blind SSRF to RCE Exploit - PrestaShop 8.1.7

This document outlines a Blind SSRF to RCE exploit on a fresh PrestaShop 8.1.7 docker installation.

## Prerequisites

- Ensure you have at least an outdated module installed, for example:
  - `ps_facetedsearch`
- Download the original package:
  - [Download ps_facetedsearch v3.16.1](https://api.prestashop-project.org/assets/modules/ps_facetedsearch/v3.16.1/ps_facetedsearch.zip)

## Steps to Reproduce

1. **Prepare the Malicious File:**
   - Download and unzip the original package.
   - Choose a suitable file and function to inject the malicious command.
   - Payload example: Create a file in the root directory (e.g., `pwn3ed_bayram.txt`). Note: Shells could also be popped.
    ![Payload](./1.png)
   - Repack the module and Host it.
    ![Repack](./2.png)
    ![Repack](./3.png)

2. **Upgrade the Module:**
   - Open the module manager in PrestaShop.
    ![Repack](./4.png)
    ![Repack](./5.png)

3. **Intercept and Modify the Request:**
   - Intercept the request
     ![Repack](./6.png)
   - Change the `source` parameter to point to the server hosting your malicious zip file.
     ![Repack](./7.png)
     ![Repack](./8.png)
     ![Repack](./9.png)

## Expected Results

- **Before Exploit:**
  - Filesystem as expected with no additional files.
    ![Repack](./10.png)

- **After Exploit:**
  - The file `pwn3ed_bayram.txt` is successfully created in the root directory.
    ![Repack](./11.png)

## Additional Notes

- Reverse shells could be obtained using similar methods.

