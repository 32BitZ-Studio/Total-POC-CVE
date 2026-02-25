# CVE-2023-4683-Test

This repo holds an easy to use POC for CVE-2023-4683. Just git clone this repo and either extract webp-test or run setup-webp-test.sh.

webp-test already has the necessary files (git commit 7ba44f80f3b94fc0138db159afea770ef06532a0 of https://chromium.googlesource.com/webm/libwebp/), and a specially crafted bad.webp and bad.webp.png files located in the webp_test/examples folder. It also has a non-crafted png file as well.

The setup-webp-test.sh will install webp's dependencies, download the vulnerable webp source code, compiles webp, downloads a POC injector to craft the bad file, and creates the file.

To use:  
cd webp_test/examples

# Tests OK. Output: Saved file: test.png
./dwebp test.webp -o test.png

# Test FAILS. Output: ==6475==ERROR: AddressSanitizer: heap-buffer-overflow on address...
./dwebp bad.webp -o test.png  
./dwebp bad.webp.png -o test.png

# What does this mean?
This means that servers are potentially vulnerable to this CVE. An attacker could upload a specially crafted file to a server, and this CVE will execute if that server processes the file, regardless of file extension, through libwebp.

# Special thanks
I would like to thank the following people:  
  
https://github.com/mistymntncop - https://github.com/mistymntncop/CVE-2023-4863 - Created the craft file that injects a file with the required data to test this POC  
Ben Hawkes - https://blog.isosceles.com/the-webp-0day/ - Detailed analysis of this CVE, plus wrote steps on how to set up the POC
