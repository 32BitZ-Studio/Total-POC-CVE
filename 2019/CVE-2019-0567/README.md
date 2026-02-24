# Chakra-CVE-2019-0567
A POC of a type confusion bug in chakracore framework that leads to code execute.  


Following from Connor McGar's blog https://connormcgarr.github.io/


NOTE: The Offsets and ROP gadgets depends on the Windows version you use, so it might not work for you. If you compare my code to Connor's POC, you will see that most of the offsets are different. That's because I had to find my own ROP gadgets!
