# VUPlayer 2.49 Local Buffer Overflow to Arbitrary Code Execution
Program Version: VUPlayer 2.49

Vulnerability: local buffer overflow when importing .wax playlist file that will lead to arbitrary code execution

Exploitation: Local Buffer Overflow

CVE: CVE-2009-0182

- VUPlayer2.49_poc.py            : without bypass DEP protection
- VUPlayer2.49_poc_bypassDEP.py  : bypass DEP protection using ROP Chain

PoC Video: https://youtu.be/HgD7gOgiIFE

Step-by-Step creating DEP bypass video: https://youtu.be/AsR8PFKK5Mw
