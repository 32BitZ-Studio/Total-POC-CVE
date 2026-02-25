# __CVE-2022-31901__
* Denial Of Services (DOS) in `Notepad++(x86)` in `8.4.3` and [before](#tested-versions).
# __Description__
*  Vulnerability triggering, via opening two specially crafted text files (````e.g. first.txt & second.txt````) as input to notepad++. 

As an illustrative example below, as of `11/07/2022`, latest version of Notepad++(x86) is 8.4.3 is used.
![Notepad](npp_images/NppVer.png)
# Proof of Concept -
* Open the two example input files first.txt & second.txt in Notepad++ in any order.
### Result :
![NotepadCrash](npp_images/01RuntimeCrash.png)
##  Visual Studio 2019 Dump Analysis
#
![NotepadCrash](npp_images/01ErrorPoint.png)

Here we can see the problem to parse these files in __ScintallComponent -> Editor.h -> Line number 690.__
#
## Root Cause Analysis
* When notepad++ opens any file it calls a function __notepad_plus::addHotSpot__ which creates heap memory with __new__ operator and stores the return address in __widetext__ variable 
  ```TCHAR *wideText = new TCHAR[endPos - startPos + 1];```.  Since it requests for large allocation, __new__ returns __bad_alloc__ which is not handled in notepad++ and results in DoS.

* So it can be said that, opening the two example files with Notepad++(x86) <= 8.4.3 is leading to Denial of Service.

#
## Tested Versions
The vulnerability is tested to work on following version:
* Notepad++ 8.3.2 32-bit
* Notepad++ 8.3.3 32-bit.
* Notepad++ 8.4.0 32-bit.
* Notepad++ 8.4.1 32-bit.
* Notepad++ 8.4.2 32-bit.
* Notepad++ 8.4.3 32-bit.

#
## Tested Environment
* Windows 11 - 22563.1000 64 bit
* Windows 10 - 10.0.19042.1586 64-bit
* Windows 10 - 10.0.19044.1706 64-bit

## Update
* As of 05-01-2023, this issue still persists in the `Notepad++ versions 8.4.8 (32-bit) and before`.
* As of 01-02-2023, this issue still persists in the `Notepad++ versions 8.4.9 (32-bit) and before`.
