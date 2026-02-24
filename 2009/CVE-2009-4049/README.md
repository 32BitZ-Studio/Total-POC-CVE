# CVE-2009-4049
 Heap-based buffer overflow in aswRdr.sys (aka the TDI RDR driver) in avast! Home and Professional 4.8.1356.0 allows local users to cause a denial of service (memory corruption) or possibly gain privileges via crafted arguments to IOCTL 0x80002024.

 While part of the reason as to why I did not finish this vulnerability is out of sheer laziness, it did not appear exploitable on the surface. It can achieve a local denial of service condition, but it does not appear that I can control the contents of memory. The only factor that can be controlled, from my tests, is the string scan loop iterations. No data appears to be passed to the output buffer, either.
