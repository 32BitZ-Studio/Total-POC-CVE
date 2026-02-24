## CVE-2019-10172 https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-10172
There is no known non-vulnerable version of this component/package. 
It is recommended to investigate alternative components or a potential mitigating control.


## Mitigation
1. (Desirable) Try to switch from usage of com.codehaus.jackson to com.fasterxml.jackson for all the cases and remove com.codehaus.jackson libs

2. Use the patched library: see https://github.com/FasterXML/jackson-1/blob/master/src/mapper/java/org/codehaus/jackson/map/ext/DOMDeserializer.java
https://github.com/FasterXML/jackson-1/blob/master/src/xc/java/org/codehaus/jackson/xc/DomElementJsonDeserializer.java
where _parserFactory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true) is set
