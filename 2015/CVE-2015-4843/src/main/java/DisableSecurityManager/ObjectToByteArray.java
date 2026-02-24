package DisableSecurityManager;

import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;

public class ObjectToByteArray {
  public static byte[] toByteArray(Object obj) throws Exception {
    ByteArrayOutputStream bos = new ByteArrayOutputStream();
    ObjectOutputStream oos = new ObjectOutputStream(bos);
    oos.writeObject(obj);
    oos.flush();
    byte [] data = bos.toByteArray();
    return data;
  }
}