package DisableSecurityManager;

import java.io.Serializable;
import java.security.AccessController;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;

public class DefaultFakeClassLoader implements PrivilegedExceptionAction<Integer>, Serializable {
  public DefaultFakeClassLoader() throws PrivilegedActionException {
    AccessController.doPrivileged(this);
  }

  public Integer run() {
    System.setSecurityManager(null);
    return 10;
  }
}
