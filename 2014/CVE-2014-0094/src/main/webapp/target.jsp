<%@ page language="java" import="java.lang.reflect.*" %>
<%!
public void processClass(Object instance, javax.servlet.jsp.JspWriter out, java.util.HashSet set, String poc){
	try {
	    Class<?> c = instance.getClass();
	    set.add(instance);
	    Method[] allMethods = c.getMethods();
	    for (Method m : allMethods) {
		if (!m.getName().startsWith("set")) {
		    continue;
		}
		if (!m.toGenericString().startsWith("public")) {
		    continue;
		}
		Class<?>[] pType  = m.getParameterTypes();
		if(pType.length!=1) continue;
		
		if(pType[0].getName().equals("java.lang.String")||
		pType[0].getName().equals("boolean")||
		pType[0].getName().equals("int")){
			String fieldName = m.getName().substring(3,4).toLowerCase()+m.getName().substring(4);
			out.print(poc+"."+fieldName + "<br>");
		}
	    }
	    for (Method m : allMethods) {
		if (!m.getName().startsWith("get")) {
		    continue;
		}
		if (!m.toGenericString().startsWith("public")) {
		    continue;
		}		
		Class<?>[] pType  = m.getParameterTypes();
		if(pType.length!=0) continue;
		if(m.getReturnType() == Void.TYPE) continue;
		Object o = m.invoke(instance);
		if(o!=null)
		{
			if(set.contains(o)) continue;
			processClass(o,out, set, poc+"."+m.getName().substring(3,4).toLowerCase()+m.getName().substring(4));	
		} 
	    }
	} catch (java.io.IOException x) {
	    x.printStackTrace();
	} catch (java.lang.IllegalAccessException x) {
	    x.printStackTrace();
	} catch (java.lang.reflect.InvocationTargetException x) {
	    x.printStackTrace();
	} 	
}
%>
<%
java.util.HashSet set = new java.util.HashSet<Object>();
String poc = "class.classLoader";
     com.haselab.struts.action.HelloWorldAction action =
new  com.haselab.struts.action.HelloWorldAction();
processClass(action.getClass().getClassLoader(),out,set,poc);
%>