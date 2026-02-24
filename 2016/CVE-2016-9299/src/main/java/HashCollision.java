/**
 * @Author: r00t4dm
 * @Date: 2022/1/10 7:11 下午
 */
public class HashCollision {
    public static String convert(String str) {
        str = (str == null ? "" : str);
        String tmp;
        StringBuffer sb = new StringBuffer(1000);
        char c;
        int i, j;
        sb.setLength(0);
        for (i = 0; i < str.length(); i++) {
            c = str.charAt(i);
            sb.append("\\u");
            j = (c >>> 8); // 取出高8位
            tmp = Integer.toHexString(j);
            if (tmp.length() == 1)
                sb.append("0");
            sb.append(tmp);
            j = (c & 0xFF); // 取出低8位
            tmp = Integer.toHexString(j);
            if (tmp.length() == 1)
                sb.append("0");
            sb.append(tmp);
        }
        return (new String(sb));
    }
    public static String string2Unicode(String string) {
        StringBuffer unicode = new StringBuffer();
        for (int i = 0; i < string.length(); i++) {
            // 取出每一个字符
            char c = string.charAt(i);
            // 转换为unicode
            unicode.append("\\u" + Integer.toHexString(c));
        }
        return unicode.toString();
    }
    /**
     * Returns a string with a hash equal to the argument.
     *
     * @return string with a hash equal to the argument.
     * @author - Joseph Darcy
     */
    public static String unhash(int target) {
        StringBuilder answer = new StringBuilder();
        if (target < 0) {
            // String with hash of Integer.MIN_VALUE, 0x80000000
            answer.append("\u0915\u0009\u001e\u000c\u0002");
            if (target == Integer.MIN_VALUE)
                return answer.toString();
            // Find target without sign bit set
            target = target & Integer.MAX_VALUE;
        }
        unhash0(answer, target);
        return answer.toString();
    }
    /**
     *
     * @author - Joseph Darcy
     */
    private static void unhash0(StringBuilder partial, int target) {
        int div = target / 31;
        int rem = target % 31;
        if (div <= Character.MAX_VALUE) {
            if (div != 0)
                partial.append((char) div);
            partial.append((char) rem);
        } else {
            unhash0(partial, div);
            partial.append((char) rem);
        }
    }
    public static void main(String[] args) {
        System.out.println(convert(unhash(877174790)));
        System.out.println("".hashCode());
    }
}
