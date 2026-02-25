package scabench;


import org.json.JSONObject;
import org.json.XML;

/**
 * Simple application -- read XML and converts it to JSON and
 * pretty-prints in to the console.
 * @author jens dietrich
 */
public class XML2JSONConverter {

    public static void main (String[] args)  {
        JSONObject json = XML.toJSONObject(args[0]);
        System.out.println(json.toString(4));
    }

}
