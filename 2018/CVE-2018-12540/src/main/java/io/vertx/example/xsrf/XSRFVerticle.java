package io.vertx.example.xsrf;


import io.vertx.rxjava.core.AbstractVerticle;
import io.vertx.rxjava.core.MultiMap;
import io.vertx.rxjava.ext.web.Router;
import io.vertx.rxjava.ext.web.RoutingContext;
import io.vertx.rxjava.ext.web.handler.BodyHandler;
import io.vertx.rxjava.ext.web.handler.CSRFHandler;
import io.vertx.rxjava.ext.web.handler.CookieHandler;
import io.vertx.rxjava.ext.web.handler.SessionHandler;
import io.vertx.rxjava.ext.web.sstore.ClusteredSessionStore;
import io.vertx.rxjava.ext.web.sstore.SessionStore;


import java.util.UUID;
import java.util.logging.Logger;

public class XSRFVerticle extends AbstractVerticle {
    private static final Logger log = Logger.getLogger(XSRFVerticle.class.getName());

    @Override
    public void start() {
        Router router = Router.router(vertx);
        SessionStore sessionStore = ClusteredSessionStore.create(vertx);
        SessionHandler sessionHandler = SessionHandler.create(sessionStore);
        router.route().handler(BodyHandler.create());
        router.route().handler(CookieHandler.create());
        router.route().handler(sessionHandler);
        router.route("/token").handler(CSRFHandler.create(UUID.randomUUID().toString()));
        router.get().handler(this::handleGet);
        router.post("/token").handler(this::handlePost);

        vertx.createHttpServer().requestHandler(router::accept).listen(8888);
    }

    private void handleGet(RoutingContext routingContext){
        log.warning("Handling GET");
        routingContext.response().end("Success!");
    }

    private void handlePost(RoutingContext routingContext){
        log.warning("Handling POST");
        routingContext.response().end("Success!");
    }
}