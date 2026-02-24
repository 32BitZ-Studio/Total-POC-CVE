package com.moresec;

import com.moresec.control.BookController;
import io.dropwizard.Application;
import io.dropwizard.setup.Bootstrap;
import io.dropwizard.setup.Environment;

import javax.validation.Validator;

public class testApplication extends Application<testConfiguration> {

    public static void main(final String[] args) throws Exception {
        new testApplication().run(args);
    }

    @Override
    public String getName() {
        return "test";
    }

    @Override
    public void initialize(final Bootstrap<testConfiguration> bootstrap) {
        // TODO: application initialization
    }

    @Override
    public void run(final testConfiguration configuration,
                    final Environment environment) {
        environment.jersey().register(new BookController());
        Validator validator = environment.getValidator();

        // TODO: implement application
    }

}
