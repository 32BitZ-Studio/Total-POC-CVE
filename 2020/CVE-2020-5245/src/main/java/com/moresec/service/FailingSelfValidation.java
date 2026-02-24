package com.moresec.service;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.dropwizard.validation.selfvalidating.SelfValidating;
import io.dropwizard.validation.selfvalidating.SelfValidation;
import io.dropwizard.validation.selfvalidating.ViolationCollector;

import javax.annotation.Nullable;
import javax.validation.constraints.NotNull;
import javax.ws.rs.QueryParam;


@SelfValidating
public class FailingSelfValidation {

    @Nullable
    @JsonProperty
    private String answer;

    public  FailingSelfValidation() { }

    public  FailingSelfValidation(@NotNull @QueryParam("answer") String answer) {
        this.answer = answer;
    }


    @SelfValidation
    public void validate(ViolationCollector collector) {
            collector.addViolation("The answer is" + this.answer);
    }

}