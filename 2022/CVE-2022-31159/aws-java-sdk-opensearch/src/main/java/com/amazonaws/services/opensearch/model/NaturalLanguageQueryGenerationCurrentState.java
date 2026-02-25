/*
 * Copyright 2020-2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"). You may not use this file except in compliance with
 * the License. A copy of the License is located at
 * 
 * http://aws.amazon.com/apache2.0
 * 
 * or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
 * and limitations under the License.
 */
package com.amazonaws.services.opensearch.model;

import javax.annotation.Generated;

/**
 * 
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public enum NaturalLanguageQueryGenerationCurrentState {

    NOT_ENABLED("NOT_ENABLED"),
    ENABLE_COMPLETE("ENABLE_COMPLETE"),
    ENABLE_IN_PROGRESS("ENABLE_IN_PROGRESS"),
    ENABLE_FAILED("ENABLE_FAILED"),
    DISABLE_COMPLETE("DISABLE_COMPLETE"),
    DISABLE_IN_PROGRESS("DISABLE_IN_PROGRESS"),
    DISABLE_FAILED("DISABLE_FAILED");

    private String value;

    private NaturalLanguageQueryGenerationCurrentState(String value) {
        this.value = value;
    }

    @Override
    public String toString() {
        return this.value;
    }

    /**
     * Use this in place of valueOf.
     *
     * @param value
     *        real value
     * @return NaturalLanguageQueryGenerationCurrentState corresponding to the value
     *
     * @throws IllegalArgumentException
     *         If the specified value does not map to one of the known values in this enum.
     */
    public static NaturalLanguageQueryGenerationCurrentState fromValue(String value) {
        if (value == null || "".equals(value)) {
            throw new IllegalArgumentException("Value cannot be null or empty!");
        }

        for (NaturalLanguageQueryGenerationCurrentState enumEntry : NaturalLanguageQueryGenerationCurrentState.values()) {
            if (enumEntry.toString().equals(value)) {
                return enumEntry;
            }
        }

        throw new IllegalArgumentException("Cannot create enum from " + value + " value!");
    }
}
