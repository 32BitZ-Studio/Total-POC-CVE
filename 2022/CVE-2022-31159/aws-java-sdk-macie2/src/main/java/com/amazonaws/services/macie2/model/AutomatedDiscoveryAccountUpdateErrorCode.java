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
package com.amazonaws.services.macie2.model;

import javax.annotation.Generated;

/**
 * <p>
 * The error code that indicates why a request failed to change the status of automated sensitive data discovery for an
 * Amazon Macie account. Possible values are:
 * </p>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public enum AutomatedDiscoveryAccountUpdateErrorCode {

    ACCOUNT_PAUSED("ACCOUNT_PAUSED"),
    ACCOUNT_NOT_FOUND("ACCOUNT_NOT_FOUND");

    private String value;

    private AutomatedDiscoveryAccountUpdateErrorCode(String value) {
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
     * @return AutomatedDiscoveryAccountUpdateErrorCode corresponding to the value
     *
     * @throws IllegalArgumentException
     *         If the specified value does not map to one of the known values in this enum.
     */
    public static AutomatedDiscoveryAccountUpdateErrorCode fromValue(String value) {
        if (value == null || "".equals(value)) {
            throw new IllegalArgumentException("Value cannot be null or empty!");
        }

        for (AutomatedDiscoveryAccountUpdateErrorCode enumEntry : AutomatedDiscoveryAccountUpdateErrorCode.values()) {
            if (enumEntry.toString().equals(value)) {
                return enumEntry;
            }
        }

        throw new IllegalArgumentException("Cannot create enum from " + value + " value!");
    }
}
