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
package com.amazonaws.services.quicksight.model;

import javax.annotation.Generated;

/**
 * 
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public enum AggType {

    SUM("SUM"),
    MIN("MIN"),
    MAX("MAX"),
    COUNT("COUNT"),
    AVERAGE("AVERAGE"),
    DISTINCT_COUNT("DISTINCT_COUNT"),
    STDEV("STDEV"),
    STDEVP("STDEVP"),
    VAR("VAR"),
    VARP("VARP"),
    PERCENTILE("PERCENTILE"),
    MEDIAN("MEDIAN"),
    PTD_SUM("PTD_SUM"),
    PTD_MIN("PTD_MIN"),
    PTD_MAX("PTD_MAX"),
    PTD_COUNT("PTD_COUNT"),
    PTD_DISTINCT_COUNT("PTD_DISTINCT_COUNT"),
    PTD_AVERAGE("PTD_AVERAGE"),
    COLUMN("COLUMN"),
    CUSTOM("CUSTOM");

    private String value;

    private AggType(String value) {
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
     * @return AggType corresponding to the value
     *
     * @throws IllegalArgumentException
     *         If the specified value does not map to one of the known values in this enum.
     */
    public static AggType fromValue(String value) {
        if (value == null || "".equals(value)) {
            throw new IllegalArgumentException("Value cannot be null or empty!");
        }

        for (AggType enumEntry : AggType.values()) {
            if (enumEntry.toString().equals(value)) {
                return enumEntry;
            }
        }

        throw new IllegalArgumentException("Cannot create enum from " + value + " value!");
    }
}
