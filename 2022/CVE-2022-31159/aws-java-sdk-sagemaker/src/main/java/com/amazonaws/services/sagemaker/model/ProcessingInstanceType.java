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
package com.amazonaws.services.sagemaker.model;

import javax.annotation.Generated;

/**
 * 
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public enum ProcessingInstanceType {

    MlT3Medium("ml.t3.medium"),
    MlT3Large("ml.t3.large"),
    MlT3Xlarge("ml.t3.xlarge"),
    MlT32xlarge("ml.t3.2xlarge"),
    MlM4Xlarge("ml.m4.xlarge"),
    MlM42xlarge("ml.m4.2xlarge"),
    MlM44xlarge("ml.m4.4xlarge"),
    MlM410xlarge("ml.m4.10xlarge"),
    MlM416xlarge("ml.m4.16xlarge"),
    MlC4Xlarge("ml.c4.xlarge"),
    MlC42xlarge("ml.c4.2xlarge"),
    MlC44xlarge("ml.c4.4xlarge"),
    MlC48xlarge("ml.c4.8xlarge"),
    MlP2Xlarge("ml.p2.xlarge"),
    MlP28xlarge("ml.p2.8xlarge"),
    MlP216xlarge("ml.p2.16xlarge"),
    MlP32xlarge("ml.p3.2xlarge"),
    MlP38xlarge("ml.p3.8xlarge"),
    MlP316xlarge("ml.p3.16xlarge"),
    MlC5Xlarge("ml.c5.xlarge"),
    MlC52xlarge("ml.c5.2xlarge"),
    MlC54xlarge("ml.c5.4xlarge"),
    MlC59xlarge("ml.c5.9xlarge"),
    MlC518xlarge("ml.c5.18xlarge"),
    MlM5Large("ml.m5.large"),
    MlM5Xlarge("ml.m5.xlarge"),
    MlM52xlarge("ml.m5.2xlarge"),
    MlM54xlarge("ml.m5.4xlarge"),
    MlM512xlarge("ml.m5.12xlarge"),
    MlM524xlarge("ml.m5.24xlarge"),
    MlR5Large("ml.r5.large"),
    MlR5Xlarge("ml.r5.xlarge"),
    MlR52xlarge("ml.r5.2xlarge"),
    MlR54xlarge("ml.r5.4xlarge"),
    MlR58xlarge("ml.r5.8xlarge"),
    MlR512xlarge("ml.r5.12xlarge"),
    MlR516xlarge("ml.r5.16xlarge"),
    MlR524xlarge("ml.r5.24xlarge"),
    MlG4dnXlarge("ml.g4dn.xlarge"),
    MlG4dn2xlarge("ml.g4dn.2xlarge"),
    MlG4dn4xlarge("ml.g4dn.4xlarge"),
    MlG4dn8xlarge("ml.g4dn.8xlarge"),
    MlG4dn12xlarge("ml.g4dn.12xlarge"),
    MlG4dn16xlarge("ml.g4dn.16xlarge"),
    MlG5Xlarge("ml.g5.xlarge"),
    MlG52xlarge("ml.g5.2xlarge"),
    MlG54xlarge("ml.g5.4xlarge"),
    MlG58xlarge("ml.g5.8xlarge"),
    MlG516xlarge("ml.g5.16xlarge"),
    MlG512xlarge("ml.g5.12xlarge"),
    MlG524xlarge("ml.g5.24xlarge"),
    MlG548xlarge("ml.g5.48xlarge"),
    MlR5dLarge("ml.r5d.large"),
    MlR5dXlarge("ml.r5d.xlarge"),
    MlR5d2xlarge("ml.r5d.2xlarge"),
    MlR5d4xlarge("ml.r5d.4xlarge"),
    MlR5d8xlarge("ml.r5d.8xlarge"),
    MlR5d12xlarge("ml.r5d.12xlarge"),
    MlR5d16xlarge("ml.r5d.16xlarge"),
    MlR5d24xlarge("ml.r5d.24xlarge");

    private String value;

    private ProcessingInstanceType(String value) {
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
     * @return ProcessingInstanceType corresponding to the value
     *
     * @throws IllegalArgumentException
     *         If the specified value does not map to one of the known values in this enum.
     */
    public static ProcessingInstanceType fromValue(String value) {
        if (value == null || "".equals(value)) {
            throw new IllegalArgumentException("Value cannot be null or empty!");
        }

        for (ProcessingInstanceType enumEntry : ProcessingInstanceType.values()) {
            if (enumEntry.toString().equals(value)) {
                return enumEntry;
            }
        }

        throw new IllegalArgumentException("Cannot create enum from " + value + " value!");
    }
}
