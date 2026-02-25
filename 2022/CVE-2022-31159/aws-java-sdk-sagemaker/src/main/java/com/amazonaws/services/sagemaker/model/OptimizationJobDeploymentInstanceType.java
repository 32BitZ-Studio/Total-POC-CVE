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
public enum OptimizationJobDeploymentInstanceType {

    MlP4d24xlarge("ml.p4d.24xlarge"),
    MlP4de24xlarge("ml.p4de.24xlarge"),
    MlP548xlarge("ml.p5.48xlarge"),
    MlG5Xlarge("ml.g5.xlarge"),
    MlG52xlarge("ml.g5.2xlarge"),
    MlG54xlarge("ml.g5.4xlarge"),
    MlG58xlarge("ml.g5.8xlarge"),
    MlG512xlarge("ml.g5.12xlarge"),
    MlG516xlarge("ml.g5.16xlarge"),
    MlG524xlarge("ml.g5.24xlarge"),
    MlG548xlarge("ml.g5.48xlarge"),
    MlG6Xlarge("ml.g6.xlarge"),
    MlG62xlarge("ml.g6.2xlarge"),
    MlG64xlarge("ml.g6.4xlarge"),
    MlG68xlarge("ml.g6.8xlarge"),
    MlG612xlarge("ml.g6.12xlarge"),
    MlG616xlarge("ml.g6.16xlarge"),
    MlG624xlarge("ml.g6.24xlarge"),
    MlG648xlarge("ml.g6.48xlarge"),
    MlInf2Xlarge("ml.inf2.xlarge"),
    MlInf28xlarge("ml.inf2.8xlarge"),
    MlInf224xlarge("ml.inf2.24xlarge"),
    MlInf248xlarge("ml.inf2.48xlarge"),
    MlTrn12xlarge("ml.trn1.2xlarge"),
    MlTrn132xlarge("ml.trn1.32xlarge"),
    MlTrn1n32xlarge("ml.trn1n.32xlarge");

    private String value;

    private OptimizationJobDeploymentInstanceType(String value) {
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
     * @return OptimizationJobDeploymentInstanceType corresponding to the value
     *
     * @throws IllegalArgumentException
     *         If the specified value does not map to one of the known values in this enum.
     */
    public static OptimizationJobDeploymentInstanceType fromValue(String value) {
        if (value == null || "".equals(value)) {
            throw new IllegalArgumentException("Value cannot be null or empty!");
        }

        for (OptimizationJobDeploymentInstanceType enumEntry : OptimizationJobDeploymentInstanceType.values()) {
            if (enumEntry.toString().equals(value)) {
                return enumEntry;
            }
        }

        throw new IllegalArgumentException("Cannot create enum from " + value + " value!");
    }
}
