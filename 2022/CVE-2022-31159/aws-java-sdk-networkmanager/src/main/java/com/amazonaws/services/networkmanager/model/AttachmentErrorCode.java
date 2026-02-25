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
package com.amazonaws.services.networkmanager.model;

import javax.annotation.Generated;

/**
 * 
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public enum AttachmentErrorCode {

    VPC_NOT_FOUND("VPC_NOT_FOUND"),
    SUBNET_NOT_FOUND("SUBNET_NOT_FOUND"),
    SUBNET_DUPLICATED_IN_AVAILABILITY_ZONE("SUBNET_DUPLICATED_IN_AVAILABILITY_ZONE"),
    SUBNET_NO_FREE_ADDRESSES("SUBNET_NO_FREE_ADDRESSES"),
    SUBNET_UNSUPPORTED_AVAILABILITY_ZONE("SUBNET_UNSUPPORTED_AVAILABILITY_ZONE"),
    SUBNET_NO_IPV6_CIDRS("SUBNET_NO_IPV6_CIDRS"),
    VPN_CONNECTION_NOT_FOUND("VPN_CONNECTION_NOT_FOUND"),
    MAXIMUM_NO_ENCAP_LIMIT_EXCEEDED("MAXIMUM_NO_ENCAP_LIMIT_EXCEEDED");

    private String value;

    private AttachmentErrorCode(String value) {
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
     * @return AttachmentErrorCode corresponding to the value
     *
     * @throws IllegalArgumentException
     *         If the specified value does not map to one of the known values in this enum.
     */
    public static AttachmentErrorCode fromValue(String value) {
        if (value == null || "".equals(value)) {
            throw new IllegalArgumentException("Value cannot be null or empty!");
        }

        for (AttachmentErrorCode enumEntry : AttachmentErrorCode.values()) {
            if (enumEntry.toString().equals(value)) {
                return enumEntry;
            }
        }

        throw new IllegalArgumentException("Cannot create enum from " + value + " value!");
    }
}
