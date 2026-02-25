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
public enum ConnectPeerErrorCode {

    EDGE_LOCATION_NO_FREE_IPS("EDGE_LOCATION_NO_FREE_IPS"),
    EDGE_LOCATION_PEER_DUPLICATE("EDGE_LOCATION_PEER_DUPLICATE"),
    SUBNET_NOT_FOUND("SUBNET_NOT_FOUND"),
    IP_OUTSIDE_SUBNET_CIDR_RANGE("IP_OUTSIDE_SUBNET_CIDR_RANGE"),
    INVALID_INSIDE_CIDR_BLOCK("INVALID_INSIDE_CIDR_BLOCK"),
    NO_ASSOCIATED_CIDR_BLOCK("NO_ASSOCIATED_CIDR_BLOCK");

    private String value;

    private ConnectPeerErrorCode(String value) {
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
     * @return ConnectPeerErrorCode corresponding to the value
     *
     * @throws IllegalArgumentException
     *         If the specified value does not map to one of the known values in this enum.
     */
    public static ConnectPeerErrorCode fromValue(String value) {
        if (value == null || "".equals(value)) {
            throw new IllegalArgumentException("Value cannot be null or empty!");
        }

        for (ConnectPeerErrorCode enumEntry : ConnectPeerErrorCode.values()) {
            if (enumEntry.toString().equals(value)) {
                return enumEntry;
            }
        }

        throw new IllegalArgumentException("Cannot create enum from " + value + " value!");
    }
}
