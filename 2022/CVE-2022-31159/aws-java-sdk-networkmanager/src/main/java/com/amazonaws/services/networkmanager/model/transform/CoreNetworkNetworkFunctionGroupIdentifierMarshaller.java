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
package com.amazonaws.services.networkmanager.model.transform;

import javax.annotation.Generated;

import com.amazonaws.SdkClientException;
import com.amazonaws.services.networkmanager.model.*;

import com.amazonaws.protocol.*;
import com.amazonaws.annotation.SdkInternalApi;

/**
 * CoreNetworkNetworkFunctionGroupIdentifierMarshaller
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
@SdkInternalApi
public class CoreNetworkNetworkFunctionGroupIdentifierMarshaller {

    private static final MarshallingInfo<String> CORENETWORKID_BINDING = MarshallingInfo.builder(MarshallingType.STRING)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("CoreNetworkId").build();
    private static final MarshallingInfo<String> NETWORKFUNCTIONGROUPNAME_BINDING = MarshallingInfo.builder(MarshallingType.STRING)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("NetworkFunctionGroupName").build();
    private static final MarshallingInfo<String> EDGELOCATION_BINDING = MarshallingInfo.builder(MarshallingType.STRING)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("EdgeLocation").build();

    private static final CoreNetworkNetworkFunctionGroupIdentifierMarshaller instance = new CoreNetworkNetworkFunctionGroupIdentifierMarshaller();

    public static CoreNetworkNetworkFunctionGroupIdentifierMarshaller getInstance() {
        return instance;
    }

    /**
     * Marshall the given parameter object.
     */
    public void marshall(CoreNetworkNetworkFunctionGroupIdentifier coreNetworkNetworkFunctionGroupIdentifier, ProtocolMarshaller protocolMarshaller) {

        if (coreNetworkNetworkFunctionGroupIdentifier == null) {
            throw new SdkClientException("Invalid argument passed to marshall(...)");
        }

        try {
            protocolMarshaller.marshall(coreNetworkNetworkFunctionGroupIdentifier.getCoreNetworkId(), CORENETWORKID_BINDING);
            protocolMarshaller.marshall(coreNetworkNetworkFunctionGroupIdentifier.getNetworkFunctionGroupName(), NETWORKFUNCTIONGROUPNAME_BINDING);
            protocolMarshaller.marshall(coreNetworkNetworkFunctionGroupIdentifier.getEdgeLocation(), EDGELOCATION_BINDING);
        } catch (Exception e) {
            throw new SdkClientException("Unable to marshall request to JSON: " + e.getMessage(), e);
        }
    }

}
