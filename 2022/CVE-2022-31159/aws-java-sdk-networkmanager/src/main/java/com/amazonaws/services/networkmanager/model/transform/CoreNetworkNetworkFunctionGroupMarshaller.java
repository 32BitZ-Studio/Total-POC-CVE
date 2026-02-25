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

import java.util.List;
import javax.annotation.Generated;

import com.amazonaws.SdkClientException;
import com.amazonaws.services.networkmanager.model.*;

import com.amazonaws.protocol.*;
import com.amazonaws.annotation.SdkInternalApi;

/**
 * CoreNetworkNetworkFunctionGroupMarshaller
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
@SdkInternalApi
public class CoreNetworkNetworkFunctionGroupMarshaller {

    private static final MarshallingInfo<String> NAME_BINDING = MarshallingInfo.builder(MarshallingType.STRING).marshallLocation(MarshallLocation.PAYLOAD)
            .marshallLocationName("Name").build();
    private static final MarshallingInfo<List> EDGELOCATIONS_BINDING = MarshallingInfo.builder(MarshallingType.LIST).marshallLocation(MarshallLocation.PAYLOAD)
            .marshallLocationName("EdgeLocations").build();
    private static final MarshallingInfo<StructuredPojo> SEGMENTS_BINDING = MarshallingInfo.builder(MarshallingType.STRUCTURED)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("Segments").build();

    private static final CoreNetworkNetworkFunctionGroupMarshaller instance = new CoreNetworkNetworkFunctionGroupMarshaller();

    public static CoreNetworkNetworkFunctionGroupMarshaller getInstance() {
        return instance;
    }

    /**
     * Marshall the given parameter object.
     */
    public void marshall(CoreNetworkNetworkFunctionGroup coreNetworkNetworkFunctionGroup, ProtocolMarshaller protocolMarshaller) {

        if (coreNetworkNetworkFunctionGroup == null) {
            throw new SdkClientException("Invalid argument passed to marshall(...)");
        }

        try {
            protocolMarshaller.marshall(coreNetworkNetworkFunctionGroup.getName(), NAME_BINDING);
            protocolMarshaller.marshall(coreNetworkNetworkFunctionGroup.getEdgeLocations(), EDGELOCATIONS_BINDING);
            protocolMarshaller.marshall(coreNetworkNetworkFunctionGroup.getSegments(), SEGMENTS_BINDING);
        } catch (Exception e) {
            throw new SdkClientException("Unable to marshall request to JSON: " + e.getMessage(), e);
        }
    }

}
