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
 * PeeringErrorMarshaller
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
@SdkInternalApi
public class PeeringErrorMarshaller {

    private static final MarshallingInfo<String> CODE_BINDING = MarshallingInfo.builder(MarshallingType.STRING).marshallLocation(MarshallLocation.PAYLOAD)
            .marshallLocationName("Code").build();
    private static final MarshallingInfo<String> MESSAGE_BINDING = MarshallingInfo.builder(MarshallingType.STRING).marshallLocation(MarshallLocation.PAYLOAD)
            .marshallLocationName("Message").build();
    private static final MarshallingInfo<String> RESOURCEARN_BINDING = MarshallingInfo.builder(MarshallingType.STRING)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("ResourceArn").build();
    private static final MarshallingInfo<String> REQUESTID_BINDING = MarshallingInfo.builder(MarshallingType.STRING).marshallLocation(MarshallLocation.PAYLOAD)
            .marshallLocationName("RequestId").build();
    private static final MarshallingInfo<StructuredPojo> MISSINGPERMISSIONSCONTEXT_BINDING = MarshallingInfo.builder(MarshallingType.STRUCTURED)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("MissingPermissionsContext").build();

    private static final PeeringErrorMarshaller instance = new PeeringErrorMarshaller();

    public static PeeringErrorMarshaller getInstance() {
        return instance;
    }

    /**
     * Marshall the given parameter object.
     */
    public void marshall(PeeringError peeringError, ProtocolMarshaller protocolMarshaller) {

        if (peeringError == null) {
            throw new SdkClientException("Invalid argument passed to marshall(...)");
        }

        try {
            protocolMarshaller.marshall(peeringError.getCode(), CODE_BINDING);
            protocolMarshaller.marshall(peeringError.getMessage(), MESSAGE_BINDING);
            protocolMarshaller.marshall(peeringError.getResourceArn(), RESOURCEARN_BINDING);
            protocolMarshaller.marshall(peeringError.getRequestId(), REQUESTID_BINDING);
            protocolMarshaller.marshall(peeringError.getMissingPermissionsContext(), MISSINGPERMISSIONSCONTEXT_BINDING);
        } catch (Exception e) {
            throw new SdkClientException("Unable to marshall request to JSON: " + e.getMessage(), e);
        }
    }

}
