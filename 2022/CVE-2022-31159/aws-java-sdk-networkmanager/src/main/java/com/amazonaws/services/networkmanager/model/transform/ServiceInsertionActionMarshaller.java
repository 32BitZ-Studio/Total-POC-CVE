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
 * ServiceInsertionActionMarshaller
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
@SdkInternalApi
public class ServiceInsertionActionMarshaller {

    private static final MarshallingInfo<String> ACTION_BINDING = MarshallingInfo.builder(MarshallingType.STRING).marshallLocation(MarshallLocation.PAYLOAD)
            .marshallLocationName("Action").build();
    private static final MarshallingInfo<String> MODE_BINDING = MarshallingInfo.builder(MarshallingType.STRING).marshallLocation(MarshallLocation.PAYLOAD)
            .marshallLocationName("Mode").build();
    private static final MarshallingInfo<StructuredPojo> WHENSENTTO_BINDING = MarshallingInfo.builder(MarshallingType.STRUCTURED)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("WhenSentTo").build();
    private static final MarshallingInfo<StructuredPojo> VIA_BINDING = MarshallingInfo.builder(MarshallingType.STRUCTURED)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("Via").build();

    private static final ServiceInsertionActionMarshaller instance = new ServiceInsertionActionMarshaller();

    public static ServiceInsertionActionMarshaller getInstance() {
        return instance;
    }

    /**
     * Marshall the given parameter object.
     */
    public void marshall(ServiceInsertionAction serviceInsertionAction, ProtocolMarshaller protocolMarshaller) {

        if (serviceInsertionAction == null) {
            throw new SdkClientException("Invalid argument passed to marshall(...)");
        }

        try {
            protocolMarshaller.marshall(serviceInsertionAction.getAction(), ACTION_BINDING);
            protocolMarshaller.marshall(serviceInsertionAction.getMode(), MODE_BINDING);
            protocolMarshaller.marshall(serviceInsertionAction.getWhenSentTo(), WHENSENTTO_BINDING);
            protocolMarshaller.marshall(serviceInsertionAction.getVia(), VIA_BINDING);
        } catch (Exception e) {
            throw new SdkClientException("Unable to marshall request to JSON: " + e.getMessage(), e);
        }
    }

}
