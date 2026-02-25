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
package com.amazonaws.services.quicksight.model.transform;

import java.util.List;
import javax.annotation.Generated;

import com.amazonaws.SdkClientException;
import com.amazonaws.services.quicksight.model.*;

import com.amazonaws.protocol.*;
import com.amazonaws.annotation.SdkInternalApi;

/**
 * TopicConstantValueMarshaller
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
@SdkInternalApi
public class TopicConstantValueMarshaller {

    private static final MarshallingInfo<String> CONSTANTTYPE_BINDING = MarshallingInfo.builder(MarshallingType.STRING)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("ConstantType").build();
    private static final MarshallingInfo<String> VALUE_BINDING = MarshallingInfo.builder(MarshallingType.STRING).marshallLocation(MarshallLocation.PAYLOAD)
            .marshallLocationName("Value").build();
    private static final MarshallingInfo<String> MINIMUM_BINDING = MarshallingInfo.builder(MarshallingType.STRING).marshallLocation(MarshallLocation.PAYLOAD)
            .marshallLocationName("Minimum").build();
    private static final MarshallingInfo<String> MAXIMUM_BINDING = MarshallingInfo.builder(MarshallingType.STRING).marshallLocation(MarshallLocation.PAYLOAD)
            .marshallLocationName("Maximum").build();
    private static final MarshallingInfo<List> VALUELIST_BINDING = MarshallingInfo.builder(MarshallingType.LIST).marshallLocation(MarshallLocation.PAYLOAD)
            .marshallLocationName("ValueList").build();

    private static final TopicConstantValueMarshaller instance = new TopicConstantValueMarshaller();

    public static TopicConstantValueMarshaller getInstance() {
        return instance;
    }

    /**
     * Marshall the given parameter object.
     */
    public void marshall(TopicConstantValue topicConstantValue, ProtocolMarshaller protocolMarshaller) {

        if (topicConstantValue == null) {
            throw new SdkClientException("Invalid argument passed to marshall(...)");
        }

        try {
            protocolMarshaller.marshall(topicConstantValue.getConstantType(), CONSTANTTYPE_BINDING);
            protocolMarshaller.marshall(topicConstantValue.getValue(), VALUE_BINDING);
            protocolMarshaller.marshall(topicConstantValue.getMinimum(), MINIMUM_BINDING);
            protocolMarshaller.marshall(topicConstantValue.getMaximum(), MAXIMUM_BINDING);
            protocolMarshaller.marshall(topicConstantValue.getValueList(), VALUELIST_BINDING);
        } catch (Exception e) {
            throw new SdkClientException("Unable to marshall request to JSON: " + e.getMessage(), e);
        }
    }

}
