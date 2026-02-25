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

import javax.annotation.Generated;

import com.amazonaws.SdkClientException;
import com.amazonaws.services.quicksight.model.*;

import com.amazonaws.protocol.*;
import com.amazonaws.annotation.SdkInternalApi;

/**
 * TopicIRGroupByMarshaller
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
@SdkInternalApi
public class TopicIRGroupByMarshaller {

    private static final MarshallingInfo<StructuredPojo> FIELDNAME_BINDING = MarshallingInfo.builder(MarshallingType.STRUCTURED)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("FieldName").build();
    private static final MarshallingInfo<String> TIMEGRANULARITY_BINDING = MarshallingInfo.builder(MarshallingType.STRING)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("TimeGranularity").build();
    private static final MarshallingInfo<StructuredPojo> SORT_BINDING = MarshallingInfo.builder(MarshallingType.STRUCTURED)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("Sort").build();
    private static final MarshallingInfo<String> DISPLAYFORMAT_BINDING = MarshallingInfo.builder(MarshallingType.STRING)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("DisplayFormat").build();
    private static final MarshallingInfo<StructuredPojo> DISPLAYFORMATOPTIONS_BINDING = MarshallingInfo.builder(MarshallingType.STRUCTURED)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("DisplayFormatOptions").build();
    private static final MarshallingInfo<StructuredPojo> NAMEDENTITY_BINDING = MarshallingInfo.builder(MarshallingType.STRUCTURED)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("NamedEntity").build();

    private static final TopicIRGroupByMarshaller instance = new TopicIRGroupByMarshaller();

    public static TopicIRGroupByMarshaller getInstance() {
        return instance;
    }

    /**
     * Marshall the given parameter object.
     */
    public void marshall(TopicIRGroupBy topicIRGroupBy, ProtocolMarshaller protocolMarshaller) {

        if (topicIRGroupBy == null) {
            throw new SdkClientException("Invalid argument passed to marshall(...)");
        }

        try {
            protocolMarshaller.marshall(topicIRGroupBy.getFieldName(), FIELDNAME_BINDING);
            protocolMarshaller.marshall(topicIRGroupBy.getTimeGranularity(), TIMEGRANULARITY_BINDING);
            protocolMarshaller.marshall(topicIRGroupBy.getSort(), SORT_BINDING);
            protocolMarshaller.marshall(topicIRGroupBy.getDisplayFormat(), DISPLAYFORMAT_BINDING);
            protocolMarshaller.marshall(topicIRGroupBy.getDisplayFormatOptions(), DISPLAYFORMATOPTIONS_BINDING);
            protocolMarshaller.marshall(topicIRGroupBy.getNamedEntity(), NAMEDENTITY_BINDING);
        } catch (Exception e) {
            throw new SdkClientException("Unable to marshall request to JSON: " + e.getMessage(), e);
        }
    }

}
