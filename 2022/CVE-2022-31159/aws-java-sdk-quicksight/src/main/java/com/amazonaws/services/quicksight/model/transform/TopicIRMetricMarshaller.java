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
 * TopicIRMetricMarshaller
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
@SdkInternalApi
public class TopicIRMetricMarshaller {

    private static final MarshallingInfo<StructuredPojo> METRICID_BINDING = MarshallingInfo.builder(MarshallingType.STRUCTURED)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("MetricId").build();
    private static final MarshallingInfo<StructuredPojo> FUNCTION_BINDING = MarshallingInfo.builder(MarshallingType.STRUCTURED)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("Function").build();
    private static final MarshallingInfo<List> OPERANDS_BINDING = MarshallingInfo.builder(MarshallingType.LIST).marshallLocation(MarshallLocation.PAYLOAD)
            .marshallLocationName("Operands").build();
    private static final MarshallingInfo<StructuredPojo> COMPARISONMETHOD_BINDING = MarshallingInfo.builder(MarshallingType.STRUCTURED)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("ComparisonMethod").build();
    private static final MarshallingInfo<String> EXPRESSION_BINDING = MarshallingInfo.builder(MarshallingType.STRING)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("Expression").build();
    private static final MarshallingInfo<List> CALCULATEDFIELDREFERENCES_BINDING = MarshallingInfo.builder(MarshallingType.LIST)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("CalculatedFieldReferences").build();
    private static final MarshallingInfo<String> DISPLAYFORMAT_BINDING = MarshallingInfo.builder(MarshallingType.STRING)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("DisplayFormat").build();
    private static final MarshallingInfo<StructuredPojo> DISPLAYFORMATOPTIONS_BINDING = MarshallingInfo.builder(MarshallingType.STRUCTURED)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("DisplayFormatOptions").build();
    private static final MarshallingInfo<StructuredPojo> NAMEDENTITY_BINDING = MarshallingInfo.builder(MarshallingType.STRUCTURED)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("NamedEntity").build();

    private static final TopicIRMetricMarshaller instance = new TopicIRMetricMarshaller();

    public static TopicIRMetricMarshaller getInstance() {
        return instance;
    }

    /**
     * Marshall the given parameter object.
     */
    public void marshall(TopicIRMetric topicIRMetric, ProtocolMarshaller protocolMarshaller) {

        if (topicIRMetric == null) {
            throw new SdkClientException("Invalid argument passed to marshall(...)");
        }

        try {
            protocolMarshaller.marshall(topicIRMetric.getMetricId(), METRICID_BINDING);
            protocolMarshaller.marshall(topicIRMetric.getFunction(), FUNCTION_BINDING);
            protocolMarshaller.marshall(topicIRMetric.getOperands(), OPERANDS_BINDING);
            protocolMarshaller.marshall(topicIRMetric.getComparisonMethod(), COMPARISONMETHOD_BINDING);
            protocolMarshaller.marshall(topicIRMetric.getExpression(), EXPRESSION_BINDING);
            protocolMarshaller.marshall(topicIRMetric.getCalculatedFieldReferences(), CALCULATEDFIELDREFERENCES_BINDING);
            protocolMarshaller.marshall(topicIRMetric.getDisplayFormat(), DISPLAYFORMAT_BINDING);
            protocolMarshaller.marshall(topicIRMetric.getDisplayFormatOptions(), DISPLAYFORMATOPTIONS_BINDING);
            protocolMarshaller.marshall(topicIRMetric.getNamedEntity(), NAMEDENTITY_BINDING);
        } catch (Exception e) {
            throw new SdkClientException("Unable to marshall request to JSON: " + e.getMessage(), e);
        }
    }

}
