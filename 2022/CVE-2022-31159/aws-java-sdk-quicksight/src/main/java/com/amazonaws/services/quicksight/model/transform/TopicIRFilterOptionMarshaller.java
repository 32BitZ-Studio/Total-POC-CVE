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

import java.util.Map;
import java.util.List;
import javax.annotation.Generated;

import com.amazonaws.SdkClientException;
import com.amazonaws.services.quicksight.model.*;

import com.amazonaws.protocol.*;
import com.amazonaws.annotation.SdkInternalApi;

/**
 * TopicIRFilterOptionMarshaller
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
@SdkInternalApi
public class TopicIRFilterOptionMarshaller {

    private static final MarshallingInfo<String> FILTERTYPE_BINDING = MarshallingInfo.builder(MarshallingType.STRING)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("FilterType").build();
    private static final MarshallingInfo<String> FILTERCLASS_BINDING = MarshallingInfo.builder(MarshallingType.STRING)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("FilterClass").build();
    private static final MarshallingInfo<StructuredPojo> OPERANDFIELD_BINDING = MarshallingInfo.builder(MarshallingType.STRUCTURED)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("OperandField").build();
    private static final MarshallingInfo<String> FUNCTION_BINDING = MarshallingInfo.builder(MarshallingType.STRING).marshallLocation(MarshallLocation.PAYLOAD)
            .marshallLocationName("Function").build();
    private static final MarshallingInfo<StructuredPojo> CONSTANT_BINDING = MarshallingInfo.builder(MarshallingType.STRUCTURED)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("Constant").build();
    private static final MarshallingInfo<Boolean> INVERSE_BINDING = MarshallingInfo.builder(MarshallingType.BOOLEAN).marshallLocation(MarshallLocation.PAYLOAD)
            .marshallLocationName("Inverse").build();
    private static final MarshallingInfo<String> NULLFILTER_BINDING = MarshallingInfo.builder(MarshallingType.STRING)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("NullFilter").build();
    private static final MarshallingInfo<String> AGGREGATION_BINDING = MarshallingInfo.builder(MarshallingType.STRING)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("Aggregation").build();
    private static final MarshallingInfo<Map> AGGREGATIONFUNCTIONPARAMETERS_BINDING = MarshallingInfo.builder(MarshallingType.MAP)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("AggregationFunctionParameters").build();
    private static final MarshallingInfo<List> AGGREGATIONPARTITIONBY_BINDING = MarshallingInfo.builder(MarshallingType.LIST)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("AggregationPartitionBy").build();
    private static final MarshallingInfo<StructuredPojo> RANGE_BINDING = MarshallingInfo.builder(MarshallingType.STRUCTURED)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("Range").build();
    private static final MarshallingInfo<Boolean> INCLUSIVE_BINDING = MarshallingInfo.builder(MarshallingType.BOOLEAN)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("Inclusive").build();
    private static final MarshallingInfo<String> TIMEGRANULARITY_BINDING = MarshallingInfo.builder(MarshallingType.STRING)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("TimeGranularity").build();
    private static final MarshallingInfo<StructuredPojo> LASTNEXTOFFSET_BINDING = MarshallingInfo.builder(MarshallingType.STRUCTURED)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("LastNextOffset").build();
    private static final MarshallingInfo<List> AGGMETRICS_BINDING = MarshallingInfo.builder(MarshallingType.LIST).marshallLocation(MarshallLocation.PAYLOAD)
            .marshallLocationName("AggMetrics").build();
    private static final MarshallingInfo<StructuredPojo> TOPBOTTOMLIMIT_BINDING = MarshallingInfo.builder(MarshallingType.STRUCTURED)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("TopBottomLimit").build();
    private static final MarshallingInfo<String> SORTDIRECTION_BINDING = MarshallingInfo.builder(MarshallingType.STRING)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("SortDirection").build();
    private static final MarshallingInfo<StructuredPojo> ANCHOR_BINDING = MarshallingInfo.builder(MarshallingType.STRUCTURED)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("Anchor").build();

    private static final TopicIRFilterOptionMarshaller instance = new TopicIRFilterOptionMarshaller();

    public static TopicIRFilterOptionMarshaller getInstance() {
        return instance;
    }

    /**
     * Marshall the given parameter object.
     */
    public void marshall(TopicIRFilterOption topicIRFilterOption, ProtocolMarshaller protocolMarshaller) {

        if (topicIRFilterOption == null) {
            throw new SdkClientException("Invalid argument passed to marshall(...)");
        }

        try {
            protocolMarshaller.marshall(topicIRFilterOption.getFilterType(), FILTERTYPE_BINDING);
            protocolMarshaller.marshall(topicIRFilterOption.getFilterClass(), FILTERCLASS_BINDING);
            protocolMarshaller.marshall(topicIRFilterOption.getOperandField(), OPERANDFIELD_BINDING);
            protocolMarshaller.marshall(topicIRFilterOption.getFunction(), FUNCTION_BINDING);
            protocolMarshaller.marshall(topicIRFilterOption.getConstant(), CONSTANT_BINDING);
            protocolMarshaller.marshall(topicIRFilterOption.getInverse(), INVERSE_BINDING);
            protocolMarshaller.marshall(topicIRFilterOption.getNullFilter(), NULLFILTER_BINDING);
            protocolMarshaller.marshall(topicIRFilterOption.getAggregation(), AGGREGATION_BINDING);
            protocolMarshaller.marshall(topicIRFilterOption.getAggregationFunctionParameters(), AGGREGATIONFUNCTIONPARAMETERS_BINDING);
            protocolMarshaller.marshall(topicIRFilterOption.getAggregationPartitionBy(), AGGREGATIONPARTITIONBY_BINDING);
            protocolMarshaller.marshall(topicIRFilterOption.getRange(), RANGE_BINDING);
            protocolMarshaller.marshall(topicIRFilterOption.getInclusive(), INCLUSIVE_BINDING);
            protocolMarshaller.marshall(topicIRFilterOption.getTimeGranularity(), TIMEGRANULARITY_BINDING);
            protocolMarshaller.marshall(topicIRFilterOption.getLastNextOffset(), LASTNEXTOFFSET_BINDING);
            protocolMarshaller.marshall(topicIRFilterOption.getAggMetrics(), AGGMETRICS_BINDING);
            protocolMarshaller.marshall(topicIRFilterOption.getTopBottomLimit(), TOPBOTTOMLIMIT_BINDING);
            protocolMarshaller.marshall(topicIRFilterOption.getSortDirection(), SORTDIRECTION_BINDING);
            protocolMarshaller.marshall(topicIRFilterOption.getAnchor(), ANCHOR_BINDING);
        } catch (Exception e) {
            throw new SdkClientException("Unable to marshall request to JSON: " + e.getMessage(), e);
        }
    }

}
