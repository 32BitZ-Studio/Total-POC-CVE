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
 * TopicIRMarshaller
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
@SdkInternalApi
public class TopicIRMarshaller {

    private static final MarshallingInfo<List> METRICS_BINDING = MarshallingInfo.builder(MarshallingType.LIST).marshallLocation(MarshallLocation.PAYLOAD)
            .marshallLocationName("Metrics").build();
    private static final MarshallingInfo<List> GROUPBYLIST_BINDING = MarshallingInfo.builder(MarshallingType.LIST).marshallLocation(MarshallLocation.PAYLOAD)
            .marshallLocationName("GroupByList").build();
    private static final MarshallingInfo<List> FILTERS_BINDING = MarshallingInfo.builder(MarshallingType.LIST).marshallLocation(MarshallLocation.PAYLOAD)
            .marshallLocationName("Filters").build();
    private static final MarshallingInfo<StructuredPojo> SORT_BINDING = MarshallingInfo.builder(MarshallingType.STRUCTURED)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("Sort").build();
    private static final MarshallingInfo<StructuredPojo> CONTRIBUTIONANALYSIS_BINDING = MarshallingInfo.builder(MarshallingType.STRUCTURED)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("ContributionAnalysis").build();
    private static final MarshallingInfo<StructuredPojo> VISUAL_BINDING = MarshallingInfo.builder(MarshallingType.STRUCTURED)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("Visual").build();

    private static final TopicIRMarshaller instance = new TopicIRMarshaller();

    public static TopicIRMarshaller getInstance() {
        return instance;
    }

    /**
     * Marshall the given parameter object.
     */
    public void marshall(TopicIR topicIR, ProtocolMarshaller protocolMarshaller) {

        if (topicIR == null) {
            throw new SdkClientException("Invalid argument passed to marshall(...)");
        }

        try {
            protocolMarshaller.marshall(topicIR.getMetrics(), METRICS_BINDING);
            protocolMarshaller.marshall(topicIR.getGroupByList(), GROUPBYLIST_BINDING);
            protocolMarshaller.marshall(topicIR.getFilters(), FILTERS_BINDING);
            protocolMarshaller.marshall(topicIR.getSort(), SORT_BINDING);
            protocolMarshaller.marshall(topicIR.getContributionAnalysis(), CONTRIBUTIONANALYSIS_BINDING);
            protocolMarshaller.marshall(topicIR.getVisual(), VISUAL_BINDING);
        } catch (Exception e) {
            throw new SdkClientException("Unable to marshall request to JSON: " + e.getMessage(), e);
        }
    }

}
