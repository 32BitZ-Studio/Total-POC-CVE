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
 * TopicIRContributionAnalysisMarshaller
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
@SdkInternalApi
public class TopicIRContributionAnalysisMarshaller {

    private static final MarshallingInfo<List> FACTORS_BINDING = MarshallingInfo.builder(MarshallingType.LIST).marshallLocation(MarshallLocation.PAYLOAD)
            .marshallLocationName("Factors").build();
    private static final MarshallingInfo<StructuredPojo> TIMERANGES_BINDING = MarshallingInfo.builder(MarshallingType.STRUCTURED)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("TimeRanges").build();
    private static final MarshallingInfo<String> DIRECTION_BINDING = MarshallingInfo.builder(MarshallingType.STRING).marshallLocation(MarshallLocation.PAYLOAD)
            .marshallLocationName("Direction").build();
    private static final MarshallingInfo<String> SORTTYPE_BINDING = MarshallingInfo.builder(MarshallingType.STRING).marshallLocation(MarshallLocation.PAYLOAD)
            .marshallLocationName("SortType").build();

    private static final TopicIRContributionAnalysisMarshaller instance = new TopicIRContributionAnalysisMarshaller();

    public static TopicIRContributionAnalysisMarshaller getInstance() {
        return instance;
    }

    /**
     * Marshall the given parameter object.
     */
    public void marshall(TopicIRContributionAnalysis topicIRContributionAnalysis, ProtocolMarshaller protocolMarshaller) {

        if (topicIRContributionAnalysis == null) {
            throw new SdkClientException("Invalid argument passed to marshall(...)");
        }

        try {
            protocolMarshaller.marshall(topicIRContributionAnalysis.getFactors(), FACTORS_BINDING);
            protocolMarshaller.marshall(topicIRContributionAnalysis.getTimeRanges(), TIMERANGES_BINDING);
            protocolMarshaller.marshall(topicIRContributionAnalysis.getDirection(), DIRECTION_BINDING);
            protocolMarshaller.marshall(topicIRContributionAnalysis.getSortType(), SORTTYPE_BINDING);
        } catch (Exception e) {
            throw new SdkClientException("Unable to marshall request to JSON: " + e.getMessage(), e);
        }
    }

}
