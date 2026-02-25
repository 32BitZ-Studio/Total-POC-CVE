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
 * ContributionAnalysisTimeRangesMarshaller
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
@SdkInternalApi
public class ContributionAnalysisTimeRangesMarshaller {

    private static final MarshallingInfo<StructuredPojo> STARTRANGE_BINDING = MarshallingInfo.builder(MarshallingType.STRUCTURED)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("StartRange").build();
    private static final MarshallingInfo<StructuredPojo> ENDRANGE_BINDING = MarshallingInfo.builder(MarshallingType.STRUCTURED)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("EndRange").build();

    private static final ContributionAnalysisTimeRangesMarshaller instance = new ContributionAnalysisTimeRangesMarshaller();

    public static ContributionAnalysisTimeRangesMarshaller getInstance() {
        return instance;
    }

    /**
     * Marshall the given parameter object.
     */
    public void marshall(ContributionAnalysisTimeRanges contributionAnalysisTimeRanges, ProtocolMarshaller protocolMarshaller) {

        if (contributionAnalysisTimeRanges == null) {
            throw new SdkClientException("Invalid argument passed to marshall(...)");
        }

        try {
            protocolMarshaller.marshall(contributionAnalysisTimeRanges.getStartRange(), STARTRANGE_BINDING);
            protocolMarshaller.marshall(contributionAnalysisTimeRanges.getEndRange(), ENDRANGE_BINDING);
        } catch (Exception e) {
            throw new SdkClientException("Unable to marshall request to JSON: " + e.getMessage(), e);
        }
    }

}
