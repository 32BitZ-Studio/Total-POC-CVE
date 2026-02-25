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
 * TopicReviewedAnswerMarshaller
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
@SdkInternalApi
public class TopicReviewedAnswerMarshaller {

    private static final MarshallingInfo<String> ARN_BINDING = MarshallingInfo.builder(MarshallingType.STRING).marshallLocation(MarshallLocation.PAYLOAD)
            .marshallLocationName("Arn").build();
    private static final MarshallingInfo<String> ANSWERID_BINDING = MarshallingInfo.builder(MarshallingType.STRING).marshallLocation(MarshallLocation.PAYLOAD)
            .marshallLocationName("AnswerId").build();
    private static final MarshallingInfo<String> DATASETARN_BINDING = MarshallingInfo.builder(MarshallingType.STRING)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("DatasetArn").build();
    private static final MarshallingInfo<String> QUESTION_BINDING = MarshallingInfo.builder(MarshallingType.STRING).marshallLocation(MarshallLocation.PAYLOAD)
            .marshallLocationName("Question").build();
    private static final MarshallingInfo<StructuredPojo> MIR_BINDING = MarshallingInfo.builder(MarshallingType.STRUCTURED)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("Mir").build();
    private static final MarshallingInfo<StructuredPojo> PRIMARYVISUAL_BINDING = MarshallingInfo.builder(MarshallingType.STRUCTURED)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("PrimaryVisual").build();
    private static final MarshallingInfo<StructuredPojo> TEMPLATE_BINDING = MarshallingInfo.builder(MarshallingType.STRUCTURED)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("Template").build();

    private static final TopicReviewedAnswerMarshaller instance = new TopicReviewedAnswerMarshaller();

    public static TopicReviewedAnswerMarshaller getInstance() {
        return instance;
    }

    /**
     * Marshall the given parameter object.
     */
    public void marshall(TopicReviewedAnswer topicReviewedAnswer, ProtocolMarshaller protocolMarshaller) {

        if (topicReviewedAnswer == null) {
            throw new SdkClientException("Invalid argument passed to marshall(...)");
        }

        try {
            protocolMarshaller.marshall(topicReviewedAnswer.getArn(), ARN_BINDING);
            protocolMarshaller.marshall(topicReviewedAnswer.getAnswerId(), ANSWERID_BINDING);
            protocolMarshaller.marshall(topicReviewedAnswer.getDatasetArn(), DATASETARN_BINDING);
            protocolMarshaller.marshall(topicReviewedAnswer.getQuestion(), QUESTION_BINDING);
            protocolMarshaller.marshall(topicReviewedAnswer.getMir(), MIR_BINDING);
            protocolMarshaller.marshall(topicReviewedAnswer.getPrimaryVisual(), PRIMARYVISUAL_BINDING);
            protocolMarshaller.marshall(topicReviewedAnswer.getTemplate(), TEMPLATE_BINDING);
        } catch (Exception e) {
            throw new SdkClientException("Unable to marshall request to JSON: " + e.getMessage(), e);
        }
    }

}
