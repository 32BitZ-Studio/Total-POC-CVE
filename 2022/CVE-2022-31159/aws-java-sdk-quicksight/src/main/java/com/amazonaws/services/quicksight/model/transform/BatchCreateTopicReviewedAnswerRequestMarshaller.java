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
 * BatchCreateTopicReviewedAnswerRequestMarshaller
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
@SdkInternalApi
public class BatchCreateTopicReviewedAnswerRequestMarshaller {

    private static final MarshallingInfo<String> AWSACCOUNTID_BINDING = MarshallingInfo.builder(MarshallingType.STRING).marshallLocation(MarshallLocation.PATH)
            .marshallLocationName("AwsAccountId").build();
    private static final MarshallingInfo<String> TOPICID_BINDING = MarshallingInfo.builder(MarshallingType.STRING).marshallLocation(MarshallLocation.PATH)
            .marshallLocationName("TopicId").build();
    private static final MarshallingInfo<List> ANSWERS_BINDING = MarshallingInfo.builder(MarshallingType.LIST).marshallLocation(MarshallLocation.PAYLOAD)
            .marshallLocationName("Answers").build();

    private static final BatchCreateTopicReviewedAnswerRequestMarshaller instance = new BatchCreateTopicReviewedAnswerRequestMarshaller();

    public static BatchCreateTopicReviewedAnswerRequestMarshaller getInstance() {
        return instance;
    }

    /**
     * Marshall the given parameter object.
     */
    public void marshall(BatchCreateTopicReviewedAnswerRequest batchCreateTopicReviewedAnswerRequest, ProtocolMarshaller protocolMarshaller) {

        if (batchCreateTopicReviewedAnswerRequest == null) {
            throw new SdkClientException("Invalid argument passed to marshall(...)");
        }

        try {
            protocolMarshaller.marshall(batchCreateTopicReviewedAnswerRequest.getAwsAccountId(), AWSACCOUNTID_BINDING);
            protocolMarshaller.marshall(batchCreateTopicReviewedAnswerRequest.getTopicId(), TOPICID_BINDING);
            protocolMarshaller.marshall(batchCreateTopicReviewedAnswerRequest.getAnswers(), ANSWERS_BINDING);
        } catch (Exception e) {
            throw new SdkClientException("Unable to marshall request to JSON: " + e.getMessage(), e);
        }
    }

}
