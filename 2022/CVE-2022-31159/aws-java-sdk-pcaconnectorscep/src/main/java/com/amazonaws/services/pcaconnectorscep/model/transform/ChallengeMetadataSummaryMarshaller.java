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
package com.amazonaws.services.pcaconnectorscep.model.transform;

import javax.annotation.Generated;

import com.amazonaws.SdkClientException;
import com.amazonaws.services.pcaconnectorscep.model.*;

import com.amazonaws.protocol.*;
import com.amazonaws.annotation.SdkInternalApi;

/**
 * ChallengeMetadataSummaryMarshaller
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
@SdkInternalApi
public class ChallengeMetadataSummaryMarshaller {

    private static final MarshallingInfo<String> ARN_BINDING = MarshallingInfo.builder(MarshallingType.STRING).marshallLocation(MarshallLocation.PAYLOAD)
            .marshallLocationName("Arn").build();
    private static final MarshallingInfo<String> CONNECTORARN_BINDING = MarshallingInfo.builder(MarshallingType.STRING)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("ConnectorArn").build();
    private static final MarshallingInfo<java.util.Date> CREATEDAT_BINDING = MarshallingInfo.builder(MarshallingType.DATE)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("CreatedAt").timestampFormat("unixTimestamp").build();
    private static final MarshallingInfo<java.util.Date> UPDATEDAT_BINDING = MarshallingInfo.builder(MarshallingType.DATE)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("UpdatedAt").timestampFormat("unixTimestamp").build();

    private static final ChallengeMetadataSummaryMarshaller instance = new ChallengeMetadataSummaryMarshaller();

    public static ChallengeMetadataSummaryMarshaller getInstance() {
        return instance;
    }

    /**
     * Marshall the given parameter object.
     */
    public void marshall(ChallengeMetadataSummary challengeMetadataSummary, ProtocolMarshaller protocolMarshaller) {

        if (challengeMetadataSummary == null) {
            throw new SdkClientException("Invalid argument passed to marshall(...)");
        }

        try {
            protocolMarshaller.marshall(challengeMetadataSummary.getArn(), ARN_BINDING);
            protocolMarshaller.marshall(challengeMetadataSummary.getConnectorArn(), CONNECTORARN_BINDING);
            protocolMarshaller.marshall(challengeMetadataSummary.getCreatedAt(), CREATEDAT_BINDING);
            protocolMarshaller.marshall(challengeMetadataSummary.getUpdatedAt(), UPDATEDAT_BINDING);
        } catch (Exception e) {
            throw new SdkClientException("Unable to marshall request to JSON: " + e.getMessage(), e);
        }
    }

}
