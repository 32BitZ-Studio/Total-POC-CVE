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
package com.amazonaws.services.sagemaker.model.transform;

import java.util.List;
import javax.annotation.Generated;

import com.amazonaws.SdkClientException;
import com.amazonaws.services.sagemaker.model.*;

import com.amazonaws.protocol.*;
import com.amazonaws.annotation.SdkInternalApi;

/**
 * CreateHubContentReferenceRequestMarshaller
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
@SdkInternalApi
public class CreateHubContentReferenceRequestMarshaller {

    private static final MarshallingInfo<String> HUBNAME_BINDING = MarshallingInfo.builder(MarshallingType.STRING).marshallLocation(MarshallLocation.PAYLOAD)
            .marshallLocationName("HubName").build();
    private static final MarshallingInfo<String> SAGEMAKERPUBLICHUBCONTENTARN_BINDING = MarshallingInfo.builder(MarshallingType.STRING)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("SageMakerPublicHubContentArn").build();
    private static final MarshallingInfo<String> HUBCONTENTNAME_BINDING = MarshallingInfo.builder(MarshallingType.STRING)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("HubContentName").build();
    private static final MarshallingInfo<String> MINVERSION_BINDING = MarshallingInfo.builder(MarshallingType.STRING)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("MinVersion").build();
    private static final MarshallingInfo<List> TAGS_BINDING = MarshallingInfo.builder(MarshallingType.LIST).marshallLocation(MarshallLocation.PAYLOAD)
            .marshallLocationName("Tags").build();

    private static final CreateHubContentReferenceRequestMarshaller instance = new CreateHubContentReferenceRequestMarshaller();

    public static CreateHubContentReferenceRequestMarshaller getInstance() {
        return instance;
    }

    /**
     * Marshall the given parameter object.
     */
    public void marshall(CreateHubContentReferenceRequest createHubContentReferenceRequest, ProtocolMarshaller protocolMarshaller) {

        if (createHubContentReferenceRequest == null) {
            throw new SdkClientException("Invalid argument passed to marshall(...)");
        }

        try {
            protocolMarshaller.marshall(createHubContentReferenceRequest.getHubName(), HUBNAME_BINDING);
            protocolMarshaller.marshall(createHubContentReferenceRequest.getSageMakerPublicHubContentArn(), SAGEMAKERPUBLICHUBCONTENTARN_BINDING);
            protocolMarshaller.marshall(createHubContentReferenceRequest.getHubContentName(), HUBCONTENTNAME_BINDING);
            protocolMarshaller.marshall(createHubContentReferenceRequest.getMinVersion(), MINVERSION_BINDING);
            protocolMarshaller.marshall(createHubContentReferenceRequest.getTags(), TAGS_BINDING);
        } catch (Exception e) {
            throw new SdkClientException("Unable to marshall request to JSON: " + e.getMessage(), e);
        }
    }

}
