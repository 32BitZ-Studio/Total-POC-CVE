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
package com.amazonaws.services.qconnect.model.transform;

import java.util.Map;

import javax.annotation.Generated;

import com.amazonaws.SdkClientException;
import com.amazonaws.services.qconnect.model.*;

import com.amazonaws.protocol.*;
import com.amazonaws.annotation.SdkInternalApi;

/**
 * ContentAssociationDataMarshaller
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
@SdkInternalApi
public class ContentAssociationDataMarshaller {

    private static final MarshallingInfo<StructuredPojo> ASSOCIATIONDATA_BINDING = MarshallingInfo.builder(MarshallingType.STRUCTURED)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("associationData").build();
    private static final MarshallingInfo<String> ASSOCIATIONTYPE_BINDING = MarshallingInfo.builder(MarshallingType.STRING)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("associationType").build();
    private static final MarshallingInfo<String> CONTENTARN_BINDING = MarshallingInfo.builder(MarshallingType.STRING)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("contentArn").build();
    private static final MarshallingInfo<String> CONTENTASSOCIATIONARN_BINDING = MarshallingInfo.builder(MarshallingType.STRING)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("contentAssociationArn").build();
    private static final MarshallingInfo<String> CONTENTASSOCIATIONID_BINDING = MarshallingInfo.builder(MarshallingType.STRING)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("contentAssociationId").build();
    private static final MarshallingInfo<String> CONTENTID_BINDING = MarshallingInfo.builder(MarshallingType.STRING).marshallLocation(MarshallLocation.PAYLOAD)
            .marshallLocationName("contentId").build();
    private static final MarshallingInfo<String> KNOWLEDGEBASEARN_BINDING = MarshallingInfo.builder(MarshallingType.STRING)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("knowledgeBaseArn").build();
    private static final MarshallingInfo<String> KNOWLEDGEBASEID_BINDING = MarshallingInfo.builder(MarshallingType.STRING)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("knowledgeBaseId").build();
    private static final MarshallingInfo<Map> TAGS_BINDING = MarshallingInfo.builder(MarshallingType.MAP).marshallLocation(MarshallLocation.PAYLOAD)
            .marshallLocationName("tags").build();

    private static final ContentAssociationDataMarshaller instance = new ContentAssociationDataMarshaller();

    public static ContentAssociationDataMarshaller getInstance() {
        return instance;
    }

    /**
     * Marshall the given parameter object.
     */
    public void marshall(ContentAssociationData contentAssociationData, ProtocolMarshaller protocolMarshaller) {

        if (contentAssociationData == null) {
            throw new SdkClientException("Invalid argument passed to marshall(...)");
        }

        try {
            protocolMarshaller.marshall(contentAssociationData.getAssociationData(), ASSOCIATIONDATA_BINDING);
            protocolMarshaller.marshall(contentAssociationData.getAssociationType(), ASSOCIATIONTYPE_BINDING);
            protocolMarshaller.marshall(contentAssociationData.getContentArn(), CONTENTARN_BINDING);
            protocolMarshaller.marshall(contentAssociationData.getContentAssociationArn(), CONTENTASSOCIATIONARN_BINDING);
            protocolMarshaller.marshall(contentAssociationData.getContentAssociationId(), CONTENTASSOCIATIONID_BINDING);
            protocolMarshaller.marshall(contentAssociationData.getContentId(), CONTENTID_BINDING);
            protocolMarshaller.marshall(contentAssociationData.getKnowledgeBaseArn(), KNOWLEDGEBASEARN_BINDING);
            protocolMarshaller.marshall(contentAssociationData.getKnowledgeBaseId(), KNOWLEDGEBASEID_BINDING);
            protocolMarshaller.marshall(contentAssociationData.getTags(), TAGS_BINDING);
        } catch (Exception e) {
            throw new SdkClientException("Unable to marshall request to JSON: " + e.getMessage(), e);
        }
    }

}
