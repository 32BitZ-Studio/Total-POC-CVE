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

import com.amazonaws.util.IdempotentUtils;

import com.amazonaws.protocol.*;
import com.amazonaws.annotation.SdkInternalApi;

/**
 * CreateContentAssociationRequestMarshaller
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
@SdkInternalApi
public class CreateContentAssociationRequestMarshaller {

    private static final MarshallingInfo<StructuredPojo> ASSOCIATION_BINDING = MarshallingInfo.builder(MarshallingType.STRUCTURED)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("association").build();
    private static final MarshallingInfo<String> ASSOCIATIONTYPE_BINDING = MarshallingInfo.builder(MarshallingType.STRING)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("associationType").build();
    private static final MarshallingInfo<String> CLIENTTOKEN_BINDING = MarshallingInfo.builder(MarshallingType.STRING)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("clientToken")
            .defaultValueSupplier(com.amazonaws.util.IdempotentUtils.getGenerator()).build();
    private static final MarshallingInfo<String> CONTENTID_BINDING = MarshallingInfo.builder(MarshallingType.STRING).marshallLocation(MarshallLocation.PATH)
            .marshallLocationName("contentId").build();
    private static final MarshallingInfo<String> KNOWLEDGEBASEID_BINDING = MarshallingInfo.builder(MarshallingType.STRING)
            .marshallLocation(MarshallLocation.PATH).marshallLocationName("knowledgeBaseId").build();
    private static final MarshallingInfo<Map> TAGS_BINDING = MarshallingInfo.builder(MarshallingType.MAP).marshallLocation(MarshallLocation.PAYLOAD)
            .marshallLocationName("tags").build();

    private static final CreateContentAssociationRequestMarshaller instance = new CreateContentAssociationRequestMarshaller();

    public static CreateContentAssociationRequestMarshaller getInstance() {
        return instance;
    }

    /**
     * Marshall the given parameter object.
     */
    public void marshall(CreateContentAssociationRequest createContentAssociationRequest, ProtocolMarshaller protocolMarshaller) {

        if (createContentAssociationRequest == null) {
            throw new SdkClientException("Invalid argument passed to marshall(...)");
        }

        try {
            protocolMarshaller.marshall(createContentAssociationRequest.getAssociation(), ASSOCIATION_BINDING);
            protocolMarshaller.marshall(createContentAssociationRequest.getAssociationType(), ASSOCIATIONTYPE_BINDING);
            protocolMarshaller.marshall(createContentAssociationRequest.getClientToken(), CLIENTTOKEN_BINDING);
            protocolMarshaller.marshall(createContentAssociationRequest.getContentId(), CONTENTID_BINDING);
            protocolMarshaller.marshall(createContentAssociationRequest.getKnowledgeBaseId(), KNOWLEDGEBASEID_BINDING);
            protocolMarshaller.marshall(createContentAssociationRequest.getTags(), TAGS_BINDING);
        } catch (Exception e) {
            throw new SdkClientException("Unable to marshall request to JSON: " + e.getMessage(), e);
        }
    }

}
