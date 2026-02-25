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
package com.amazonaws.services.qapps.model.transform;

import javax.annotation.Generated;

import com.amazonaws.SdkClientException;
import com.amazonaws.services.qapps.model.*;

import com.amazonaws.protocol.*;
import com.amazonaws.annotation.SdkInternalApi;

/**
 * QQueryCardInputMarshaller
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
@SdkInternalApi
public class QQueryCardInputMarshaller {

    private static final MarshallingInfo<String> TITLE_BINDING = MarshallingInfo.builder(MarshallingType.STRING).marshallLocation(MarshallLocation.PAYLOAD)
            .marshallLocationName("title").build();
    private static final MarshallingInfo<String> ID_BINDING = MarshallingInfo.builder(MarshallingType.STRING).marshallLocation(MarshallLocation.PAYLOAD)
            .marshallLocationName("id").build();
    private static final MarshallingInfo<String> TYPE_BINDING = MarshallingInfo.builder(MarshallingType.STRING).marshallLocation(MarshallLocation.PAYLOAD)
            .marshallLocationName("type").build();
    private static final MarshallingInfo<String> PROMPT_BINDING = MarshallingInfo.builder(MarshallingType.STRING).marshallLocation(MarshallLocation.PAYLOAD)
            .marshallLocationName("prompt").build();
    private static final MarshallingInfo<String> OUTPUTSOURCE_BINDING = MarshallingInfo.builder(MarshallingType.STRING)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("outputSource").build();
    private static final MarshallingInfo<StructuredPojo> ATTRIBUTEFILTER_BINDING = MarshallingInfo.builder(MarshallingType.STRUCTURED)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("attributeFilter").build();

    private static final QQueryCardInputMarshaller instance = new QQueryCardInputMarshaller();

    public static QQueryCardInputMarshaller getInstance() {
        return instance;
    }

    /**
     * Marshall the given parameter object.
     */
    public void marshall(QQueryCardInput qQueryCardInput, ProtocolMarshaller protocolMarshaller) {

        if (qQueryCardInput == null) {
            throw new SdkClientException("Invalid argument passed to marshall(...)");
        }

        try {
            protocolMarshaller.marshall(qQueryCardInput.getTitle(), TITLE_BINDING);
            protocolMarshaller.marshall(qQueryCardInput.getId(), ID_BINDING);
            protocolMarshaller.marshall(qQueryCardInput.getType(), TYPE_BINDING);
            protocolMarshaller.marshall(qQueryCardInput.getPrompt(), PROMPT_BINDING);
            protocolMarshaller.marshall(qQueryCardInput.getOutputSource(), OUTPUTSOURCE_BINDING);
            protocolMarshaller.marshall(qQueryCardInput.getAttributeFilter(), ATTRIBUTEFILTER_BINDING);
        } catch (Exception e) {
            throw new SdkClientException("Unable to marshall request to JSON: " + e.getMessage(), e);
        }
    }

}
