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

import java.util.List;
import javax.annotation.Generated;

import com.amazonaws.SdkClientException;
import com.amazonaws.services.qapps.model.*;

import com.amazonaws.protocol.*;
import com.amazonaws.annotation.SdkInternalApi;

/**
 * TextInputCardMarshaller
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
@SdkInternalApi
public class TextInputCardMarshaller {

    private static final MarshallingInfo<String> ID_BINDING = MarshallingInfo.builder(MarshallingType.STRING).marshallLocation(MarshallLocation.PAYLOAD)
            .marshallLocationName("id").build();
    private static final MarshallingInfo<String> TITLE_BINDING = MarshallingInfo.builder(MarshallingType.STRING).marshallLocation(MarshallLocation.PAYLOAD)
            .marshallLocationName("title").build();
    private static final MarshallingInfo<List> DEPENDENCIES_BINDING = MarshallingInfo.builder(MarshallingType.LIST).marshallLocation(MarshallLocation.PAYLOAD)
            .marshallLocationName("dependencies").build();
    private static final MarshallingInfo<String> TYPE_BINDING = MarshallingInfo.builder(MarshallingType.STRING).marshallLocation(MarshallLocation.PAYLOAD)
            .marshallLocationName("type").build();
    private static final MarshallingInfo<String> PLACEHOLDER_BINDING = MarshallingInfo.builder(MarshallingType.STRING)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("placeholder").build();
    private static final MarshallingInfo<String> DEFAULTVALUE_BINDING = MarshallingInfo.builder(MarshallingType.STRING)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("defaultValue").build();

    private static final TextInputCardMarshaller instance = new TextInputCardMarshaller();

    public static TextInputCardMarshaller getInstance() {
        return instance;
    }

    /**
     * Marshall the given parameter object.
     */
    public void marshall(TextInputCard textInputCard, ProtocolMarshaller protocolMarshaller) {

        if (textInputCard == null) {
            throw new SdkClientException("Invalid argument passed to marshall(...)");
        }

        try {
            protocolMarshaller.marshall(textInputCard.getId(), ID_BINDING);
            protocolMarshaller.marshall(textInputCard.getTitle(), TITLE_BINDING);
            protocolMarshaller.marshall(textInputCard.getDependencies(), DEPENDENCIES_BINDING);
            protocolMarshaller.marshall(textInputCard.getType(), TYPE_BINDING);
            protocolMarshaller.marshall(textInputCard.getPlaceholder(), PLACEHOLDER_BINDING);
            protocolMarshaller.marshall(textInputCard.getDefaultValue(), DEFAULTVALUE_BINDING);
        } catch (Exception e) {
            throw new SdkClientException("Unable to marshall request to JSON: " + e.getMessage(), e);
        }
    }

}
