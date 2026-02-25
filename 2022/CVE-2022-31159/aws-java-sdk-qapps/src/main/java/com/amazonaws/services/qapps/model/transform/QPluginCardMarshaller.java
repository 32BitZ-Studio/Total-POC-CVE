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
 * QPluginCardMarshaller
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
@SdkInternalApi
public class QPluginCardMarshaller {

    private static final MarshallingInfo<String> ID_BINDING = MarshallingInfo.builder(MarshallingType.STRING).marshallLocation(MarshallLocation.PAYLOAD)
            .marshallLocationName("id").build();
    private static final MarshallingInfo<String> TITLE_BINDING = MarshallingInfo.builder(MarshallingType.STRING).marshallLocation(MarshallLocation.PAYLOAD)
            .marshallLocationName("title").build();
    private static final MarshallingInfo<List> DEPENDENCIES_BINDING = MarshallingInfo.builder(MarshallingType.LIST).marshallLocation(MarshallLocation.PAYLOAD)
            .marshallLocationName("dependencies").build();
    private static final MarshallingInfo<String> TYPE_BINDING = MarshallingInfo.builder(MarshallingType.STRING).marshallLocation(MarshallLocation.PAYLOAD)
            .marshallLocationName("type").build();
    private static final MarshallingInfo<String> PROMPT_BINDING = MarshallingInfo.builder(MarshallingType.STRING).marshallLocation(MarshallLocation.PAYLOAD)
            .marshallLocationName("prompt").build();
    private static final MarshallingInfo<String> PLUGINTYPE_BINDING = MarshallingInfo.builder(MarshallingType.STRING)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("pluginType").build();
    private static final MarshallingInfo<String> PLUGINID_BINDING = MarshallingInfo.builder(MarshallingType.STRING).marshallLocation(MarshallLocation.PAYLOAD)
            .marshallLocationName("pluginId").build();

    private static final QPluginCardMarshaller instance = new QPluginCardMarshaller();

    public static QPluginCardMarshaller getInstance() {
        return instance;
    }

    /**
     * Marshall the given parameter object.
     */
    public void marshall(QPluginCard qPluginCard, ProtocolMarshaller protocolMarshaller) {

        if (qPluginCard == null) {
            throw new SdkClientException("Invalid argument passed to marshall(...)");
        }

        try {
            protocolMarshaller.marshall(qPluginCard.getId(), ID_BINDING);
            protocolMarshaller.marshall(qPluginCard.getTitle(), TITLE_BINDING);
            protocolMarshaller.marshall(qPluginCard.getDependencies(), DEPENDENCIES_BINDING);
            protocolMarshaller.marshall(qPluginCard.getType(), TYPE_BINDING);
            protocolMarshaller.marshall(qPluginCard.getPrompt(), PROMPT_BINDING);
            protocolMarshaller.marshall(qPluginCard.getPluginType(), PLUGINTYPE_BINDING);
            protocolMarshaller.marshall(qPluginCard.getPluginId(), PLUGINID_BINDING);
        } catch (Exception e) {
            throw new SdkClientException("Unable to marshall request to JSON: " + e.getMessage(), e);
        }
    }

}
