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
package com.amazonaws.services.workspaces.model.transform;

import java.util.List;
import javax.annotation.Generated;

import com.amazonaws.SdkClientException;
import com.amazonaws.services.workspaces.model.*;

import com.amazonaws.protocol.*;
import com.amazonaws.annotation.SdkInternalApi;

/**
 * StreamingPropertiesMarshaller
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
@SdkInternalApi
public class StreamingPropertiesMarshaller {

    private static final MarshallingInfo<String> STREAMINGEXPERIENCEPREFERREDPROTOCOL_BINDING = MarshallingInfo.builder(MarshallingType.STRING)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("StreamingExperiencePreferredProtocol").build();
    private static final MarshallingInfo<List> USERSETTINGS_BINDING = MarshallingInfo.builder(MarshallingType.LIST).marshallLocation(MarshallLocation.PAYLOAD)
            .marshallLocationName("UserSettings").build();
    private static final MarshallingInfo<List> STORAGECONNECTORS_BINDING = MarshallingInfo.builder(MarshallingType.LIST)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("StorageConnectors").build();

    private static final StreamingPropertiesMarshaller instance = new StreamingPropertiesMarshaller();

    public static StreamingPropertiesMarshaller getInstance() {
        return instance;
    }

    /**
     * Marshall the given parameter object.
     */
    public void marshall(StreamingProperties streamingProperties, ProtocolMarshaller protocolMarshaller) {

        if (streamingProperties == null) {
            throw new SdkClientException("Invalid argument passed to marshall(...)");
        }

        try {
            protocolMarshaller.marshall(streamingProperties.getStreamingExperiencePreferredProtocol(), STREAMINGEXPERIENCEPREFERREDPROTOCOL_BINDING);
            protocolMarshaller.marshall(streamingProperties.getUserSettings(), USERSETTINGS_BINDING);
            protocolMarshaller.marshall(streamingProperties.getStorageConnectors(), STORAGECONNECTORS_BINDING);
        } catch (Exception e) {
            throw new SdkClientException("Unable to marshall request to JSON: " + e.getMessage(), e);
        }
    }

}
