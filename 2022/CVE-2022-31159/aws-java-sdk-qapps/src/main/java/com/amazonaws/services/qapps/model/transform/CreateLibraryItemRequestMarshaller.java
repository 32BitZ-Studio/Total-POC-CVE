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
 * CreateLibraryItemRequestMarshaller
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
@SdkInternalApi
public class CreateLibraryItemRequestMarshaller {

    private static final MarshallingInfo<String> INSTANCEID_BINDING = MarshallingInfo.builder(MarshallingType.STRING).marshallLocation(MarshallLocation.HEADER)
            .marshallLocationName("instance-id").build();
    private static final MarshallingInfo<String> APPID_BINDING = MarshallingInfo.builder(MarshallingType.STRING).marshallLocation(MarshallLocation.PAYLOAD)
            .marshallLocationName("appId").build();
    private static final MarshallingInfo<Integer> APPVERSION_BINDING = MarshallingInfo.builder(MarshallingType.INTEGER)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("appVersion").build();
    private static final MarshallingInfo<List> CATEGORIES_BINDING = MarshallingInfo.builder(MarshallingType.LIST).marshallLocation(MarshallLocation.PAYLOAD)
            .marshallLocationName("categories").build();

    private static final CreateLibraryItemRequestMarshaller instance = new CreateLibraryItemRequestMarshaller();

    public static CreateLibraryItemRequestMarshaller getInstance() {
        return instance;
    }

    /**
     * Marshall the given parameter object.
     */
    public void marshall(CreateLibraryItemRequest createLibraryItemRequest, ProtocolMarshaller protocolMarshaller) {

        if (createLibraryItemRequest == null) {
            throw new SdkClientException("Invalid argument passed to marshall(...)");
        }

        try {
            protocolMarshaller.marshall(createLibraryItemRequest.getInstanceId(), INSTANCEID_BINDING);
            protocolMarshaller.marshall(createLibraryItemRequest.getAppId(), APPID_BINDING);
            protocolMarshaller.marshall(createLibraryItemRequest.getAppVersion(), APPVERSION_BINDING);
            protocolMarshaller.marshall(createLibraryItemRequest.getCategories(), CATEGORIES_BINDING);
        } catch (Exception e) {
            throw new SdkClientException("Unable to marshall request to JSON: " + e.getMessage(), e);
        }
    }

}
