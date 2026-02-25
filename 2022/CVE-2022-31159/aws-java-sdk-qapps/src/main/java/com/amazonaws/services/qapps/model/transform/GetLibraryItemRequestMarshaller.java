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
 * GetLibraryItemRequestMarshaller
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
@SdkInternalApi
public class GetLibraryItemRequestMarshaller {

    private static final MarshallingInfo<String> INSTANCEID_BINDING = MarshallingInfo.builder(MarshallingType.STRING).marshallLocation(MarshallLocation.HEADER)
            .marshallLocationName("instance-id").build();
    private static final MarshallingInfo<String> LIBRARYITEMID_BINDING = MarshallingInfo.builder(MarshallingType.STRING)
            .marshallLocation(MarshallLocation.QUERY_PARAM).marshallLocationName("libraryItemId").build();
    private static final MarshallingInfo<String> APPID_BINDING = MarshallingInfo.builder(MarshallingType.STRING).marshallLocation(MarshallLocation.QUERY_PARAM)
            .marshallLocationName("appId").build();

    private static final GetLibraryItemRequestMarshaller instance = new GetLibraryItemRequestMarshaller();

    public static GetLibraryItemRequestMarshaller getInstance() {
        return instance;
    }

    /**
     * Marshall the given parameter object.
     */
    public void marshall(GetLibraryItemRequest getLibraryItemRequest, ProtocolMarshaller protocolMarshaller) {

        if (getLibraryItemRequest == null) {
            throw new SdkClientException("Invalid argument passed to marshall(...)");
        }

        try {
            protocolMarshaller.marshall(getLibraryItemRequest.getInstanceId(), INSTANCEID_BINDING);
            protocolMarshaller.marshall(getLibraryItemRequest.getLibraryItemId(), LIBRARYITEMID_BINDING);
            protocolMarshaller.marshall(getLibraryItemRequest.getAppId(), APPID_BINDING);
        } catch (Exception e) {
            throw new SdkClientException("Unable to marshall request to JSON: " + e.getMessage(), e);
        }
    }

}
