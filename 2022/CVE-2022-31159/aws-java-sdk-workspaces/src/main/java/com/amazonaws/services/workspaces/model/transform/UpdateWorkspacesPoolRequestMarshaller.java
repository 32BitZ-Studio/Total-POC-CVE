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

import javax.annotation.Generated;

import com.amazonaws.SdkClientException;
import com.amazonaws.services.workspaces.model.*;

import com.amazonaws.protocol.*;
import com.amazonaws.annotation.SdkInternalApi;

/**
 * UpdateWorkspacesPoolRequestMarshaller
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
@SdkInternalApi
public class UpdateWorkspacesPoolRequestMarshaller {

    private static final MarshallingInfo<String> POOLID_BINDING = MarshallingInfo.builder(MarshallingType.STRING).marshallLocation(MarshallLocation.PAYLOAD)
            .marshallLocationName("PoolId").build();
    private static final MarshallingInfo<String> DESCRIPTION_BINDING = MarshallingInfo.builder(MarshallingType.STRING)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("Description").build();
    private static final MarshallingInfo<String> BUNDLEID_BINDING = MarshallingInfo.builder(MarshallingType.STRING).marshallLocation(MarshallLocation.PAYLOAD)
            .marshallLocationName("BundleId").build();
    private static final MarshallingInfo<String> DIRECTORYID_BINDING = MarshallingInfo.builder(MarshallingType.STRING)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("DirectoryId").build();
    private static final MarshallingInfo<StructuredPojo> CAPACITY_BINDING = MarshallingInfo.builder(MarshallingType.STRUCTURED)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("Capacity").build();
    private static final MarshallingInfo<StructuredPojo> APPLICATIONSETTINGS_BINDING = MarshallingInfo.builder(MarshallingType.STRUCTURED)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("ApplicationSettings").build();
    private static final MarshallingInfo<StructuredPojo> TIMEOUTSETTINGS_BINDING = MarshallingInfo.builder(MarshallingType.STRUCTURED)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("TimeoutSettings").build();

    private static final UpdateWorkspacesPoolRequestMarshaller instance = new UpdateWorkspacesPoolRequestMarshaller();

    public static UpdateWorkspacesPoolRequestMarshaller getInstance() {
        return instance;
    }

    /**
     * Marshall the given parameter object.
     */
    public void marshall(UpdateWorkspacesPoolRequest updateWorkspacesPoolRequest, ProtocolMarshaller protocolMarshaller) {

        if (updateWorkspacesPoolRequest == null) {
            throw new SdkClientException("Invalid argument passed to marshall(...)");
        }

        try {
            protocolMarshaller.marshall(updateWorkspacesPoolRequest.getPoolId(), POOLID_BINDING);
            protocolMarshaller.marshall(updateWorkspacesPoolRequest.getDescription(), DESCRIPTION_BINDING);
            protocolMarshaller.marshall(updateWorkspacesPoolRequest.getBundleId(), BUNDLEID_BINDING);
            protocolMarshaller.marshall(updateWorkspacesPoolRequest.getDirectoryId(), DIRECTORYID_BINDING);
            protocolMarshaller.marshall(updateWorkspacesPoolRequest.getCapacity(), CAPACITY_BINDING);
            protocolMarshaller.marshall(updateWorkspacesPoolRequest.getApplicationSettings(), APPLICATIONSETTINGS_BINDING);
            protocolMarshaller.marshall(updateWorkspacesPoolRequest.getTimeoutSettings(), TIMEOUTSETTINGS_BINDING);
        } catch (Exception e) {
            throw new SdkClientException("Unable to marshall request to JSON: " + e.getMessage(), e);
        }
    }

}
