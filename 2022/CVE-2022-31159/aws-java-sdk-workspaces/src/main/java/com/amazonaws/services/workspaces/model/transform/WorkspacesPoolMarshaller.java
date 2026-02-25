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
 * WorkspacesPoolMarshaller
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
@SdkInternalApi
public class WorkspacesPoolMarshaller {

    private static final MarshallingInfo<String> POOLID_BINDING = MarshallingInfo.builder(MarshallingType.STRING).marshallLocation(MarshallLocation.PAYLOAD)
            .marshallLocationName("PoolId").build();
    private static final MarshallingInfo<String> POOLARN_BINDING = MarshallingInfo.builder(MarshallingType.STRING).marshallLocation(MarshallLocation.PAYLOAD)
            .marshallLocationName("PoolArn").build();
    private static final MarshallingInfo<StructuredPojo> CAPACITYSTATUS_BINDING = MarshallingInfo.builder(MarshallingType.STRUCTURED)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("CapacityStatus").build();
    private static final MarshallingInfo<String> POOLNAME_BINDING = MarshallingInfo.builder(MarshallingType.STRING).marshallLocation(MarshallLocation.PAYLOAD)
            .marshallLocationName("PoolName").build();
    private static final MarshallingInfo<String> DESCRIPTION_BINDING = MarshallingInfo.builder(MarshallingType.STRING)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("Description").build();
    private static final MarshallingInfo<String> STATE_BINDING = MarshallingInfo.builder(MarshallingType.STRING).marshallLocation(MarshallLocation.PAYLOAD)
            .marshallLocationName("State").build();
    private static final MarshallingInfo<java.util.Date> CREATEDAT_BINDING = MarshallingInfo.builder(MarshallingType.DATE)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("CreatedAt").timestampFormat("unixTimestamp").build();
    private static final MarshallingInfo<String> BUNDLEID_BINDING = MarshallingInfo.builder(MarshallingType.STRING).marshallLocation(MarshallLocation.PAYLOAD)
            .marshallLocationName("BundleId").build();
    private static final MarshallingInfo<String> DIRECTORYID_BINDING = MarshallingInfo.builder(MarshallingType.STRING)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("DirectoryId").build();
    private static final MarshallingInfo<List> ERRORS_BINDING = MarshallingInfo.builder(MarshallingType.LIST).marshallLocation(MarshallLocation.PAYLOAD)
            .marshallLocationName("Errors").build();
    private static final MarshallingInfo<StructuredPojo> APPLICATIONSETTINGS_BINDING = MarshallingInfo.builder(MarshallingType.STRUCTURED)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("ApplicationSettings").build();
    private static final MarshallingInfo<StructuredPojo> TIMEOUTSETTINGS_BINDING = MarshallingInfo.builder(MarshallingType.STRUCTURED)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("TimeoutSettings").build();

    private static final WorkspacesPoolMarshaller instance = new WorkspacesPoolMarshaller();

    public static WorkspacesPoolMarshaller getInstance() {
        return instance;
    }

    /**
     * Marshall the given parameter object.
     */
    public void marshall(WorkspacesPool workspacesPool, ProtocolMarshaller protocolMarshaller) {

        if (workspacesPool == null) {
            throw new SdkClientException("Invalid argument passed to marshall(...)");
        }

        try {
            protocolMarshaller.marshall(workspacesPool.getPoolId(), POOLID_BINDING);
            protocolMarshaller.marshall(workspacesPool.getPoolArn(), POOLARN_BINDING);
            protocolMarshaller.marshall(workspacesPool.getCapacityStatus(), CAPACITYSTATUS_BINDING);
            protocolMarshaller.marshall(workspacesPool.getPoolName(), POOLNAME_BINDING);
            protocolMarshaller.marshall(workspacesPool.getDescription(), DESCRIPTION_BINDING);
            protocolMarshaller.marshall(workspacesPool.getState(), STATE_BINDING);
            protocolMarshaller.marshall(workspacesPool.getCreatedAt(), CREATEDAT_BINDING);
            protocolMarshaller.marshall(workspacesPool.getBundleId(), BUNDLEID_BINDING);
            protocolMarshaller.marshall(workspacesPool.getDirectoryId(), DIRECTORYID_BINDING);
            protocolMarshaller.marshall(workspacesPool.getErrors(), ERRORS_BINDING);
            protocolMarshaller.marshall(workspacesPool.getApplicationSettings(), APPLICATIONSETTINGS_BINDING);
            protocolMarshaller.marshall(workspacesPool.getTimeoutSettings(), TIMEOUTSETTINGS_BINDING);
        } catch (Exception e) {
            throw new SdkClientException("Unable to marshall request to JSON: " + e.getMessage(), e);
        }
    }

}
