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
 * WorkspacesPoolSessionMarshaller
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
@SdkInternalApi
public class WorkspacesPoolSessionMarshaller {

    private static final MarshallingInfo<String> AUTHENTICATIONTYPE_BINDING = MarshallingInfo.builder(MarshallingType.STRING)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("AuthenticationType").build();
    private static final MarshallingInfo<String> CONNECTIONSTATE_BINDING = MarshallingInfo.builder(MarshallingType.STRING)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("ConnectionState").build();
    private static final MarshallingInfo<String> SESSIONID_BINDING = MarshallingInfo.builder(MarshallingType.STRING).marshallLocation(MarshallLocation.PAYLOAD)
            .marshallLocationName("SessionId").build();
    private static final MarshallingInfo<String> INSTANCEID_BINDING = MarshallingInfo.builder(MarshallingType.STRING)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("InstanceId").build();
    private static final MarshallingInfo<String> POOLID_BINDING = MarshallingInfo.builder(MarshallingType.STRING).marshallLocation(MarshallLocation.PAYLOAD)
            .marshallLocationName("PoolId").build();
    private static final MarshallingInfo<java.util.Date> EXPIRATIONTIME_BINDING = MarshallingInfo.builder(MarshallingType.DATE)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("ExpirationTime").timestampFormat("unixTimestamp").build();
    private static final MarshallingInfo<StructuredPojo> NETWORKACCESSCONFIGURATION_BINDING = MarshallingInfo.builder(MarshallingType.STRUCTURED)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("NetworkAccessConfiguration").build();
    private static final MarshallingInfo<java.util.Date> STARTTIME_BINDING = MarshallingInfo.builder(MarshallingType.DATE)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("StartTime").timestampFormat("unixTimestamp").build();
    private static final MarshallingInfo<String> USERID_BINDING = MarshallingInfo.builder(MarshallingType.STRING).marshallLocation(MarshallLocation.PAYLOAD)
            .marshallLocationName("UserId").build();

    private static final WorkspacesPoolSessionMarshaller instance = new WorkspacesPoolSessionMarshaller();

    public static WorkspacesPoolSessionMarshaller getInstance() {
        return instance;
    }

    /**
     * Marshall the given parameter object.
     */
    public void marshall(WorkspacesPoolSession workspacesPoolSession, ProtocolMarshaller protocolMarshaller) {

        if (workspacesPoolSession == null) {
            throw new SdkClientException("Invalid argument passed to marshall(...)");
        }

        try {
            protocolMarshaller.marshall(workspacesPoolSession.getAuthenticationType(), AUTHENTICATIONTYPE_BINDING);
            protocolMarshaller.marshall(workspacesPoolSession.getConnectionState(), CONNECTIONSTATE_BINDING);
            protocolMarshaller.marshall(workspacesPoolSession.getSessionId(), SESSIONID_BINDING);
            protocolMarshaller.marshall(workspacesPoolSession.getInstanceId(), INSTANCEID_BINDING);
            protocolMarshaller.marshall(workspacesPoolSession.getPoolId(), POOLID_BINDING);
            protocolMarshaller.marshall(workspacesPoolSession.getExpirationTime(), EXPIRATIONTIME_BINDING);
            protocolMarshaller.marshall(workspacesPoolSession.getNetworkAccessConfiguration(), NETWORKACCESSCONFIGURATION_BINDING);
            protocolMarshaller.marshall(workspacesPoolSession.getStartTime(), STARTTIME_BINDING);
            protocolMarshaller.marshall(workspacesPoolSession.getUserId(), USERID_BINDING);
        } catch (Exception e) {
            throw new SdkClientException("Unable to marshall request to JSON: " + e.getMessage(), e);
        }
    }

}
