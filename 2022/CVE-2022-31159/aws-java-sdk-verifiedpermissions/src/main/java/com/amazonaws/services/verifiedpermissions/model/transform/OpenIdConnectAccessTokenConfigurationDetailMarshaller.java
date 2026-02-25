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
package com.amazonaws.services.verifiedpermissions.model.transform;

import java.util.List;
import javax.annotation.Generated;

import com.amazonaws.SdkClientException;
import com.amazonaws.services.verifiedpermissions.model.*;

import com.amazonaws.protocol.*;
import com.amazonaws.annotation.SdkInternalApi;

/**
 * OpenIdConnectAccessTokenConfigurationDetailMarshaller
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
@SdkInternalApi
public class OpenIdConnectAccessTokenConfigurationDetailMarshaller {

    private static final MarshallingInfo<String> PRINCIPALIDCLAIM_BINDING = MarshallingInfo.builder(MarshallingType.STRING)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("principalIdClaim").build();
    private static final MarshallingInfo<List> AUDIENCES_BINDING = MarshallingInfo.builder(MarshallingType.LIST).marshallLocation(MarshallLocation.PAYLOAD)
            .marshallLocationName("audiences").build();

    private static final OpenIdConnectAccessTokenConfigurationDetailMarshaller instance = new OpenIdConnectAccessTokenConfigurationDetailMarshaller();

    public static OpenIdConnectAccessTokenConfigurationDetailMarshaller getInstance() {
        return instance;
    }

    /**
     * Marshall the given parameter object.
     */
    public void marshall(OpenIdConnectAccessTokenConfigurationDetail openIdConnectAccessTokenConfigurationDetail, ProtocolMarshaller protocolMarshaller) {

        if (openIdConnectAccessTokenConfigurationDetail == null) {
            throw new SdkClientException("Invalid argument passed to marshall(...)");
        }

        try {
            protocolMarshaller.marshall(openIdConnectAccessTokenConfigurationDetail.getPrincipalIdClaim(), PRINCIPALIDCLAIM_BINDING);
            protocolMarshaller.marshall(openIdConnectAccessTokenConfigurationDetail.getAudiences(), AUDIENCES_BINDING);
        } catch (Exception e) {
            throw new SdkClientException("Unable to marshall request to JSON: " + e.getMessage(), e);
        }
    }

}
