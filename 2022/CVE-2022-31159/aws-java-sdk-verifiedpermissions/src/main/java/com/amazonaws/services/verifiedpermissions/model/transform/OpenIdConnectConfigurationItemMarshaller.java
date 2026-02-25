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

import javax.annotation.Generated;

import com.amazonaws.SdkClientException;
import com.amazonaws.services.verifiedpermissions.model.*;

import com.amazonaws.protocol.*;
import com.amazonaws.annotation.SdkInternalApi;

/**
 * OpenIdConnectConfigurationItemMarshaller
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
@SdkInternalApi
public class OpenIdConnectConfigurationItemMarshaller {

    private static final MarshallingInfo<String> ISSUER_BINDING = MarshallingInfo.builder(MarshallingType.STRING).marshallLocation(MarshallLocation.PAYLOAD)
            .marshallLocationName("issuer").build();
    private static final MarshallingInfo<String> ENTITYIDPREFIX_BINDING = MarshallingInfo.builder(MarshallingType.STRING)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("entityIdPrefix").build();
    private static final MarshallingInfo<StructuredPojo> GROUPCONFIGURATION_BINDING = MarshallingInfo.builder(MarshallingType.STRUCTURED)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("groupConfiguration").build();
    private static final MarshallingInfo<StructuredPojo> TOKENSELECTION_BINDING = MarshallingInfo.builder(MarshallingType.STRUCTURED)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("tokenSelection").build();

    private static final OpenIdConnectConfigurationItemMarshaller instance = new OpenIdConnectConfigurationItemMarshaller();

    public static OpenIdConnectConfigurationItemMarshaller getInstance() {
        return instance;
    }

    /**
     * Marshall the given parameter object.
     */
    public void marshall(OpenIdConnectConfigurationItem openIdConnectConfigurationItem, ProtocolMarshaller protocolMarshaller) {

        if (openIdConnectConfigurationItem == null) {
            throw new SdkClientException("Invalid argument passed to marshall(...)");
        }

        try {
            protocolMarshaller.marshall(openIdConnectConfigurationItem.getIssuer(), ISSUER_BINDING);
            protocolMarshaller.marshall(openIdConnectConfigurationItem.getEntityIdPrefix(), ENTITYIDPREFIX_BINDING);
            protocolMarshaller.marshall(openIdConnectConfigurationItem.getGroupConfiguration(), GROUPCONFIGURATION_BINDING);
            protocolMarshaller.marshall(openIdConnectConfigurationItem.getTokenSelection(), TOKENSELECTION_BINDING);
        } catch (Exception e) {
            throw new SdkClientException("Unable to marshall request to JSON: " + e.getMessage(), e);
        }
    }

}
