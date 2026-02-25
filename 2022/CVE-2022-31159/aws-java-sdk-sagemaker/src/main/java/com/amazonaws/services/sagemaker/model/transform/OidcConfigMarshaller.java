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
package com.amazonaws.services.sagemaker.model.transform;

import java.util.Map;

import javax.annotation.Generated;

import com.amazonaws.SdkClientException;
import com.amazonaws.services.sagemaker.model.*;

import com.amazonaws.protocol.*;
import com.amazonaws.annotation.SdkInternalApi;

/**
 * OidcConfigMarshaller
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
@SdkInternalApi
public class OidcConfigMarshaller {

    private static final MarshallingInfo<String> CLIENTID_BINDING = MarshallingInfo.builder(MarshallingType.STRING).marshallLocation(MarshallLocation.PAYLOAD)
            .marshallLocationName("ClientId").build();
    private static final MarshallingInfo<String> CLIENTSECRET_BINDING = MarshallingInfo.builder(MarshallingType.STRING)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("ClientSecret").build();
    private static final MarshallingInfo<String> ISSUER_BINDING = MarshallingInfo.builder(MarshallingType.STRING).marshallLocation(MarshallLocation.PAYLOAD)
            .marshallLocationName("Issuer").build();
    private static final MarshallingInfo<String> AUTHORIZATIONENDPOINT_BINDING = MarshallingInfo.builder(MarshallingType.STRING)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("AuthorizationEndpoint").build();
    private static final MarshallingInfo<String> TOKENENDPOINT_BINDING = MarshallingInfo.builder(MarshallingType.STRING)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("TokenEndpoint").build();
    private static final MarshallingInfo<String> USERINFOENDPOINT_BINDING = MarshallingInfo.builder(MarshallingType.STRING)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("UserInfoEndpoint").build();
    private static final MarshallingInfo<String> LOGOUTENDPOINT_BINDING = MarshallingInfo.builder(MarshallingType.STRING)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("LogoutEndpoint").build();
    private static final MarshallingInfo<String> JWKSURI_BINDING = MarshallingInfo.builder(MarshallingType.STRING).marshallLocation(MarshallLocation.PAYLOAD)
            .marshallLocationName("JwksUri").build();
    private static final MarshallingInfo<String> SCOPE_BINDING = MarshallingInfo.builder(MarshallingType.STRING).marshallLocation(MarshallLocation.PAYLOAD)
            .marshallLocationName("Scope").build();
    private static final MarshallingInfo<Map> AUTHENTICATIONREQUESTEXTRAPARAMS_BINDING = MarshallingInfo.builder(MarshallingType.MAP)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("AuthenticationRequestExtraParams").build();

    private static final OidcConfigMarshaller instance = new OidcConfigMarshaller();

    public static OidcConfigMarshaller getInstance() {
        return instance;
    }

    /**
     * Marshall the given parameter object.
     */
    public void marshall(OidcConfig oidcConfig, ProtocolMarshaller protocolMarshaller) {

        if (oidcConfig == null) {
            throw new SdkClientException("Invalid argument passed to marshall(...)");
        }

        try {
            protocolMarshaller.marshall(oidcConfig.getClientId(), CLIENTID_BINDING);
            protocolMarshaller.marshall(oidcConfig.getClientSecret(), CLIENTSECRET_BINDING);
            protocolMarshaller.marshall(oidcConfig.getIssuer(), ISSUER_BINDING);
            protocolMarshaller.marshall(oidcConfig.getAuthorizationEndpoint(), AUTHORIZATIONENDPOINT_BINDING);
            protocolMarshaller.marshall(oidcConfig.getTokenEndpoint(), TOKENENDPOINT_BINDING);
            protocolMarshaller.marshall(oidcConfig.getUserInfoEndpoint(), USERINFOENDPOINT_BINDING);
            protocolMarshaller.marshall(oidcConfig.getLogoutEndpoint(), LOGOUTENDPOINT_BINDING);
            protocolMarshaller.marshall(oidcConfig.getJwksUri(), JWKSURI_BINDING);
            protocolMarshaller.marshall(oidcConfig.getScope(), SCOPE_BINDING);
            protocolMarshaller.marshall(oidcConfig.getAuthenticationRequestExtraParams(), AUTHENTICATIONREQUESTEXTRAPARAMS_BINDING);
        } catch (Exception e) {
            throw new SdkClientException("Unable to marshall request to JSON: " + e.getMessage(), e);
        }
    }

}
