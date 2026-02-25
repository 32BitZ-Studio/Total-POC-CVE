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
package com.amazonaws.services.opensearch.model.transform;

import javax.annotation.Generated;

import com.amazonaws.SdkClientException;
import com.amazonaws.services.opensearch.model.*;

import com.amazonaws.protocol.*;
import com.amazonaws.annotation.SdkInternalApi;

/**
 * JWTOptionsInputMarshaller
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
@SdkInternalApi
public class JWTOptionsInputMarshaller {

    private static final MarshallingInfo<Boolean> ENABLED_BINDING = MarshallingInfo.builder(MarshallingType.BOOLEAN).marshallLocation(MarshallLocation.PAYLOAD)
            .marshallLocationName("Enabled").build();
    private static final MarshallingInfo<String> SUBJECTKEY_BINDING = MarshallingInfo.builder(MarshallingType.STRING)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("SubjectKey").build();
    private static final MarshallingInfo<String> ROLESKEY_BINDING = MarshallingInfo.builder(MarshallingType.STRING).marshallLocation(MarshallLocation.PAYLOAD)
            .marshallLocationName("RolesKey").build();
    private static final MarshallingInfo<String> PUBLICKEY_BINDING = MarshallingInfo.builder(MarshallingType.STRING).marshallLocation(MarshallLocation.PAYLOAD)
            .marshallLocationName("PublicKey").build();

    private static final JWTOptionsInputMarshaller instance = new JWTOptionsInputMarshaller();

    public static JWTOptionsInputMarshaller getInstance() {
        return instance;
    }

    /**
     * Marshall the given parameter object.
     */
    public void marshall(JWTOptionsInput jWTOptionsInput, ProtocolMarshaller protocolMarshaller) {

        if (jWTOptionsInput == null) {
            throw new SdkClientException("Invalid argument passed to marshall(...)");
        }

        try {
            protocolMarshaller.marshall(jWTOptionsInput.getEnabled(), ENABLED_BINDING);
            protocolMarshaller.marshall(jWTOptionsInput.getSubjectKey(), SUBJECTKEY_BINDING);
            protocolMarshaller.marshall(jWTOptionsInput.getRolesKey(), ROLESKEY_BINDING);
            protocolMarshaller.marshall(jWTOptionsInput.getPublicKey(), PUBLICKEY_BINDING);
        } catch (Exception e) {
            throw new SdkClientException("Unable to marshall request to JSON: " + e.getMessage(), e);
        }
    }

}
