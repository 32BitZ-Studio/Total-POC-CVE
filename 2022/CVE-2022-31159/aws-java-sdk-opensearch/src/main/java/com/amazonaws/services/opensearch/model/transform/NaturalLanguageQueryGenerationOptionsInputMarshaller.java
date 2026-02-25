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
 * NaturalLanguageQueryGenerationOptionsInputMarshaller
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
@SdkInternalApi
public class NaturalLanguageQueryGenerationOptionsInputMarshaller {

    private static final MarshallingInfo<String> DESIREDSTATE_BINDING = MarshallingInfo.builder(MarshallingType.STRING)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("DesiredState").build();

    private static final NaturalLanguageQueryGenerationOptionsInputMarshaller instance = new NaturalLanguageQueryGenerationOptionsInputMarshaller();

    public static NaturalLanguageQueryGenerationOptionsInputMarshaller getInstance() {
        return instance;
    }

    /**
     * Marshall the given parameter object.
     */
    public void marshall(NaturalLanguageQueryGenerationOptionsInput naturalLanguageQueryGenerationOptionsInput, ProtocolMarshaller protocolMarshaller) {

        if (naturalLanguageQueryGenerationOptionsInput == null) {
            throw new SdkClientException("Invalid argument passed to marshall(...)");
        }

        try {
            protocolMarshaller.marshall(naturalLanguageQueryGenerationOptionsInput.getDesiredState(), DESIREDSTATE_BINDING);
        } catch (Exception e) {
            throw new SdkClientException("Unable to marshall request to JSON: " + e.getMessage(), e);
        }
    }

}
