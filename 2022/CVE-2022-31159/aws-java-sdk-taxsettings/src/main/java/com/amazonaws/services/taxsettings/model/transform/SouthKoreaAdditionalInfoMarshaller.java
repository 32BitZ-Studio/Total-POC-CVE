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
package com.amazonaws.services.taxsettings.model.transform;

import javax.annotation.Generated;

import com.amazonaws.SdkClientException;
import com.amazonaws.services.taxsettings.model.*;

import com.amazonaws.protocol.*;
import com.amazonaws.annotation.SdkInternalApi;

/**
 * SouthKoreaAdditionalInfoMarshaller
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
@SdkInternalApi
public class SouthKoreaAdditionalInfoMarshaller {

    private static final MarshallingInfo<String> BUSINESSREPRESENTATIVENAME_BINDING = MarshallingInfo.builder(MarshallingType.STRING)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("businessRepresentativeName").build();
    private static final MarshallingInfo<String> ITEMOFBUSINESS_BINDING = MarshallingInfo.builder(MarshallingType.STRING)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("itemOfBusiness").build();
    private static final MarshallingInfo<String> LINEOFBUSINESS_BINDING = MarshallingInfo.builder(MarshallingType.STRING)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("lineOfBusiness").build();

    private static final SouthKoreaAdditionalInfoMarshaller instance = new SouthKoreaAdditionalInfoMarshaller();

    public static SouthKoreaAdditionalInfoMarshaller getInstance() {
        return instance;
    }

    /**
     * Marshall the given parameter object.
     */
    public void marshall(SouthKoreaAdditionalInfo southKoreaAdditionalInfo, ProtocolMarshaller protocolMarshaller) {

        if (southKoreaAdditionalInfo == null) {
            throw new SdkClientException("Invalid argument passed to marshall(...)");
        }

        try {
            protocolMarshaller.marshall(southKoreaAdditionalInfo.getBusinessRepresentativeName(), BUSINESSREPRESENTATIVENAME_BINDING);
            protocolMarshaller.marshall(southKoreaAdditionalInfo.getItemOfBusiness(), ITEMOFBUSINESS_BINDING);
            protocolMarshaller.marshall(southKoreaAdditionalInfo.getLineOfBusiness(), LINEOFBUSINESS_BINDING);
        } catch (Exception e) {
            throw new SdkClientException("Unable to marshall request to JSON: " + e.getMessage(), e);
        }
    }

}
