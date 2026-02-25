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
 * TurkeyAdditionalInfoMarshaller
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
@SdkInternalApi
public class TurkeyAdditionalInfoMarshaller {

    private static final MarshallingInfo<String> INDUSTRIES_BINDING = MarshallingInfo.builder(MarshallingType.STRING)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("industries").build();
    private static final MarshallingInfo<String> KEPEMAILID_BINDING = MarshallingInfo.builder(MarshallingType.STRING)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("kepEmailId").build();
    private static final MarshallingInfo<String> SECONDARYTAXID_BINDING = MarshallingInfo.builder(MarshallingType.STRING)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("secondaryTaxId").build();
    private static final MarshallingInfo<String> TAXOFFICE_BINDING = MarshallingInfo.builder(MarshallingType.STRING).marshallLocation(MarshallLocation.PAYLOAD)
            .marshallLocationName("taxOffice").build();

    private static final TurkeyAdditionalInfoMarshaller instance = new TurkeyAdditionalInfoMarshaller();

    public static TurkeyAdditionalInfoMarshaller getInstance() {
        return instance;
    }

    /**
     * Marshall the given parameter object.
     */
    public void marshall(TurkeyAdditionalInfo turkeyAdditionalInfo, ProtocolMarshaller protocolMarshaller) {

        if (turkeyAdditionalInfo == null) {
            throw new SdkClientException("Invalid argument passed to marshall(...)");
        }

        try {
            protocolMarshaller.marshall(turkeyAdditionalInfo.getIndustries(), INDUSTRIES_BINDING);
            protocolMarshaller.marshall(turkeyAdditionalInfo.getKepEmailId(), KEPEMAILID_BINDING);
            protocolMarshaller.marshall(turkeyAdditionalInfo.getSecondaryTaxId(), SECONDARYTAXID_BINDING);
            protocolMarshaller.marshall(turkeyAdditionalInfo.getTaxOffice(), TAXOFFICE_BINDING);
        } catch (Exception e) {
            throw new SdkClientException("Unable to marshall request to JSON: " + e.getMessage(), e);
        }
    }

}
