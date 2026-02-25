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
 * ItalyAdditionalInfoMarshaller
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
@SdkInternalApi
public class ItalyAdditionalInfoMarshaller {

    private static final MarshallingInfo<String> CIGNUMBER_BINDING = MarshallingInfo.builder(MarshallingType.STRING).marshallLocation(MarshallLocation.PAYLOAD)
            .marshallLocationName("cigNumber").build();
    private static final MarshallingInfo<String> CUPNUMBER_BINDING = MarshallingInfo.builder(MarshallingType.STRING).marshallLocation(MarshallLocation.PAYLOAD)
            .marshallLocationName("cupNumber").build();
    private static final MarshallingInfo<String> SDIACCOUNTID_BINDING = MarshallingInfo.builder(MarshallingType.STRING)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("sdiAccountId").build();
    private static final MarshallingInfo<String> TAXCODE_BINDING = MarshallingInfo.builder(MarshallingType.STRING).marshallLocation(MarshallLocation.PAYLOAD)
            .marshallLocationName("taxCode").build();

    private static final ItalyAdditionalInfoMarshaller instance = new ItalyAdditionalInfoMarshaller();

    public static ItalyAdditionalInfoMarshaller getInstance() {
        return instance;
    }

    /**
     * Marshall the given parameter object.
     */
    public void marshall(ItalyAdditionalInfo italyAdditionalInfo, ProtocolMarshaller protocolMarshaller) {

        if (italyAdditionalInfo == null) {
            throw new SdkClientException("Invalid argument passed to marshall(...)");
        }

        try {
            protocolMarshaller.marshall(italyAdditionalInfo.getCigNumber(), CIGNUMBER_BINDING);
            protocolMarshaller.marshall(italyAdditionalInfo.getCupNumber(), CUPNUMBER_BINDING);
            protocolMarshaller.marshall(italyAdditionalInfo.getSdiAccountId(), SDIACCOUNTID_BINDING);
            protocolMarshaller.marshall(italyAdditionalInfo.getTaxCode(), TAXCODE_BINDING);
        } catch (Exception e) {
            throw new SdkClientException("Unable to marshall request to JSON: " + e.getMessage(), e);
        }
    }

}
