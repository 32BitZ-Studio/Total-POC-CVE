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
 * PutTaxRegistrationRequestMarshaller
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
@SdkInternalApi
public class PutTaxRegistrationRequestMarshaller {

    private static final MarshallingInfo<String> ACCOUNTID_BINDING = MarshallingInfo.builder(MarshallingType.STRING).marshallLocation(MarshallLocation.PAYLOAD)
            .marshallLocationName("accountId").build();
    private static final MarshallingInfo<StructuredPojo> TAXREGISTRATIONENTRY_BINDING = MarshallingInfo.builder(MarshallingType.STRUCTURED)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("taxRegistrationEntry").build();

    private static final PutTaxRegistrationRequestMarshaller instance = new PutTaxRegistrationRequestMarshaller();

    public static PutTaxRegistrationRequestMarshaller getInstance() {
        return instance;
    }

    /**
     * Marshall the given parameter object.
     */
    public void marshall(PutTaxRegistrationRequest putTaxRegistrationRequest, ProtocolMarshaller protocolMarshaller) {

        if (putTaxRegistrationRequest == null) {
            throw new SdkClientException("Invalid argument passed to marshall(...)");
        }

        try {
            protocolMarshaller.marshall(putTaxRegistrationRequest.getAccountId(), ACCOUNTID_BINDING);
            protocolMarshaller.marshall(putTaxRegistrationRequest.getTaxRegistrationEntry(), TAXREGISTRATIONENTRY_BINDING);
        } catch (Exception e) {
            throw new SdkClientException("Unable to marshall request to JSON: " + e.getMessage(), e);
        }
    }

}
