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
 * TaxRegistrationEntryMarshaller
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
@SdkInternalApi
public class TaxRegistrationEntryMarshaller {

    private static final MarshallingInfo<StructuredPojo> ADDITIONALTAXINFORMATION_BINDING = MarshallingInfo.builder(MarshallingType.STRUCTURED)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("additionalTaxInformation").build();
    private static final MarshallingInfo<String> CERTIFIEDEMAILID_BINDING = MarshallingInfo.builder(MarshallingType.STRING)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("certifiedEmailId").build();
    private static final MarshallingInfo<StructuredPojo> LEGALADDRESS_BINDING = MarshallingInfo.builder(MarshallingType.STRUCTURED)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("legalAddress").build();
    private static final MarshallingInfo<String> LEGALNAME_BINDING = MarshallingInfo.builder(MarshallingType.STRING).marshallLocation(MarshallLocation.PAYLOAD)
            .marshallLocationName("legalName").build();
    private static final MarshallingInfo<String> REGISTRATIONID_BINDING = MarshallingInfo.builder(MarshallingType.STRING)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("registrationId").build();
    private static final MarshallingInfo<String> REGISTRATIONTYPE_BINDING = MarshallingInfo.builder(MarshallingType.STRING)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("registrationType").build();
    private static final MarshallingInfo<String> SECTOR_BINDING = MarshallingInfo.builder(MarshallingType.STRING).marshallLocation(MarshallLocation.PAYLOAD)
            .marshallLocationName("sector").build();
    private static final MarshallingInfo<StructuredPojo> VERIFICATIONDETAILS_BINDING = MarshallingInfo.builder(MarshallingType.STRUCTURED)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("verificationDetails").build();

    private static final TaxRegistrationEntryMarshaller instance = new TaxRegistrationEntryMarshaller();

    public static TaxRegistrationEntryMarshaller getInstance() {
        return instance;
    }

    /**
     * Marshall the given parameter object.
     */
    public void marshall(TaxRegistrationEntry taxRegistrationEntry, ProtocolMarshaller protocolMarshaller) {

        if (taxRegistrationEntry == null) {
            throw new SdkClientException("Invalid argument passed to marshall(...)");
        }

        try {
            protocolMarshaller.marshall(taxRegistrationEntry.getAdditionalTaxInformation(), ADDITIONALTAXINFORMATION_BINDING);
            protocolMarshaller.marshall(taxRegistrationEntry.getCertifiedEmailId(), CERTIFIEDEMAILID_BINDING);
            protocolMarshaller.marshall(taxRegistrationEntry.getLegalAddress(), LEGALADDRESS_BINDING);
            protocolMarshaller.marshall(taxRegistrationEntry.getLegalName(), LEGALNAME_BINDING);
            protocolMarshaller.marshall(taxRegistrationEntry.getRegistrationId(), REGISTRATIONID_BINDING);
            protocolMarshaller.marshall(taxRegistrationEntry.getRegistrationType(), REGISTRATIONTYPE_BINDING);
            protocolMarshaller.marshall(taxRegistrationEntry.getSector(), SECTOR_BINDING);
            protocolMarshaller.marshall(taxRegistrationEntry.getVerificationDetails(), VERIFICATIONDETAILS_BINDING);
        } catch (Exception e) {
            throw new SdkClientException("Unable to marshall request to JSON: " + e.getMessage(), e);
        }
    }

}
