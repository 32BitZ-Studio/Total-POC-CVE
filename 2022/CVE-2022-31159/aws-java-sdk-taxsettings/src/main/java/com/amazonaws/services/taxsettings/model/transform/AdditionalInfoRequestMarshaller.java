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
 * AdditionalInfoRequestMarshaller
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
@SdkInternalApi
public class AdditionalInfoRequestMarshaller {

    private static final MarshallingInfo<StructuredPojo> CANADAADDITIONALINFO_BINDING = MarshallingInfo.builder(MarshallingType.STRUCTURED)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("canadaAdditionalInfo").build();
    private static final MarshallingInfo<StructuredPojo> ESTONIAADDITIONALINFO_BINDING = MarshallingInfo.builder(MarshallingType.STRUCTURED)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("estoniaAdditionalInfo").build();
    private static final MarshallingInfo<StructuredPojo> GEORGIAADDITIONALINFO_BINDING = MarshallingInfo.builder(MarshallingType.STRUCTURED)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("georgiaAdditionalInfo").build();
    private static final MarshallingInfo<StructuredPojo> ISRAELADDITIONALINFO_BINDING = MarshallingInfo.builder(MarshallingType.STRUCTURED)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("israelAdditionalInfo").build();
    private static final MarshallingInfo<StructuredPojo> ITALYADDITIONALINFO_BINDING = MarshallingInfo.builder(MarshallingType.STRUCTURED)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("italyAdditionalInfo").build();
    private static final MarshallingInfo<StructuredPojo> KENYAADDITIONALINFO_BINDING = MarshallingInfo.builder(MarshallingType.STRUCTURED)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("kenyaAdditionalInfo").build();
    private static final MarshallingInfo<StructuredPojo> MALAYSIAADDITIONALINFO_BINDING = MarshallingInfo.builder(MarshallingType.STRUCTURED)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("malaysiaAdditionalInfo").build();
    private static final MarshallingInfo<StructuredPojo> POLANDADDITIONALINFO_BINDING = MarshallingInfo.builder(MarshallingType.STRUCTURED)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("polandAdditionalInfo").build();
    private static final MarshallingInfo<StructuredPojo> ROMANIAADDITIONALINFO_BINDING = MarshallingInfo.builder(MarshallingType.STRUCTURED)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("romaniaAdditionalInfo").build();
    private static final MarshallingInfo<StructuredPojo> SAUDIARABIAADDITIONALINFO_BINDING = MarshallingInfo.builder(MarshallingType.STRUCTURED)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("saudiArabiaAdditionalInfo").build();
    private static final MarshallingInfo<StructuredPojo> SOUTHKOREAADDITIONALINFO_BINDING = MarshallingInfo.builder(MarshallingType.STRUCTURED)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("southKoreaAdditionalInfo").build();
    private static final MarshallingInfo<StructuredPojo> SPAINADDITIONALINFO_BINDING = MarshallingInfo.builder(MarshallingType.STRUCTURED)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("spainAdditionalInfo").build();
    private static final MarshallingInfo<StructuredPojo> TURKEYADDITIONALINFO_BINDING = MarshallingInfo.builder(MarshallingType.STRUCTURED)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("turkeyAdditionalInfo").build();
    private static final MarshallingInfo<StructuredPojo> UKRAINEADDITIONALINFO_BINDING = MarshallingInfo.builder(MarshallingType.STRUCTURED)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("ukraineAdditionalInfo").build();

    private static final AdditionalInfoRequestMarshaller instance = new AdditionalInfoRequestMarshaller();

    public static AdditionalInfoRequestMarshaller getInstance() {
        return instance;
    }

    /**
     * Marshall the given parameter object.
     */
    public void marshall(AdditionalInfoRequest additionalInfoRequest, ProtocolMarshaller protocolMarshaller) {

        if (additionalInfoRequest == null) {
            throw new SdkClientException("Invalid argument passed to marshall(...)");
        }

        try {
            protocolMarshaller.marshall(additionalInfoRequest.getCanadaAdditionalInfo(), CANADAADDITIONALINFO_BINDING);
            protocolMarshaller.marshall(additionalInfoRequest.getEstoniaAdditionalInfo(), ESTONIAADDITIONALINFO_BINDING);
            protocolMarshaller.marshall(additionalInfoRequest.getGeorgiaAdditionalInfo(), GEORGIAADDITIONALINFO_BINDING);
            protocolMarshaller.marshall(additionalInfoRequest.getIsraelAdditionalInfo(), ISRAELADDITIONALINFO_BINDING);
            protocolMarshaller.marshall(additionalInfoRequest.getItalyAdditionalInfo(), ITALYADDITIONALINFO_BINDING);
            protocolMarshaller.marshall(additionalInfoRequest.getKenyaAdditionalInfo(), KENYAADDITIONALINFO_BINDING);
            protocolMarshaller.marshall(additionalInfoRequest.getMalaysiaAdditionalInfo(), MALAYSIAADDITIONALINFO_BINDING);
            protocolMarshaller.marshall(additionalInfoRequest.getPolandAdditionalInfo(), POLANDADDITIONALINFO_BINDING);
            protocolMarshaller.marshall(additionalInfoRequest.getRomaniaAdditionalInfo(), ROMANIAADDITIONALINFO_BINDING);
            protocolMarshaller.marshall(additionalInfoRequest.getSaudiArabiaAdditionalInfo(), SAUDIARABIAADDITIONALINFO_BINDING);
            protocolMarshaller.marshall(additionalInfoRequest.getSouthKoreaAdditionalInfo(), SOUTHKOREAADDITIONALINFO_BINDING);
            protocolMarshaller.marshall(additionalInfoRequest.getSpainAdditionalInfo(), SPAINADDITIONALINFO_BINDING);
            protocolMarshaller.marshall(additionalInfoRequest.getTurkeyAdditionalInfo(), TURKEYADDITIONALINFO_BINDING);
            protocolMarshaller.marshall(additionalInfoRequest.getUkraineAdditionalInfo(), UKRAINEADDITIONALINFO_BINDING);
        } catch (Exception e) {
            throw new SdkClientException("Unable to marshall request to JSON: " + e.getMessage(), e);
        }
    }

}
