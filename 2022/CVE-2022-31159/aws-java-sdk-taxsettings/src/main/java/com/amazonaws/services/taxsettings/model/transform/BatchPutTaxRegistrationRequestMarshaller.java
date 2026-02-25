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

import java.util.List;
import javax.annotation.Generated;

import com.amazonaws.SdkClientException;
import com.amazonaws.services.taxsettings.model.*;

import com.amazonaws.protocol.*;
import com.amazonaws.annotation.SdkInternalApi;

/**
 * BatchPutTaxRegistrationRequestMarshaller
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
@SdkInternalApi
public class BatchPutTaxRegistrationRequestMarshaller {

    private static final MarshallingInfo<List> ACCOUNTIDS_BINDING = MarshallingInfo.builder(MarshallingType.LIST).marshallLocation(MarshallLocation.PAYLOAD)
            .marshallLocationName("accountIds").build();
    private static final MarshallingInfo<StructuredPojo> TAXREGISTRATIONENTRY_BINDING = MarshallingInfo.builder(MarshallingType.STRUCTURED)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("taxRegistrationEntry").build();

    private static final BatchPutTaxRegistrationRequestMarshaller instance = new BatchPutTaxRegistrationRequestMarshaller();

    public static BatchPutTaxRegistrationRequestMarshaller getInstance() {
        return instance;
    }

    /**
     * Marshall the given parameter object.
     */
    public void marshall(BatchPutTaxRegistrationRequest batchPutTaxRegistrationRequest, ProtocolMarshaller protocolMarshaller) {

        if (batchPutTaxRegistrationRequest == null) {
            throw new SdkClientException("Invalid argument passed to marshall(...)");
        }

        try {
            protocolMarshaller.marshall(batchPutTaxRegistrationRequest.getAccountIds(), ACCOUNTIDS_BINDING);
            protocolMarshaller.marshall(batchPutTaxRegistrationRequest.getTaxRegistrationEntry(), TAXREGISTRATIONENTRY_BINDING);
        } catch (Exception e) {
            throw new SdkClientException("Unable to marshall request to JSON: " + e.getMessage(), e);
        }
    }

}
