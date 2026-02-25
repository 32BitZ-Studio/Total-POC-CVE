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

import java.util.Map;

import javax.annotation.Generated;

import com.amazonaws.SdkClientException;
import com.amazonaws.services.taxsettings.model.*;

import com.amazonaws.protocol.*;
import com.amazonaws.annotation.SdkInternalApi;

/**
 * AccountMetaDataMarshaller
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
@SdkInternalApi
public class AccountMetaDataMarshaller {

    private static final MarshallingInfo<String> ACCOUNTNAME_BINDING = MarshallingInfo.builder(MarshallingType.STRING)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("accountName").build();
    private static final MarshallingInfo<StructuredPojo> ADDRESS_BINDING = MarshallingInfo.builder(MarshallingType.STRUCTURED)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("address").build();
    private static final MarshallingInfo<Map> ADDRESSROLEMAP_BINDING = MarshallingInfo.builder(MarshallingType.MAP).marshallLocation(MarshallLocation.PAYLOAD)
            .marshallLocationName("addressRoleMap").build();
    private static final MarshallingInfo<String> ADDRESSTYPE_BINDING = MarshallingInfo.builder(MarshallingType.STRING)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("addressType").build();
    private static final MarshallingInfo<String> SELLER_BINDING = MarshallingInfo.builder(MarshallingType.STRING).marshallLocation(MarshallLocation.PAYLOAD)
            .marshallLocationName("seller").build();

    private static final AccountMetaDataMarshaller instance = new AccountMetaDataMarshaller();

    public static AccountMetaDataMarshaller getInstance() {
        return instance;
    }

    /**
     * Marshall the given parameter object.
     */
    public void marshall(AccountMetaData accountMetaData, ProtocolMarshaller protocolMarshaller) {

        if (accountMetaData == null) {
            throw new SdkClientException("Invalid argument passed to marshall(...)");
        }

        try {
            protocolMarshaller.marshall(accountMetaData.getAccountName(), ACCOUNTNAME_BINDING);
            protocolMarshaller.marshall(accountMetaData.getAddress(), ADDRESS_BINDING);
            protocolMarshaller.marshall(accountMetaData.getAddressRoleMap(), ADDRESSROLEMAP_BINDING);
            protocolMarshaller.marshall(accountMetaData.getAddressType(), ADDRESSTYPE_BINDING);
            protocolMarshaller.marshall(accountMetaData.getSeller(), SELLER_BINDING);
        } catch (Exception e) {
            throw new SdkClientException("Unable to marshall request to JSON: " + e.getMessage(), e);
        }
    }

}
