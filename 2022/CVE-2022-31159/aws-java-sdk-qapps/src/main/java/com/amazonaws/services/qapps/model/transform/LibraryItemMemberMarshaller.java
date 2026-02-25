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
package com.amazonaws.services.qapps.model.transform;

import java.util.List;
import javax.annotation.Generated;

import com.amazonaws.SdkClientException;
import com.amazonaws.services.qapps.model.*;

import com.amazonaws.protocol.*;
import com.amazonaws.annotation.SdkInternalApi;

/**
 * LibraryItemMemberMarshaller
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
@SdkInternalApi
public class LibraryItemMemberMarshaller {

    private static final MarshallingInfo<String> LIBRARYITEMID_BINDING = MarshallingInfo.builder(MarshallingType.STRING)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("libraryItemId").build();
    private static final MarshallingInfo<String> APPID_BINDING = MarshallingInfo.builder(MarshallingType.STRING).marshallLocation(MarshallLocation.PAYLOAD)
            .marshallLocationName("appId").build();
    private static final MarshallingInfo<Integer> APPVERSION_BINDING = MarshallingInfo.builder(MarshallingType.INTEGER)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("appVersion").build();
    private static final MarshallingInfo<List> CATEGORIES_BINDING = MarshallingInfo.builder(MarshallingType.LIST).marshallLocation(MarshallLocation.PAYLOAD)
            .marshallLocationName("categories").build();
    private static final MarshallingInfo<String> STATUS_BINDING = MarshallingInfo.builder(MarshallingType.STRING).marshallLocation(MarshallLocation.PAYLOAD)
            .marshallLocationName("status").build();
    private static final MarshallingInfo<java.util.Date> CREATEDAT_BINDING = MarshallingInfo.builder(MarshallingType.DATE)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("createdAt").timestampFormat("iso8601").build();
    private static final MarshallingInfo<String> CREATEDBY_BINDING = MarshallingInfo.builder(MarshallingType.STRING).marshallLocation(MarshallLocation.PAYLOAD)
            .marshallLocationName("createdBy").build();
    private static final MarshallingInfo<java.util.Date> UPDATEDAT_BINDING = MarshallingInfo.builder(MarshallingType.DATE)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("updatedAt").timestampFormat("iso8601").build();
    private static final MarshallingInfo<String> UPDATEDBY_BINDING = MarshallingInfo.builder(MarshallingType.STRING).marshallLocation(MarshallLocation.PAYLOAD)
            .marshallLocationName("updatedBy").build();
    private static final MarshallingInfo<Integer> RATINGCOUNT_BINDING = MarshallingInfo.builder(MarshallingType.INTEGER)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("ratingCount").build();
    private static final MarshallingInfo<Boolean> ISRATEDBYUSER_BINDING = MarshallingInfo.builder(MarshallingType.BOOLEAN)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("isRatedByUser").build();
    private static final MarshallingInfo<Integer> USERCOUNT_BINDING = MarshallingInfo.builder(MarshallingType.INTEGER)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("userCount").build();

    private static final LibraryItemMemberMarshaller instance = new LibraryItemMemberMarshaller();

    public static LibraryItemMemberMarshaller getInstance() {
        return instance;
    }

    /**
     * Marshall the given parameter object.
     */
    public void marshall(LibraryItemMember libraryItemMember, ProtocolMarshaller protocolMarshaller) {

        if (libraryItemMember == null) {
            throw new SdkClientException("Invalid argument passed to marshall(...)");
        }

        try {
            protocolMarshaller.marshall(libraryItemMember.getLibraryItemId(), LIBRARYITEMID_BINDING);
            protocolMarshaller.marshall(libraryItemMember.getAppId(), APPID_BINDING);
            protocolMarshaller.marshall(libraryItemMember.getAppVersion(), APPVERSION_BINDING);
            protocolMarshaller.marshall(libraryItemMember.getCategories(), CATEGORIES_BINDING);
            protocolMarshaller.marshall(libraryItemMember.getStatus(), STATUS_BINDING);
            protocolMarshaller.marshall(libraryItemMember.getCreatedAt(), CREATEDAT_BINDING);
            protocolMarshaller.marshall(libraryItemMember.getCreatedBy(), CREATEDBY_BINDING);
            protocolMarshaller.marshall(libraryItemMember.getUpdatedAt(), UPDATEDAT_BINDING);
            protocolMarshaller.marshall(libraryItemMember.getUpdatedBy(), UPDATEDBY_BINDING);
            protocolMarshaller.marshall(libraryItemMember.getRatingCount(), RATINGCOUNT_BINDING);
            protocolMarshaller.marshall(libraryItemMember.getIsRatedByUser(), ISRATEDBYUSER_BINDING);
            protocolMarshaller.marshall(libraryItemMember.getUserCount(), USERCOUNT_BINDING);
        } catch (Exception e) {
            throw new SdkClientException("Unable to marshall request to JSON: " + e.getMessage(), e);
        }
    }

}
