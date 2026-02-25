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
package com.amazonaws.services.sagemaker.model.transform;

import javax.annotation.Generated;

import com.amazonaws.SdkClientException;
import com.amazonaws.services.sagemaker.model.*;

import com.amazonaws.protocol.*;
import com.amazonaws.annotation.SdkInternalApi;

/**
 * ListMlflowTrackingServersRequestMarshaller
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
@SdkInternalApi
public class ListMlflowTrackingServersRequestMarshaller {

    private static final MarshallingInfo<java.util.Date> CREATEDAFTER_BINDING = MarshallingInfo.builder(MarshallingType.DATE)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("CreatedAfter").timestampFormat("unixTimestamp").build();
    private static final MarshallingInfo<java.util.Date> CREATEDBEFORE_BINDING = MarshallingInfo.builder(MarshallingType.DATE)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("CreatedBefore").timestampFormat("unixTimestamp").build();
    private static final MarshallingInfo<String> TRACKINGSERVERSTATUS_BINDING = MarshallingInfo.builder(MarshallingType.STRING)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("TrackingServerStatus").build();
    private static final MarshallingInfo<String> MLFLOWVERSION_BINDING = MarshallingInfo.builder(MarshallingType.STRING)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("MlflowVersion").build();
    private static final MarshallingInfo<String> SORTBY_BINDING = MarshallingInfo.builder(MarshallingType.STRING).marshallLocation(MarshallLocation.PAYLOAD)
            .marshallLocationName("SortBy").build();
    private static final MarshallingInfo<String> SORTORDER_BINDING = MarshallingInfo.builder(MarshallingType.STRING).marshallLocation(MarshallLocation.PAYLOAD)
            .marshallLocationName("SortOrder").build();
    private static final MarshallingInfo<String> NEXTTOKEN_BINDING = MarshallingInfo.builder(MarshallingType.STRING).marshallLocation(MarshallLocation.PAYLOAD)
            .marshallLocationName("NextToken").build();
    private static final MarshallingInfo<Integer> MAXRESULTS_BINDING = MarshallingInfo.builder(MarshallingType.INTEGER)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("MaxResults").build();

    private static final ListMlflowTrackingServersRequestMarshaller instance = new ListMlflowTrackingServersRequestMarshaller();

    public static ListMlflowTrackingServersRequestMarshaller getInstance() {
        return instance;
    }

    /**
     * Marshall the given parameter object.
     */
    public void marshall(ListMlflowTrackingServersRequest listMlflowTrackingServersRequest, ProtocolMarshaller protocolMarshaller) {

        if (listMlflowTrackingServersRequest == null) {
            throw new SdkClientException("Invalid argument passed to marshall(...)");
        }

        try {
            protocolMarshaller.marshall(listMlflowTrackingServersRequest.getCreatedAfter(), CREATEDAFTER_BINDING);
            protocolMarshaller.marshall(listMlflowTrackingServersRequest.getCreatedBefore(), CREATEDBEFORE_BINDING);
            protocolMarshaller.marshall(listMlflowTrackingServersRequest.getTrackingServerStatus(), TRACKINGSERVERSTATUS_BINDING);
            protocolMarshaller.marshall(listMlflowTrackingServersRequest.getMlflowVersion(), MLFLOWVERSION_BINDING);
            protocolMarshaller.marshall(listMlflowTrackingServersRequest.getSortBy(), SORTBY_BINDING);
            protocolMarshaller.marshall(listMlflowTrackingServersRequest.getSortOrder(), SORTORDER_BINDING);
            protocolMarshaller.marshall(listMlflowTrackingServersRequest.getNextToken(), NEXTTOKEN_BINDING);
            protocolMarshaller.marshall(listMlflowTrackingServersRequest.getMaxResults(), MAXRESULTS_BINDING);
        } catch (Exception e) {
            throw new SdkClientException("Unable to marshall request to JSON: " + e.getMessage(), e);
        }
    }

}
