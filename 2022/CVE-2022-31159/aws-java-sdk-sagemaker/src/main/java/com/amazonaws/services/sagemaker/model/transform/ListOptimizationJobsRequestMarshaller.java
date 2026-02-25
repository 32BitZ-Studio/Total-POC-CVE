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
 * ListOptimizationJobsRequestMarshaller
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
@SdkInternalApi
public class ListOptimizationJobsRequestMarshaller {

    private static final MarshallingInfo<String> NEXTTOKEN_BINDING = MarshallingInfo.builder(MarshallingType.STRING).marshallLocation(MarshallLocation.PAYLOAD)
            .marshallLocationName("NextToken").build();
    private static final MarshallingInfo<Integer> MAXRESULTS_BINDING = MarshallingInfo.builder(MarshallingType.INTEGER)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("MaxResults").build();
    private static final MarshallingInfo<java.util.Date> CREATIONTIMEAFTER_BINDING = MarshallingInfo.builder(MarshallingType.DATE)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("CreationTimeAfter").timestampFormat("unixTimestamp").build();
    private static final MarshallingInfo<java.util.Date> CREATIONTIMEBEFORE_BINDING = MarshallingInfo.builder(MarshallingType.DATE)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("CreationTimeBefore").timestampFormat("unixTimestamp").build();
    private static final MarshallingInfo<java.util.Date> LASTMODIFIEDTIMEAFTER_BINDING = MarshallingInfo.builder(MarshallingType.DATE)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("LastModifiedTimeAfter").timestampFormat("unixTimestamp").build();
    private static final MarshallingInfo<java.util.Date> LASTMODIFIEDTIMEBEFORE_BINDING = MarshallingInfo.builder(MarshallingType.DATE)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("LastModifiedTimeBefore").timestampFormat("unixTimestamp").build();
    private static final MarshallingInfo<String> OPTIMIZATIONCONTAINS_BINDING = MarshallingInfo.builder(MarshallingType.STRING)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("OptimizationContains").build();
    private static final MarshallingInfo<String> NAMECONTAINS_BINDING = MarshallingInfo.builder(MarshallingType.STRING)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("NameContains").build();
    private static final MarshallingInfo<String> STATUSEQUALS_BINDING = MarshallingInfo.builder(MarshallingType.STRING)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("StatusEquals").build();
    private static final MarshallingInfo<String> SORTBY_BINDING = MarshallingInfo.builder(MarshallingType.STRING).marshallLocation(MarshallLocation.PAYLOAD)
            .marshallLocationName("SortBy").build();
    private static final MarshallingInfo<String> SORTORDER_BINDING = MarshallingInfo.builder(MarshallingType.STRING).marshallLocation(MarshallLocation.PAYLOAD)
            .marshallLocationName("SortOrder").build();

    private static final ListOptimizationJobsRequestMarshaller instance = new ListOptimizationJobsRequestMarshaller();

    public static ListOptimizationJobsRequestMarshaller getInstance() {
        return instance;
    }

    /**
     * Marshall the given parameter object.
     */
    public void marshall(ListOptimizationJobsRequest listOptimizationJobsRequest, ProtocolMarshaller protocolMarshaller) {

        if (listOptimizationJobsRequest == null) {
            throw new SdkClientException("Invalid argument passed to marshall(...)");
        }

        try {
            protocolMarshaller.marshall(listOptimizationJobsRequest.getNextToken(), NEXTTOKEN_BINDING);
            protocolMarshaller.marshall(listOptimizationJobsRequest.getMaxResults(), MAXRESULTS_BINDING);
            protocolMarshaller.marshall(listOptimizationJobsRequest.getCreationTimeAfter(), CREATIONTIMEAFTER_BINDING);
            protocolMarshaller.marshall(listOptimizationJobsRequest.getCreationTimeBefore(), CREATIONTIMEBEFORE_BINDING);
            protocolMarshaller.marshall(listOptimizationJobsRequest.getLastModifiedTimeAfter(), LASTMODIFIEDTIMEAFTER_BINDING);
            protocolMarshaller.marshall(listOptimizationJobsRequest.getLastModifiedTimeBefore(), LASTMODIFIEDTIMEBEFORE_BINDING);
            protocolMarshaller.marshall(listOptimizationJobsRequest.getOptimizationContains(), OPTIMIZATIONCONTAINS_BINDING);
            protocolMarshaller.marshall(listOptimizationJobsRequest.getNameContains(), NAMECONTAINS_BINDING);
            protocolMarshaller.marshall(listOptimizationJobsRequest.getStatusEquals(), STATUSEQUALS_BINDING);
            protocolMarshaller.marshall(listOptimizationJobsRequest.getSortBy(), SORTBY_BINDING);
            protocolMarshaller.marshall(listOptimizationJobsRequest.getSortOrder(), SORTORDER_BINDING);
        } catch (Exception e) {
            throw new SdkClientException("Unable to marshall request to JSON: " + e.getMessage(), e);
        }
    }

}
