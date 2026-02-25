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
package com.amazonaws.services.quicksight.model.transform;

import javax.annotation.Generated;

import com.amazonaws.SdkClientException;
import com.amazonaws.services.quicksight.model.*;

import com.amazonaws.protocol.*;
import com.amazonaws.annotation.SdkInternalApi;

/**
 * NestedFilterMarshaller
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
@SdkInternalApi
public class NestedFilterMarshaller {

    private static final MarshallingInfo<String> FILTERID_BINDING = MarshallingInfo.builder(MarshallingType.STRING).marshallLocation(MarshallLocation.PAYLOAD)
            .marshallLocationName("FilterId").build();
    private static final MarshallingInfo<StructuredPojo> COLUMN_BINDING = MarshallingInfo.builder(MarshallingType.STRUCTURED)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("Column").build();
    private static final MarshallingInfo<Boolean> INCLUDEINNERSET_BINDING = MarshallingInfo.builder(MarshallingType.BOOLEAN)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("IncludeInnerSet").build();
    private static final MarshallingInfo<StructuredPojo> INNERFILTER_BINDING = MarshallingInfo.builder(MarshallingType.STRUCTURED)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("InnerFilter").build();

    private static final NestedFilterMarshaller instance = new NestedFilterMarshaller();

    public static NestedFilterMarshaller getInstance() {
        return instance;
    }

    /**
     * Marshall the given parameter object.
     */
    public void marshall(NestedFilter nestedFilter, ProtocolMarshaller protocolMarshaller) {

        if (nestedFilter == null) {
            throw new SdkClientException("Invalid argument passed to marshall(...)");
        }

        try {
            protocolMarshaller.marshall(nestedFilter.getFilterId(), FILTERID_BINDING);
            protocolMarshaller.marshall(nestedFilter.getColumn(), COLUMN_BINDING);
            protocolMarshaller.marshall(nestedFilter.getIncludeInnerSet(), INCLUDEINNERSET_BINDING);
            protocolMarshaller.marshall(nestedFilter.getInnerFilter(), INNERFILTER_BINDING);
        } catch (Exception e) {
            throw new SdkClientException("Unable to marshall request to JSON: " + e.getMessage(), e);
        }
    }

}
