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
package com.amazonaws.services.pipes.model.transform;

import javax.annotation.Generated;

import com.amazonaws.SdkClientException;
import com.amazonaws.services.pipes.model.*;

import com.amazonaws.protocol.*;
import com.amazonaws.annotation.SdkInternalApi;

/**
 * SingleMeasureMappingMarshaller
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
@SdkInternalApi
public class SingleMeasureMappingMarshaller {

    private static final MarshallingInfo<String> MEASUREVALUE_BINDING = MarshallingInfo.builder(MarshallingType.STRING)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("MeasureValue").build();
    private static final MarshallingInfo<String> MEASUREVALUETYPE_BINDING = MarshallingInfo.builder(MarshallingType.STRING)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("MeasureValueType").build();
    private static final MarshallingInfo<String> MEASURENAME_BINDING = MarshallingInfo.builder(MarshallingType.STRING)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("MeasureName").build();

    private static final SingleMeasureMappingMarshaller instance = new SingleMeasureMappingMarshaller();

    public static SingleMeasureMappingMarshaller getInstance() {
        return instance;
    }

    /**
     * Marshall the given parameter object.
     */
    public void marshall(SingleMeasureMapping singleMeasureMapping, ProtocolMarshaller protocolMarshaller) {

        if (singleMeasureMapping == null) {
            throw new SdkClientException("Invalid argument passed to marshall(...)");
        }

        try {
            protocolMarshaller.marshall(singleMeasureMapping.getMeasureValue(), MEASUREVALUE_BINDING);
            protocolMarshaller.marshall(singleMeasureMapping.getMeasureValueType(), MEASUREVALUETYPE_BINDING);
            protocolMarshaller.marshall(singleMeasureMapping.getMeasureName(), MEASURENAME_BINDING);
        } catch (Exception e) {
            throw new SdkClientException("Unable to marshall request to JSON: " + e.getMessage(), e);
        }
    }

}
