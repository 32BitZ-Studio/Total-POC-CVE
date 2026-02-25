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

import java.util.Map;

import javax.annotation.Generated;

import com.amazonaws.SdkClientException;
import com.amazonaws.services.quicksight.model.*;

import com.amazonaws.protocol.*;
import com.amazonaws.annotation.SdkInternalApi;

/**
 * AggFunctionMarshaller
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
@SdkInternalApi
public class AggFunctionMarshaller {

    private static final MarshallingInfo<String> AGGREGATION_BINDING = MarshallingInfo.builder(MarshallingType.STRING)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("Aggregation").build();
    private static final MarshallingInfo<Map> AGGREGATIONFUNCTIONPARAMETERS_BINDING = MarshallingInfo.builder(MarshallingType.MAP)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("AggregationFunctionParameters").build();
    private static final MarshallingInfo<String> PERIOD_BINDING = MarshallingInfo.builder(MarshallingType.STRING).marshallLocation(MarshallLocation.PAYLOAD)
            .marshallLocationName("Period").build();
    private static final MarshallingInfo<String> PERIODFIELD_BINDING = MarshallingInfo.builder(MarshallingType.STRING)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("PeriodField").build();

    private static final AggFunctionMarshaller instance = new AggFunctionMarshaller();

    public static AggFunctionMarshaller getInstance() {
        return instance;
    }

    /**
     * Marshall the given parameter object.
     */
    public void marshall(AggFunction aggFunction, ProtocolMarshaller protocolMarshaller) {

        if (aggFunction == null) {
            throw new SdkClientException("Invalid argument passed to marshall(...)");
        }

        try {
            protocolMarshaller.marshall(aggFunction.getAggregation(), AGGREGATION_BINDING);
            protocolMarshaller.marshall(aggFunction.getAggregationFunctionParameters(), AGGREGATIONFUNCTIONPARAMETERS_BINDING);
            protocolMarshaller.marshall(aggFunction.getPeriod(), PERIOD_BINDING);
            protocolMarshaller.marshall(aggFunction.getPeriodField(), PERIODFIELD_BINDING);
        } catch (Exception e) {
            throw new SdkClientException("Unable to marshall request to JSON: " + e.getMessage(), e);
        }
    }

}
