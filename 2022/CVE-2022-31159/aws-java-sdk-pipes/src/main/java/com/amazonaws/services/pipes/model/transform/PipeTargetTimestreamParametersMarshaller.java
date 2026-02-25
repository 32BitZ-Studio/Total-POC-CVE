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

import java.util.List;
import javax.annotation.Generated;

import com.amazonaws.SdkClientException;
import com.amazonaws.services.pipes.model.*;

import com.amazonaws.protocol.*;
import com.amazonaws.annotation.SdkInternalApi;

/**
 * PipeTargetTimestreamParametersMarshaller
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
@SdkInternalApi
public class PipeTargetTimestreamParametersMarshaller {

    private static final MarshallingInfo<String> TIMEVALUE_BINDING = MarshallingInfo.builder(MarshallingType.STRING).marshallLocation(MarshallLocation.PAYLOAD)
            .marshallLocationName("TimeValue").build();
    private static final MarshallingInfo<String> EPOCHTIMEUNIT_BINDING = MarshallingInfo.builder(MarshallingType.STRING)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("EpochTimeUnit").build();
    private static final MarshallingInfo<String> TIMEFIELDTYPE_BINDING = MarshallingInfo.builder(MarshallingType.STRING)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("TimeFieldType").build();
    private static final MarshallingInfo<String> TIMESTAMPFORMAT_BINDING = MarshallingInfo.builder(MarshallingType.STRING)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("TimestampFormat").build();
    private static final MarshallingInfo<String> VERSIONVALUE_BINDING = MarshallingInfo.builder(MarshallingType.STRING)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("VersionValue").build();
    private static final MarshallingInfo<List> DIMENSIONMAPPINGS_BINDING = MarshallingInfo.builder(MarshallingType.LIST)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("DimensionMappings").build();
    private static final MarshallingInfo<List> SINGLEMEASUREMAPPINGS_BINDING = MarshallingInfo.builder(MarshallingType.LIST)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("SingleMeasureMappings").build();
    private static final MarshallingInfo<List> MULTIMEASUREMAPPINGS_BINDING = MarshallingInfo.builder(MarshallingType.LIST)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("MultiMeasureMappings").build();

    private static final PipeTargetTimestreamParametersMarshaller instance = new PipeTargetTimestreamParametersMarshaller();

    public static PipeTargetTimestreamParametersMarshaller getInstance() {
        return instance;
    }

    /**
     * Marshall the given parameter object.
     */
    public void marshall(PipeTargetTimestreamParameters pipeTargetTimestreamParameters, ProtocolMarshaller protocolMarshaller) {

        if (pipeTargetTimestreamParameters == null) {
            throw new SdkClientException("Invalid argument passed to marshall(...)");
        }

        try {
            protocolMarshaller.marshall(pipeTargetTimestreamParameters.getTimeValue(), TIMEVALUE_BINDING);
            protocolMarshaller.marshall(pipeTargetTimestreamParameters.getEpochTimeUnit(), EPOCHTIMEUNIT_BINDING);
            protocolMarshaller.marshall(pipeTargetTimestreamParameters.getTimeFieldType(), TIMEFIELDTYPE_BINDING);
            protocolMarshaller.marshall(pipeTargetTimestreamParameters.getTimestampFormat(), TIMESTAMPFORMAT_BINDING);
            protocolMarshaller.marshall(pipeTargetTimestreamParameters.getVersionValue(), VERSIONVALUE_BINDING);
            protocolMarshaller.marshall(pipeTargetTimestreamParameters.getDimensionMappings(), DIMENSIONMAPPINGS_BINDING);
            protocolMarshaller.marshall(pipeTargetTimestreamParameters.getSingleMeasureMappings(), SINGLEMEASUREMAPPINGS_BINDING);
            protocolMarshaller.marshall(pipeTargetTimestreamParameters.getMultiMeasureMappings(), MULTIMEASUREMAPPINGS_BINDING);
        } catch (Exception e) {
            throw new SdkClientException("Unable to marshall request to JSON: " + e.getMessage(), e);
        }
    }

}
