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

import java.util.List;
import javax.annotation.Generated;

import com.amazonaws.SdkClientException;
import com.amazonaws.services.sagemaker.model.*;

import com.amazonaws.protocol.*;
import com.amazonaws.annotation.SdkInternalApi;

/**
 * OptimizationJobSummaryMarshaller
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
@SdkInternalApi
public class OptimizationJobSummaryMarshaller {

    private static final MarshallingInfo<String> OPTIMIZATIONJOBNAME_BINDING = MarshallingInfo.builder(MarshallingType.STRING)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("OptimizationJobName").build();
    private static final MarshallingInfo<String> OPTIMIZATIONJOBARN_BINDING = MarshallingInfo.builder(MarshallingType.STRING)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("OptimizationJobArn").build();
    private static final MarshallingInfo<java.util.Date> CREATIONTIME_BINDING = MarshallingInfo.builder(MarshallingType.DATE)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("CreationTime").timestampFormat("unixTimestamp").build();
    private static final MarshallingInfo<String> OPTIMIZATIONJOBSTATUS_BINDING = MarshallingInfo.builder(MarshallingType.STRING)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("OptimizationJobStatus").build();
    private static final MarshallingInfo<java.util.Date> OPTIMIZATIONSTARTTIME_BINDING = MarshallingInfo.builder(MarshallingType.DATE)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("OptimizationStartTime").timestampFormat("unixTimestamp").build();
    private static final MarshallingInfo<java.util.Date> OPTIMIZATIONENDTIME_BINDING = MarshallingInfo.builder(MarshallingType.DATE)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("OptimizationEndTime").timestampFormat("unixTimestamp").build();
    private static final MarshallingInfo<java.util.Date> LASTMODIFIEDTIME_BINDING = MarshallingInfo.builder(MarshallingType.DATE)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("LastModifiedTime").timestampFormat("unixTimestamp").build();
    private static final MarshallingInfo<String> DEPLOYMENTINSTANCETYPE_BINDING = MarshallingInfo.builder(MarshallingType.STRING)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("DeploymentInstanceType").build();
    private static final MarshallingInfo<List> OPTIMIZATIONTYPES_BINDING = MarshallingInfo.builder(MarshallingType.LIST)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("OptimizationTypes").build();

    private static final OptimizationJobSummaryMarshaller instance = new OptimizationJobSummaryMarshaller();

    public static OptimizationJobSummaryMarshaller getInstance() {
        return instance;
    }

    /**
     * Marshall the given parameter object.
     */
    public void marshall(OptimizationJobSummary optimizationJobSummary, ProtocolMarshaller protocolMarshaller) {

        if (optimizationJobSummary == null) {
            throw new SdkClientException("Invalid argument passed to marshall(...)");
        }

        try {
            protocolMarshaller.marshall(optimizationJobSummary.getOptimizationJobName(), OPTIMIZATIONJOBNAME_BINDING);
            protocolMarshaller.marshall(optimizationJobSummary.getOptimizationJobArn(), OPTIMIZATIONJOBARN_BINDING);
            protocolMarshaller.marshall(optimizationJobSummary.getCreationTime(), CREATIONTIME_BINDING);
            protocolMarshaller.marshall(optimizationJobSummary.getOptimizationJobStatus(), OPTIMIZATIONJOBSTATUS_BINDING);
            protocolMarshaller.marshall(optimizationJobSummary.getOptimizationStartTime(), OPTIMIZATIONSTARTTIME_BINDING);
            protocolMarshaller.marshall(optimizationJobSummary.getOptimizationEndTime(), OPTIMIZATIONENDTIME_BINDING);
            protocolMarshaller.marshall(optimizationJobSummary.getLastModifiedTime(), LASTMODIFIEDTIME_BINDING);
            protocolMarshaller.marshall(optimizationJobSummary.getDeploymentInstanceType(), DEPLOYMENTINSTANCETYPE_BINDING);
            protocolMarshaller.marshall(optimizationJobSummary.getOptimizationTypes(), OPTIMIZATIONTYPES_BINDING);
        } catch (Exception e) {
            throw new SdkClientException("Unable to marshall request to JSON: " + e.getMessage(), e);
        }
    }

}
