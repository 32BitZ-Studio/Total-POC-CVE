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

import java.util.Map;
import java.util.List;
import javax.annotation.Generated;

import com.amazonaws.SdkClientException;
import com.amazonaws.services.sagemaker.model.*;

import com.amazonaws.protocol.*;
import com.amazonaws.annotation.SdkInternalApi;

/**
 * CreateOptimizationJobRequestMarshaller
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
@SdkInternalApi
public class CreateOptimizationJobRequestMarshaller {

    private static final MarshallingInfo<String> OPTIMIZATIONJOBNAME_BINDING = MarshallingInfo.builder(MarshallingType.STRING)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("OptimizationJobName").build();
    private static final MarshallingInfo<String> ROLEARN_BINDING = MarshallingInfo.builder(MarshallingType.STRING).marshallLocation(MarshallLocation.PAYLOAD)
            .marshallLocationName("RoleArn").build();
    private static final MarshallingInfo<StructuredPojo> MODELSOURCE_BINDING = MarshallingInfo.builder(MarshallingType.STRUCTURED)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("ModelSource").build();
    private static final MarshallingInfo<String> DEPLOYMENTINSTANCETYPE_BINDING = MarshallingInfo.builder(MarshallingType.STRING)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("DeploymentInstanceType").build();
    private static final MarshallingInfo<Map> OPTIMIZATIONENVIRONMENT_BINDING = MarshallingInfo.builder(MarshallingType.MAP)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("OptimizationEnvironment").build();
    private static final MarshallingInfo<List> OPTIMIZATIONCONFIGS_BINDING = MarshallingInfo.builder(MarshallingType.LIST)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("OptimizationConfigs").build();
    private static final MarshallingInfo<StructuredPojo> OUTPUTCONFIG_BINDING = MarshallingInfo.builder(MarshallingType.STRUCTURED)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("OutputConfig").build();
    private static final MarshallingInfo<StructuredPojo> STOPPINGCONDITION_BINDING = MarshallingInfo.builder(MarshallingType.STRUCTURED)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("StoppingCondition").build();
    private static final MarshallingInfo<List> TAGS_BINDING = MarshallingInfo.builder(MarshallingType.LIST).marshallLocation(MarshallLocation.PAYLOAD)
            .marshallLocationName("Tags").build();
    private static final MarshallingInfo<StructuredPojo> VPCCONFIG_BINDING = MarshallingInfo.builder(MarshallingType.STRUCTURED)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("VpcConfig").build();

    private static final CreateOptimizationJobRequestMarshaller instance = new CreateOptimizationJobRequestMarshaller();

    public static CreateOptimizationJobRequestMarshaller getInstance() {
        return instance;
    }

    /**
     * Marshall the given parameter object.
     */
    public void marshall(CreateOptimizationJobRequest createOptimizationJobRequest, ProtocolMarshaller protocolMarshaller) {

        if (createOptimizationJobRequest == null) {
            throw new SdkClientException("Invalid argument passed to marshall(...)");
        }

        try {
            protocolMarshaller.marshall(createOptimizationJobRequest.getOptimizationJobName(), OPTIMIZATIONJOBNAME_BINDING);
            protocolMarshaller.marshall(createOptimizationJobRequest.getRoleArn(), ROLEARN_BINDING);
            protocolMarshaller.marshall(createOptimizationJobRequest.getModelSource(), MODELSOURCE_BINDING);
            protocolMarshaller.marshall(createOptimizationJobRequest.getDeploymentInstanceType(), DEPLOYMENTINSTANCETYPE_BINDING);
            protocolMarshaller.marshall(createOptimizationJobRequest.getOptimizationEnvironment(), OPTIMIZATIONENVIRONMENT_BINDING);
            protocolMarshaller.marshall(createOptimizationJobRequest.getOptimizationConfigs(), OPTIMIZATIONCONFIGS_BINDING);
            protocolMarshaller.marshall(createOptimizationJobRequest.getOutputConfig(), OUTPUTCONFIG_BINDING);
            protocolMarshaller.marshall(createOptimizationJobRequest.getStoppingCondition(), STOPPINGCONDITION_BINDING);
            protocolMarshaller.marshall(createOptimizationJobRequest.getTags(), TAGS_BINDING);
            protocolMarshaller.marshall(createOptimizationJobRequest.getVpcConfig(), VPCCONFIG_BINDING);
        } catch (Exception e) {
            throw new SdkClientException("Unable to marshall request to JSON: " + e.getMessage(), e);
        }
    }

}
