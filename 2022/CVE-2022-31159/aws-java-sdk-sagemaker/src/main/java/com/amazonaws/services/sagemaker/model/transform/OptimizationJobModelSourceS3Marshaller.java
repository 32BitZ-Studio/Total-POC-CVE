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
 * OptimizationJobModelSourceS3Marshaller
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
@SdkInternalApi
public class OptimizationJobModelSourceS3Marshaller {

    private static final MarshallingInfo<String> S3URI_BINDING = MarshallingInfo.builder(MarshallingType.STRING).marshallLocation(MarshallLocation.PAYLOAD)
            .marshallLocationName("S3Uri").build();
    private static final MarshallingInfo<StructuredPojo> MODELACCESSCONFIG_BINDING = MarshallingInfo.builder(MarshallingType.STRUCTURED)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("ModelAccessConfig").build();

    private static final OptimizationJobModelSourceS3Marshaller instance = new OptimizationJobModelSourceS3Marshaller();

    public static OptimizationJobModelSourceS3Marshaller getInstance() {
        return instance;
    }

    /**
     * Marshall the given parameter object.
     */
    public void marshall(OptimizationJobModelSourceS3 optimizationJobModelSourceS3, ProtocolMarshaller protocolMarshaller) {

        if (optimizationJobModelSourceS3 == null) {
            throw new SdkClientException("Invalid argument passed to marshall(...)");
        }

        try {
            protocolMarshaller.marshall(optimizationJobModelSourceS3.getS3Uri(), S3URI_BINDING);
            protocolMarshaller.marshall(optimizationJobModelSourceS3.getModelAccessConfig(), MODELACCESSCONFIG_BINDING);
        } catch (Exception e) {
            throw new SdkClientException("Unable to marshall request to JSON: " + e.getMessage(), e);
        }
    }

}
