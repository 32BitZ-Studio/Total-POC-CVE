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
package com.amazonaws.services.location.model.transform;

import javax.annotation.Generated;

import com.amazonaws.SdkClientException;
import com.amazonaws.services.location.model.*;

import com.amazonaws.protocol.*;
import com.amazonaws.annotation.SdkInternalApi;

/**
 * VerifyDevicePositionRequestMarshaller
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
@SdkInternalApi
public class VerifyDevicePositionRequestMarshaller {

    private static final MarshallingInfo<String> TRACKERNAME_BINDING = MarshallingInfo.builder(MarshallingType.STRING).marshallLocation(MarshallLocation.PATH)
            .marshallLocationName("TrackerName").build();
    private static final MarshallingInfo<StructuredPojo> DEVICESTATE_BINDING = MarshallingInfo.builder(MarshallingType.STRUCTURED)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("DeviceState").build();
    private static final MarshallingInfo<String> DISTANCEUNIT_BINDING = MarshallingInfo.builder(MarshallingType.STRING)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("DistanceUnit").build();

    private static final VerifyDevicePositionRequestMarshaller instance = new VerifyDevicePositionRequestMarshaller();

    public static VerifyDevicePositionRequestMarshaller getInstance() {
        return instance;
    }

    /**
     * Marshall the given parameter object.
     */
    public void marshall(VerifyDevicePositionRequest verifyDevicePositionRequest, ProtocolMarshaller protocolMarshaller) {

        if (verifyDevicePositionRequest == null) {
            throw new SdkClientException("Invalid argument passed to marshall(...)");
        }

        try {
            protocolMarshaller.marshall(verifyDevicePositionRequest.getTrackerName(), TRACKERNAME_BINDING);
            protocolMarshaller.marshall(verifyDevicePositionRequest.getDeviceState(), DEVICESTATE_BINDING);
            protocolMarshaller.marshall(verifyDevicePositionRequest.getDistanceUnit(), DISTANCEUNIT_BINDING);
        } catch (Exception e) {
            throw new SdkClientException("Unable to marshall request to JSON: " + e.getMessage(), e);
        }
    }

}
