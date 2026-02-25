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

import java.util.List;
import javax.annotation.Generated;

import com.amazonaws.SdkClientException;
import com.amazonaws.services.location.model.*;

import com.amazonaws.protocol.*;
import com.amazonaws.annotation.SdkInternalApi;

/**
 * ForecastGeofenceEventsDeviceStateMarshaller
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
@SdkInternalApi
public class ForecastGeofenceEventsDeviceStateMarshaller {

    private static final MarshallingInfo<List> POSITION_BINDING = MarshallingInfo.builder(MarshallingType.LIST).marshallLocation(MarshallLocation.PAYLOAD)
            .marshallLocationName("Position").build();
    private static final MarshallingInfo<Double> SPEED_BINDING = MarshallingInfo.builder(MarshallingType.DOUBLE).marshallLocation(MarshallLocation.PAYLOAD)
            .marshallLocationName("Speed").build();

    private static final ForecastGeofenceEventsDeviceStateMarshaller instance = new ForecastGeofenceEventsDeviceStateMarshaller();

    public static ForecastGeofenceEventsDeviceStateMarshaller getInstance() {
        return instance;
    }

    /**
     * Marshall the given parameter object.
     */
    public void marshall(ForecastGeofenceEventsDeviceState forecastGeofenceEventsDeviceState, ProtocolMarshaller protocolMarshaller) {

        if (forecastGeofenceEventsDeviceState == null) {
            throw new SdkClientException("Invalid argument passed to marshall(...)");
        }

        try {
            protocolMarshaller.marshall(forecastGeofenceEventsDeviceState.getPosition(), POSITION_BINDING);
            protocolMarshaller.marshall(forecastGeofenceEventsDeviceState.getSpeed(), SPEED_BINDING);
        } catch (Exception e) {
            throw new SdkClientException("Unable to marshall request to JSON: " + e.getMessage(), e);
        }
    }

}
