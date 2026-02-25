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

import java.util.Map;

import javax.annotation.Generated;

import com.amazonaws.SdkClientException;
import com.amazonaws.services.location.model.*;

import com.amazonaws.protocol.*;
import com.amazonaws.annotation.SdkInternalApi;

/**
 * ForecastedEventMarshaller
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
@SdkInternalApi
public class ForecastedEventMarshaller {

    private static final MarshallingInfo<String> EVENTID_BINDING = MarshallingInfo.builder(MarshallingType.STRING).marshallLocation(MarshallLocation.PAYLOAD)
            .marshallLocationName("EventId").build();
    private static final MarshallingInfo<String> GEOFENCEID_BINDING = MarshallingInfo.builder(MarshallingType.STRING)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("GeofenceId").build();
    private static final MarshallingInfo<Boolean> ISDEVICEINGEOFENCE_BINDING = MarshallingInfo.builder(MarshallingType.BOOLEAN)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("IsDeviceInGeofence").build();
    private static final MarshallingInfo<Double> NEARESTDISTANCE_BINDING = MarshallingInfo.builder(MarshallingType.DOUBLE)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("NearestDistance").build();
    private static final MarshallingInfo<String> EVENTTYPE_BINDING = MarshallingInfo.builder(MarshallingType.STRING).marshallLocation(MarshallLocation.PAYLOAD)
            .marshallLocationName("EventType").build();
    private static final MarshallingInfo<java.util.Date> FORECASTEDBREACHTIME_BINDING = MarshallingInfo.builder(MarshallingType.DATE)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("ForecastedBreachTime").timestampFormat("iso8601").build();
    private static final MarshallingInfo<Map> GEOFENCEPROPERTIES_BINDING = MarshallingInfo.builder(MarshallingType.MAP)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("GeofenceProperties").build();

    private static final ForecastedEventMarshaller instance = new ForecastedEventMarshaller();

    public static ForecastedEventMarshaller getInstance() {
        return instance;
    }

    /**
     * Marshall the given parameter object.
     */
    public void marshall(ForecastedEvent forecastedEvent, ProtocolMarshaller protocolMarshaller) {

        if (forecastedEvent == null) {
            throw new SdkClientException("Invalid argument passed to marshall(...)");
        }

        try {
            protocolMarshaller.marshall(forecastedEvent.getEventId(), EVENTID_BINDING);
            protocolMarshaller.marshall(forecastedEvent.getGeofenceId(), GEOFENCEID_BINDING);
            protocolMarshaller.marshall(forecastedEvent.getIsDeviceInGeofence(), ISDEVICEINGEOFENCE_BINDING);
            protocolMarshaller.marshall(forecastedEvent.getNearestDistance(), NEARESTDISTANCE_BINDING);
            protocolMarshaller.marshall(forecastedEvent.getEventType(), EVENTTYPE_BINDING);
            protocolMarshaller.marshall(forecastedEvent.getForecastedBreachTime(), FORECASTEDBREACHTIME_BINDING);
            protocolMarshaller.marshall(forecastedEvent.getGeofenceProperties(), GEOFENCEPROPERTIES_BINDING);
        } catch (Exception e) {
            throw new SdkClientException("Unable to marshall request to JSON: " + e.getMessage(), e);
        }
    }

}
