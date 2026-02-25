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
 * DeviceStateMarshaller
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
@SdkInternalApi
public class DeviceStateMarshaller {

    private static final MarshallingInfo<String> DEVICEID_BINDING = MarshallingInfo.builder(MarshallingType.STRING).marshallLocation(MarshallLocation.PAYLOAD)
            .marshallLocationName("DeviceId").build();
    private static final MarshallingInfo<java.util.Date> SAMPLETIME_BINDING = MarshallingInfo.builder(MarshallingType.DATE)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("SampleTime").timestampFormat("iso8601").build();
    private static final MarshallingInfo<List> POSITION_BINDING = MarshallingInfo.builder(MarshallingType.LIST).marshallLocation(MarshallLocation.PAYLOAD)
            .marshallLocationName("Position").build();
    private static final MarshallingInfo<StructuredPojo> ACCURACY_BINDING = MarshallingInfo.builder(MarshallingType.STRUCTURED)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("Accuracy").build();
    private static final MarshallingInfo<String> IPV4ADDRESS_BINDING = MarshallingInfo.builder(MarshallingType.STRING)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("Ipv4Address").build();
    private static final MarshallingInfo<List> WIFIACCESSPOINTS_BINDING = MarshallingInfo.builder(MarshallingType.LIST)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("WiFiAccessPoints").build();
    private static final MarshallingInfo<StructuredPojo> CELLSIGNALS_BINDING = MarshallingInfo.builder(MarshallingType.STRUCTURED)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("CellSignals").build();

    private static final DeviceStateMarshaller instance = new DeviceStateMarshaller();

    public static DeviceStateMarshaller getInstance() {
        return instance;
    }

    /**
     * Marshall the given parameter object.
     */
    public void marshall(DeviceState deviceState, ProtocolMarshaller protocolMarshaller) {

        if (deviceState == null) {
            throw new SdkClientException("Invalid argument passed to marshall(...)");
        }

        try {
            protocolMarshaller.marshall(deviceState.getDeviceId(), DEVICEID_BINDING);
            protocolMarshaller.marshall(deviceState.getSampleTime(), SAMPLETIME_BINDING);
            protocolMarshaller.marshall(deviceState.getPosition(), POSITION_BINDING);
            protocolMarshaller.marshall(deviceState.getAccuracy(), ACCURACY_BINDING);
            protocolMarshaller.marshall(deviceState.getIpv4Address(), IPV4ADDRESS_BINDING);
            protocolMarshaller.marshall(deviceState.getWiFiAccessPoints(), WIFIACCESSPOINTS_BINDING);
            protocolMarshaller.marshall(deviceState.getCellSignals(), CELLSIGNALS_BINDING);
        } catch (Exception e) {
            throw new SdkClientException("Unable to marshall request to JSON: " + e.getMessage(), e);
        }
    }

}
