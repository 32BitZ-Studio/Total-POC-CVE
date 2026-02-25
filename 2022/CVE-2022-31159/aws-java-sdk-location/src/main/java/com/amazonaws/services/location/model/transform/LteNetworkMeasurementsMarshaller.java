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
 * LteNetworkMeasurementsMarshaller
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
@SdkInternalApi
public class LteNetworkMeasurementsMarshaller {

    private static final MarshallingInfo<Integer> EARFCN_BINDING = MarshallingInfo.builder(MarshallingType.INTEGER).marshallLocation(MarshallLocation.PAYLOAD)
            .marshallLocationName("Earfcn").build();
    private static final MarshallingInfo<Integer> CELLID_BINDING = MarshallingInfo.builder(MarshallingType.INTEGER).marshallLocation(MarshallLocation.PAYLOAD)
            .marshallLocationName("CellId").build();
    private static final MarshallingInfo<Integer> PCI_BINDING = MarshallingInfo.builder(MarshallingType.INTEGER).marshallLocation(MarshallLocation.PAYLOAD)
            .marshallLocationName("Pci").build();
    private static final MarshallingInfo<Integer> RSRP_BINDING = MarshallingInfo.builder(MarshallingType.INTEGER).marshallLocation(MarshallLocation.PAYLOAD)
            .marshallLocationName("Rsrp").build();
    private static final MarshallingInfo<Float> RSRQ_BINDING = MarshallingInfo.builder(MarshallingType.FLOAT).marshallLocation(MarshallLocation.PAYLOAD)
            .marshallLocationName("Rsrq").build();

    private static final LteNetworkMeasurementsMarshaller instance = new LteNetworkMeasurementsMarshaller();

    public static LteNetworkMeasurementsMarshaller getInstance() {
        return instance;
    }

    /**
     * Marshall the given parameter object.
     */
    public void marshall(LteNetworkMeasurements lteNetworkMeasurements, ProtocolMarshaller protocolMarshaller) {

        if (lteNetworkMeasurements == null) {
            throw new SdkClientException("Invalid argument passed to marshall(...)");
        }

        try {
            protocolMarshaller.marshall(lteNetworkMeasurements.getEarfcn(), EARFCN_BINDING);
            protocolMarshaller.marshall(lteNetworkMeasurements.getCellId(), CELLID_BINDING);
            protocolMarshaller.marshall(lteNetworkMeasurements.getPci(), PCI_BINDING);
            protocolMarshaller.marshall(lteNetworkMeasurements.getRsrp(), RSRP_BINDING);
            protocolMarshaller.marshall(lteNetworkMeasurements.getRsrq(), RSRQ_BINDING);
        } catch (Exception e) {
            throw new SdkClientException("Unable to marshall request to JSON: " + e.getMessage(), e);
        }
    }

}
