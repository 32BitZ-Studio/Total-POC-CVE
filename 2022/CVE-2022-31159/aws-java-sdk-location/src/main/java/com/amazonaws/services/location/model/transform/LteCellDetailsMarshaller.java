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
 * LteCellDetailsMarshaller
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
@SdkInternalApi
public class LteCellDetailsMarshaller {

    private static final MarshallingInfo<Integer> CELLID_BINDING = MarshallingInfo.builder(MarshallingType.INTEGER).marshallLocation(MarshallLocation.PAYLOAD)
            .marshallLocationName("CellId").build();
    private static final MarshallingInfo<Integer> MCC_BINDING = MarshallingInfo.builder(MarshallingType.INTEGER).marshallLocation(MarshallLocation.PAYLOAD)
            .marshallLocationName("Mcc").build();
    private static final MarshallingInfo<Integer> MNC_BINDING = MarshallingInfo.builder(MarshallingType.INTEGER).marshallLocation(MarshallLocation.PAYLOAD)
            .marshallLocationName("Mnc").build();
    private static final MarshallingInfo<StructuredPojo> LOCALID_BINDING = MarshallingInfo.builder(MarshallingType.STRUCTURED)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("LocalId").build();
    private static final MarshallingInfo<List> NETWORKMEASUREMENTS_BINDING = MarshallingInfo.builder(MarshallingType.LIST)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("NetworkMeasurements").build();
    private static final MarshallingInfo<Integer> TIMINGADVANCE_BINDING = MarshallingInfo.builder(MarshallingType.INTEGER)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("TimingAdvance").build();
    private static final MarshallingInfo<Boolean> NRCAPABLE_BINDING = MarshallingInfo.builder(MarshallingType.BOOLEAN)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("NrCapable").build();
    private static final MarshallingInfo<Integer> RSRP_BINDING = MarshallingInfo.builder(MarshallingType.INTEGER).marshallLocation(MarshallLocation.PAYLOAD)
            .marshallLocationName("Rsrp").build();
    private static final MarshallingInfo<Float> RSRQ_BINDING = MarshallingInfo.builder(MarshallingType.FLOAT).marshallLocation(MarshallLocation.PAYLOAD)
            .marshallLocationName("Rsrq").build();
    private static final MarshallingInfo<Integer> TAC_BINDING = MarshallingInfo.builder(MarshallingType.INTEGER).marshallLocation(MarshallLocation.PAYLOAD)
            .marshallLocationName("Tac").build();

    private static final LteCellDetailsMarshaller instance = new LteCellDetailsMarshaller();

    public static LteCellDetailsMarshaller getInstance() {
        return instance;
    }

    /**
     * Marshall the given parameter object.
     */
    public void marshall(LteCellDetails lteCellDetails, ProtocolMarshaller protocolMarshaller) {

        if (lteCellDetails == null) {
            throw new SdkClientException("Invalid argument passed to marshall(...)");
        }

        try {
            protocolMarshaller.marshall(lteCellDetails.getCellId(), CELLID_BINDING);
            protocolMarshaller.marshall(lteCellDetails.getMcc(), MCC_BINDING);
            protocolMarshaller.marshall(lteCellDetails.getMnc(), MNC_BINDING);
            protocolMarshaller.marshall(lteCellDetails.getLocalId(), LOCALID_BINDING);
            protocolMarshaller.marshall(lteCellDetails.getNetworkMeasurements(), NETWORKMEASUREMENTS_BINDING);
            protocolMarshaller.marshall(lteCellDetails.getTimingAdvance(), TIMINGADVANCE_BINDING);
            protocolMarshaller.marshall(lteCellDetails.getNrCapable(), NRCAPABLE_BINDING);
            protocolMarshaller.marshall(lteCellDetails.getRsrp(), RSRP_BINDING);
            protocolMarshaller.marshall(lteCellDetails.getRsrq(), RSRQ_BINDING);
            protocolMarshaller.marshall(lteCellDetails.getTac(), TAC_BINDING);
        } catch (Exception e) {
            throw new SdkClientException("Unable to marshall request to JSON: " + e.getMessage(), e);
        }
    }

}
