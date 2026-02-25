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
package com.amazonaws.services.mediaconvert.model.transform;

import javax.annotation.Generated;

import com.amazonaws.SdkClientException;
import com.amazonaws.services.mediaconvert.model.*;

import com.amazonaws.protocol.*;
import com.amazonaws.annotation.SdkInternalApi;

/**
 * InputVideoGeneratorMarshaller
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
@SdkInternalApi
public class InputVideoGeneratorMarshaller {

    private static final MarshallingInfo<Integer> CHANNELS_BINDING = MarshallingInfo.builder(MarshallingType.INTEGER)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("channels").build();
    private static final MarshallingInfo<Integer> DURATION_BINDING = MarshallingInfo.builder(MarshallingType.INTEGER)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("duration").build();
    private static final MarshallingInfo<Integer> FRAMERATEDENOMINATOR_BINDING = MarshallingInfo.builder(MarshallingType.INTEGER)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("framerateDenominator").build();
    private static final MarshallingInfo<Integer> FRAMERATENUMERATOR_BINDING = MarshallingInfo.builder(MarshallingType.INTEGER)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("framerateNumerator").build();
    private static final MarshallingInfo<Integer> SAMPLERATE_BINDING = MarshallingInfo.builder(MarshallingType.INTEGER)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("sampleRate").build();

    private static final InputVideoGeneratorMarshaller instance = new InputVideoGeneratorMarshaller();

    public static InputVideoGeneratorMarshaller getInstance() {
        return instance;
    }

    /**
     * Marshall the given parameter object.
     */
    public void marshall(InputVideoGenerator inputVideoGenerator, ProtocolMarshaller protocolMarshaller) {

        if (inputVideoGenerator == null) {
            throw new SdkClientException("Invalid argument passed to marshall(...)");
        }

        try {
            protocolMarshaller.marshall(inputVideoGenerator.getChannels(), CHANNELS_BINDING);
            protocolMarshaller.marshall(inputVideoGenerator.getDuration(), DURATION_BINDING);
            protocolMarshaller.marshall(inputVideoGenerator.getFramerateDenominator(), FRAMERATEDENOMINATOR_BINDING);
            protocolMarshaller.marshall(inputVideoGenerator.getFramerateNumerator(), FRAMERATENUMERATOR_BINDING);
            protocolMarshaller.marshall(inputVideoGenerator.getSampleRate(), SAMPLERATE_BINDING);
        } catch (Exception e) {
            throw new SdkClientException("Unable to marshall request to JSON: " + e.getMessage(), e);
        }
    }

}
