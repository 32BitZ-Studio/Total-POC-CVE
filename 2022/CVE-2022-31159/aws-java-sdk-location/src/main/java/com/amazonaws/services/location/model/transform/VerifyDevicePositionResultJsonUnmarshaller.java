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

import java.math.*;

import javax.annotation.Generated;

import com.amazonaws.services.location.model.*;
import com.amazonaws.transform.SimpleTypeJsonUnmarshallers.*;
import com.amazonaws.transform.*;

import com.fasterxml.jackson.core.JsonToken;
import static com.fasterxml.jackson.core.JsonToken.*;

/**
 * VerifyDevicePositionResult JSON Unmarshaller
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class VerifyDevicePositionResultJsonUnmarshaller implements Unmarshaller<VerifyDevicePositionResult, JsonUnmarshallerContext> {

    public VerifyDevicePositionResult unmarshall(JsonUnmarshallerContext context) throws Exception {
        VerifyDevicePositionResult verifyDevicePositionResult = new VerifyDevicePositionResult();

        int originalDepth = context.getCurrentDepth();
        String currentParentElement = context.getCurrentParentElement();
        int targetDepth = originalDepth + 1;

        JsonToken token = context.getCurrentToken();
        if (token == null)
            token = context.nextToken();
        if (token == VALUE_NULL) {
            return verifyDevicePositionResult;
        }

        while (true) {
            if (token == null)
                break;

            if (token == FIELD_NAME || token == START_OBJECT) {
                if (context.testExpression("InferredState", targetDepth)) {
                    context.nextToken();
                    verifyDevicePositionResult.setInferredState(InferredStateJsonUnmarshaller.getInstance().unmarshall(context));
                }
                if (context.testExpression("DeviceId", targetDepth)) {
                    context.nextToken();
                    verifyDevicePositionResult.setDeviceId(context.getUnmarshaller(String.class).unmarshall(context));
                }
                if (context.testExpression("SampleTime", targetDepth)) {
                    context.nextToken();
                    verifyDevicePositionResult.setSampleTime(DateJsonUnmarshallerFactory.getInstance("iso8601").unmarshall(context));
                }
                if (context.testExpression("ReceivedTime", targetDepth)) {
                    context.nextToken();
                    verifyDevicePositionResult.setReceivedTime(DateJsonUnmarshallerFactory.getInstance("iso8601").unmarshall(context));
                }
                if (context.testExpression("DistanceUnit", targetDepth)) {
                    context.nextToken();
                    verifyDevicePositionResult.setDistanceUnit(context.getUnmarshaller(String.class).unmarshall(context));
                }
            } else if (token == END_ARRAY || token == END_OBJECT) {
                if (context.getLastParsedParentElement() == null || context.getLastParsedParentElement().equals(currentParentElement)) {
                    if (context.getCurrentDepth() <= originalDepth)
                        break;
                }
            }
            token = context.nextToken();
        }

        return verifyDevicePositionResult;
    }

    private static VerifyDevicePositionResultJsonUnmarshaller instance;

    public static VerifyDevicePositionResultJsonUnmarshaller getInstance() {
        if (instance == null)
            instance = new VerifyDevicePositionResultJsonUnmarshaller();
        return instance;
    }
}
