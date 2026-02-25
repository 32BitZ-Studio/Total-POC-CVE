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
 * LteCellDetails JSON Unmarshaller
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class LteCellDetailsJsonUnmarshaller implements Unmarshaller<LteCellDetails, JsonUnmarshallerContext> {

    public LteCellDetails unmarshall(JsonUnmarshallerContext context) throws Exception {
        LteCellDetails lteCellDetails = new LteCellDetails();

        int originalDepth = context.getCurrentDepth();
        String currentParentElement = context.getCurrentParentElement();
        int targetDepth = originalDepth + 1;

        JsonToken token = context.getCurrentToken();
        if (token == null)
            token = context.nextToken();
        if (token == VALUE_NULL) {
            return null;
        }

        while (true) {
            if (token == null)
                break;

            if (token == FIELD_NAME || token == START_OBJECT) {
                if (context.testExpression("CellId", targetDepth)) {
                    context.nextToken();
                    lteCellDetails.setCellId(context.getUnmarshaller(Integer.class).unmarshall(context));
                }
                if (context.testExpression("Mcc", targetDepth)) {
                    context.nextToken();
                    lteCellDetails.setMcc(context.getUnmarshaller(Integer.class).unmarshall(context));
                }
                if (context.testExpression("Mnc", targetDepth)) {
                    context.nextToken();
                    lteCellDetails.setMnc(context.getUnmarshaller(Integer.class).unmarshall(context));
                }
                if (context.testExpression("LocalId", targetDepth)) {
                    context.nextToken();
                    lteCellDetails.setLocalId(LteLocalIdJsonUnmarshaller.getInstance().unmarshall(context));
                }
                if (context.testExpression("NetworkMeasurements", targetDepth)) {
                    context.nextToken();
                    lteCellDetails.setNetworkMeasurements(new ListUnmarshaller<LteNetworkMeasurements>(LteNetworkMeasurementsJsonUnmarshaller.getInstance())

                    .unmarshall(context));
                }
                if (context.testExpression("TimingAdvance", targetDepth)) {
                    context.nextToken();
                    lteCellDetails.setTimingAdvance(context.getUnmarshaller(Integer.class).unmarshall(context));
                }
                if (context.testExpression("NrCapable", targetDepth)) {
                    context.nextToken();
                    lteCellDetails.setNrCapable(context.getUnmarshaller(Boolean.class).unmarshall(context));
                }
                if (context.testExpression("Rsrp", targetDepth)) {
                    context.nextToken();
                    lteCellDetails.setRsrp(context.getUnmarshaller(Integer.class).unmarshall(context));
                }
                if (context.testExpression("Rsrq", targetDepth)) {
                    context.nextToken();
                    lteCellDetails.setRsrq(context.getUnmarshaller(Float.class).unmarshall(context));
                }
                if (context.testExpression("Tac", targetDepth)) {
                    context.nextToken();
                    lteCellDetails.setTac(context.getUnmarshaller(Integer.class).unmarshall(context));
                }
            } else if (token == END_ARRAY || token == END_OBJECT) {
                if (context.getLastParsedParentElement() == null || context.getLastParsedParentElement().equals(currentParentElement)) {
                    if (context.getCurrentDepth() <= originalDepth)
                        break;
                }
            }
            token = context.nextToken();
        }

        return lteCellDetails;
    }

    private static LteCellDetailsJsonUnmarshaller instance;

    public static LteCellDetailsJsonUnmarshaller getInstance() {
        if (instance == null)
            instance = new LteCellDetailsJsonUnmarshaller();
        return instance;
    }
}
