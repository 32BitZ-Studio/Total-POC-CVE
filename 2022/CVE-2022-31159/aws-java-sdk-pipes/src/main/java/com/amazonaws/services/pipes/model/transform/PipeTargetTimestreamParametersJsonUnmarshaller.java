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
package com.amazonaws.services.pipes.model.transform;

import java.math.*;

import javax.annotation.Generated;

import com.amazonaws.services.pipes.model.*;
import com.amazonaws.transform.SimpleTypeJsonUnmarshallers.*;
import com.amazonaws.transform.*;

import com.fasterxml.jackson.core.JsonToken;
import static com.fasterxml.jackson.core.JsonToken.*;

/**
 * PipeTargetTimestreamParameters JSON Unmarshaller
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class PipeTargetTimestreamParametersJsonUnmarshaller implements Unmarshaller<PipeTargetTimestreamParameters, JsonUnmarshallerContext> {

    public PipeTargetTimestreamParameters unmarshall(JsonUnmarshallerContext context) throws Exception {
        PipeTargetTimestreamParameters pipeTargetTimestreamParameters = new PipeTargetTimestreamParameters();

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
                if (context.testExpression("TimeValue", targetDepth)) {
                    context.nextToken();
                    pipeTargetTimestreamParameters.setTimeValue(context.getUnmarshaller(String.class).unmarshall(context));
                }
                if (context.testExpression("EpochTimeUnit", targetDepth)) {
                    context.nextToken();
                    pipeTargetTimestreamParameters.setEpochTimeUnit(context.getUnmarshaller(String.class).unmarshall(context));
                }
                if (context.testExpression("TimeFieldType", targetDepth)) {
                    context.nextToken();
                    pipeTargetTimestreamParameters.setTimeFieldType(context.getUnmarshaller(String.class).unmarshall(context));
                }
                if (context.testExpression("TimestampFormat", targetDepth)) {
                    context.nextToken();
                    pipeTargetTimestreamParameters.setTimestampFormat(context.getUnmarshaller(String.class).unmarshall(context));
                }
                if (context.testExpression("VersionValue", targetDepth)) {
                    context.nextToken();
                    pipeTargetTimestreamParameters.setVersionValue(context.getUnmarshaller(String.class).unmarshall(context));
                }
                if (context.testExpression("DimensionMappings", targetDepth)) {
                    context.nextToken();
                    pipeTargetTimestreamParameters.setDimensionMappings(new ListUnmarshaller<DimensionMapping>(DimensionMappingJsonUnmarshaller.getInstance())

                    .unmarshall(context));
                }
                if (context.testExpression("SingleMeasureMappings", targetDepth)) {
                    context.nextToken();
                    pipeTargetTimestreamParameters.setSingleMeasureMappings(new ListUnmarshaller<SingleMeasureMapping>(SingleMeasureMappingJsonUnmarshaller
                            .getInstance())

                    .unmarshall(context));
                }
                if (context.testExpression("MultiMeasureMappings", targetDepth)) {
                    context.nextToken();
                    pipeTargetTimestreamParameters.setMultiMeasureMappings(new ListUnmarshaller<MultiMeasureMapping>(MultiMeasureMappingJsonUnmarshaller
                            .getInstance())

                    .unmarshall(context));
                }
            } else if (token == END_ARRAY || token == END_OBJECT) {
                if (context.getLastParsedParentElement() == null || context.getLastParsedParentElement().equals(currentParentElement)) {
                    if (context.getCurrentDepth() <= originalDepth)
                        break;
                }
            }
            token = context.nextToken();
        }

        return pipeTargetTimestreamParameters;
    }

    private static PipeTargetTimestreamParametersJsonUnmarshaller instance;

    public static PipeTargetTimestreamParametersJsonUnmarshaller getInstance() {
        if (instance == null)
            instance = new PipeTargetTimestreamParametersJsonUnmarshaller();
        return instance;
    }
}
