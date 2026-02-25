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
package com.amazonaws.services.quicksight.model.transform;

import java.math.*;

import javax.annotation.Generated;

import com.amazonaws.services.quicksight.model.*;
import com.amazonaws.transform.SimpleTypeJsonUnmarshallers.*;
import com.amazonaws.transform.*;

import com.fasterxml.jackson.core.JsonToken;
import static com.fasterxml.jackson.core.JsonToken.*;

/**
 * TopicIRMetric JSON Unmarshaller
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class TopicIRMetricJsonUnmarshaller implements Unmarshaller<TopicIRMetric, JsonUnmarshallerContext> {

    public TopicIRMetric unmarshall(JsonUnmarshallerContext context) throws Exception {
        TopicIRMetric topicIRMetric = new TopicIRMetric();

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
                if (context.testExpression("MetricId", targetDepth)) {
                    context.nextToken();
                    topicIRMetric.setMetricId(IdentifierJsonUnmarshaller.getInstance().unmarshall(context));
                }
                if (context.testExpression("Function", targetDepth)) {
                    context.nextToken();
                    topicIRMetric.setFunction(AggFunctionJsonUnmarshaller.getInstance().unmarshall(context));
                }
                if (context.testExpression("Operands", targetDepth)) {
                    context.nextToken();
                    topicIRMetric.setOperands(new ListUnmarshaller<Identifier>(IdentifierJsonUnmarshaller.getInstance())

                    .unmarshall(context));
                }
                if (context.testExpression("ComparisonMethod", targetDepth)) {
                    context.nextToken();
                    topicIRMetric.setComparisonMethod(TopicIRComparisonMethodJsonUnmarshaller.getInstance().unmarshall(context));
                }
                if (context.testExpression("Expression", targetDepth)) {
                    context.nextToken();
                    topicIRMetric.setExpression(context.getUnmarshaller(String.class).unmarshall(context));
                }
                if (context.testExpression("CalculatedFieldReferences", targetDepth)) {
                    context.nextToken();
                    topicIRMetric.setCalculatedFieldReferences(new ListUnmarshaller<Identifier>(IdentifierJsonUnmarshaller.getInstance())

                    .unmarshall(context));
                }
                if (context.testExpression("DisplayFormat", targetDepth)) {
                    context.nextToken();
                    topicIRMetric.setDisplayFormat(context.getUnmarshaller(String.class).unmarshall(context));
                }
                if (context.testExpression("DisplayFormatOptions", targetDepth)) {
                    context.nextToken();
                    topicIRMetric.setDisplayFormatOptions(DisplayFormatOptionsJsonUnmarshaller.getInstance().unmarshall(context));
                }
                if (context.testExpression("NamedEntity", targetDepth)) {
                    context.nextToken();
                    topicIRMetric.setNamedEntity(NamedEntityRefJsonUnmarshaller.getInstance().unmarshall(context));
                }
            } else if (token == END_ARRAY || token == END_OBJECT) {
                if (context.getLastParsedParentElement() == null || context.getLastParsedParentElement().equals(currentParentElement)) {
                    if (context.getCurrentDepth() <= originalDepth)
                        break;
                }
            }
            token = context.nextToken();
        }

        return topicIRMetric;
    }

    private static TopicIRMetricJsonUnmarshaller instance;

    public static TopicIRMetricJsonUnmarshaller getInstance() {
        if (instance == null)
            instance = new TopicIRMetricJsonUnmarshaller();
        return instance;
    }
}
