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
 * FilterAggMetrics JSON Unmarshaller
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class FilterAggMetricsJsonUnmarshaller implements Unmarshaller<FilterAggMetrics, JsonUnmarshallerContext> {

    public FilterAggMetrics unmarshall(JsonUnmarshallerContext context) throws Exception {
        FilterAggMetrics filterAggMetrics = new FilterAggMetrics();

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
                if (context.testExpression("MetricOperand", targetDepth)) {
                    context.nextToken();
                    filterAggMetrics.setMetricOperand(IdentifierJsonUnmarshaller.getInstance().unmarshall(context));
                }
                if (context.testExpression("Function", targetDepth)) {
                    context.nextToken();
                    filterAggMetrics.setFunction(context.getUnmarshaller(String.class).unmarshall(context));
                }
                if (context.testExpression("SortDirection", targetDepth)) {
                    context.nextToken();
                    filterAggMetrics.setSortDirection(context.getUnmarshaller(String.class).unmarshall(context));
                }
            } else if (token == END_ARRAY || token == END_OBJECT) {
                if (context.getLastParsedParentElement() == null || context.getLastParsedParentElement().equals(currentParentElement)) {
                    if (context.getCurrentDepth() <= originalDepth)
                        break;
                }
            }
            token = context.nextToken();
        }

        return filterAggMetrics;
    }

    private static FilterAggMetricsJsonUnmarshaller instance;

    public static FilterAggMetricsJsonUnmarshaller getInstance() {
        if (instance == null)
            instance = new FilterAggMetricsJsonUnmarshaller();
        return instance;
    }
}
