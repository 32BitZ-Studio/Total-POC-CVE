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
 * TopicIRFilterOption JSON Unmarshaller
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class TopicIRFilterOptionJsonUnmarshaller implements Unmarshaller<TopicIRFilterOption, JsonUnmarshallerContext> {

    public TopicIRFilterOption unmarshall(JsonUnmarshallerContext context) throws Exception {
        TopicIRFilterOption topicIRFilterOption = new TopicIRFilterOption();

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
                if (context.testExpression("FilterType", targetDepth)) {
                    context.nextToken();
                    topicIRFilterOption.setFilterType(context.getUnmarshaller(String.class).unmarshall(context));
                }
                if (context.testExpression("FilterClass", targetDepth)) {
                    context.nextToken();
                    topicIRFilterOption.setFilterClass(context.getUnmarshaller(String.class).unmarshall(context));
                }
                if (context.testExpression("OperandField", targetDepth)) {
                    context.nextToken();
                    topicIRFilterOption.setOperandField(IdentifierJsonUnmarshaller.getInstance().unmarshall(context));
                }
                if (context.testExpression("Function", targetDepth)) {
                    context.nextToken();
                    topicIRFilterOption.setFunction(context.getUnmarshaller(String.class).unmarshall(context));
                }
                if (context.testExpression("Constant", targetDepth)) {
                    context.nextToken();
                    topicIRFilterOption.setConstant(TopicConstantValueJsonUnmarshaller.getInstance().unmarshall(context));
                }
                if (context.testExpression("Inverse", targetDepth)) {
                    context.nextToken();
                    topicIRFilterOption.setInverse(context.getUnmarshaller(Boolean.class).unmarshall(context));
                }
                if (context.testExpression("NullFilter", targetDepth)) {
                    context.nextToken();
                    topicIRFilterOption.setNullFilter(context.getUnmarshaller(String.class).unmarshall(context));
                }
                if (context.testExpression("Aggregation", targetDepth)) {
                    context.nextToken();
                    topicIRFilterOption.setAggregation(context.getUnmarshaller(String.class).unmarshall(context));
                }
                if (context.testExpression("AggregationFunctionParameters", targetDepth)) {
                    context.nextToken();
                    topicIRFilterOption.setAggregationFunctionParameters(new MapUnmarshaller<String, String>(context.getUnmarshaller(String.class), context
                            .getUnmarshaller(String.class)).unmarshall(context));
                }
                if (context.testExpression("AggregationPartitionBy", targetDepth)) {
                    context.nextToken();
                    topicIRFilterOption.setAggregationPartitionBy(new ListUnmarshaller<AggregationPartitionBy>(AggregationPartitionByJsonUnmarshaller
                            .getInstance())

                    .unmarshall(context));
                }
                if (context.testExpression("Range", targetDepth)) {
                    context.nextToken();
                    topicIRFilterOption.setRange(TopicConstantValueJsonUnmarshaller.getInstance().unmarshall(context));
                }
                if (context.testExpression("Inclusive", targetDepth)) {
                    context.nextToken();
                    topicIRFilterOption.setInclusive(context.getUnmarshaller(Boolean.class).unmarshall(context));
                }
                if (context.testExpression("TimeGranularity", targetDepth)) {
                    context.nextToken();
                    topicIRFilterOption.setTimeGranularity(context.getUnmarshaller(String.class).unmarshall(context));
                }
                if (context.testExpression("LastNextOffset", targetDepth)) {
                    context.nextToken();
                    topicIRFilterOption.setLastNextOffset(TopicConstantValueJsonUnmarshaller.getInstance().unmarshall(context));
                }
                if (context.testExpression("AggMetrics", targetDepth)) {
                    context.nextToken();
                    topicIRFilterOption.setAggMetrics(new ListUnmarshaller<FilterAggMetrics>(FilterAggMetricsJsonUnmarshaller.getInstance())

                    .unmarshall(context));
                }
                if (context.testExpression("TopBottomLimit", targetDepth)) {
                    context.nextToken();
                    topicIRFilterOption.setTopBottomLimit(TopicConstantValueJsonUnmarshaller.getInstance().unmarshall(context));
                }
                if (context.testExpression("SortDirection", targetDepth)) {
                    context.nextToken();
                    topicIRFilterOption.setSortDirection(context.getUnmarshaller(String.class).unmarshall(context));
                }
                if (context.testExpression("Anchor", targetDepth)) {
                    context.nextToken();
                    topicIRFilterOption.setAnchor(AnchorJsonUnmarshaller.getInstance().unmarshall(context));
                }
            } else if (token == END_ARRAY || token == END_OBJECT) {
                if (context.getLastParsedParentElement() == null || context.getLastParsedParentElement().equals(currentParentElement)) {
                    if (context.getCurrentDepth() <= originalDepth)
                        break;
                }
            }
            token = context.nextToken();
        }

        return topicIRFilterOption;
    }

    private static TopicIRFilterOptionJsonUnmarshaller instance;

    public static TopicIRFilterOptionJsonUnmarshaller getInstance() {
        if (instance == null)
            instance = new TopicIRFilterOptionJsonUnmarshaller();
        return instance;
    }
}
