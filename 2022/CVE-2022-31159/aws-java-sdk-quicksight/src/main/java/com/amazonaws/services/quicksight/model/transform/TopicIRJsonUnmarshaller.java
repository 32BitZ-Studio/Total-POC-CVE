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
 * TopicIR JSON Unmarshaller
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class TopicIRJsonUnmarshaller implements Unmarshaller<TopicIR, JsonUnmarshallerContext> {

    public TopicIR unmarshall(JsonUnmarshallerContext context) throws Exception {
        TopicIR topicIR = new TopicIR();

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
                if (context.testExpression("Metrics", targetDepth)) {
                    context.nextToken();
                    topicIR.setMetrics(new ListUnmarshaller<TopicIRMetric>(TopicIRMetricJsonUnmarshaller.getInstance())

                    .unmarshall(context));
                }
                if (context.testExpression("GroupByList", targetDepth)) {
                    context.nextToken();
                    topicIR.setGroupByList(new ListUnmarshaller<TopicIRGroupBy>(TopicIRGroupByJsonUnmarshaller.getInstance())

                    .unmarshall(context));
                }
                if (context.testExpression("Filters", targetDepth)) {
                    context.nextToken();
                    topicIR.setFilters(new ListUnmarshaller<java.util.List<TopicIRFilterOption>>(new ListUnmarshaller<TopicIRFilterOption>(
                            TopicIRFilterOptionJsonUnmarshaller.getInstance())

                    )

                    .unmarshall(context));
                }
                if (context.testExpression("Sort", targetDepth)) {
                    context.nextToken();
                    topicIR.setSort(TopicSortClauseJsonUnmarshaller.getInstance().unmarshall(context));
                }
                if (context.testExpression("ContributionAnalysis", targetDepth)) {
                    context.nextToken();
                    topicIR.setContributionAnalysis(TopicIRContributionAnalysisJsonUnmarshaller.getInstance().unmarshall(context));
                }
                if (context.testExpression("Visual", targetDepth)) {
                    context.nextToken();
                    topicIR.setVisual(VisualOptionsJsonUnmarshaller.getInstance().unmarshall(context));
                }
            } else if (token == END_ARRAY || token == END_OBJECT) {
                if (context.getLastParsedParentElement() == null || context.getLastParsedParentElement().equals(currentParentElement)) {
                    if (context.getCurrentDepth() <= originalDepth)
                        break;
                }
            }
            token = context.nextToken();
        }

        return topicIR;
    }

    private static TopicIRJsonUnmarshaller instance;

    public static TopicIRJsonUnmarshaller getInstance() {
        if (instance == null)
            instance = new TopicIRJsonUnmarshaller();
        return instance;
    }
}
