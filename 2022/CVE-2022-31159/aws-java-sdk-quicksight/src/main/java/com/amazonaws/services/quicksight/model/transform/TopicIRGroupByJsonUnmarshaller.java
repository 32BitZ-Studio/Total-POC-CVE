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
 * TopicIRGroupBy JSON Unmarshaller
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class TopicIRGroupByJsonUnmarshaller implements Unmarshaller<TopicIRGroupBy, JsonUnmarshallerContext> {

    public TopicIRGroupBy unmarshall(JsonUnmarshallerContext context) throws Exception {
        TopicIRGroupBy topicIRGroupBy = new TopicIRGroupBy();

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
                if (context.testExpression("FieldName", targetDepth)) {
                    context.nextToken();
                    topicIRGroupBy.setFieldName(IdentifierJsonUnmarshaller.getInstance().unmarshall(context));
                }
                if (context.testExpression("TimeGranularity", targetDepth)) {
                    context.nextToken();
                    topicIRGroupBy.setTimeGranularity(context.getUnmarshaller(String.class).unmarshall(context));
                }
                if (context.testExpression("Sort", targetDepth)) {
                    context.nextToken();
                    topicIRGroupBy.setSort(TopicSortClauseJsonUnmarshaller.getInstance().unmarshall(context));
                }
                if (context.testExpression("DisplayFormat", targetDepth)) {
                    context.nextToken();
                    topicIRGroupBy.setDisplayFormat(context.getUnmarshaller(String.class).unmarshall(context));
                }
                if (context.testExpression("DisplayFormatOptions", targetDepth)) {
                    context.nextToken();
                    topicIRGroupBy.setDisplayFormatOptions(DisplayFormatOptionsJsonUnmarshaller.getInstance().unmarshall(context));
                }
                if (context.testExpression("NamedEntity", targetDepth)) {
                    context.nextToken();
                    topicIRGroupBy.setNamedEntity(NamedEntityRefJsonUnmarshaller.getInstance().unmarshall(context));
                }
            } else if (token == END_ARRAY || token == END_OBJECT) {
                if (context.getLastParsedParentElement() == null || context.getLastParsedParentElement().equals(currentParentElement)) {
                    if (context.getCurrentDepth() <= originalDepth)
                        break;
                }
            }
            token = context.nextToken();
        }

        return topicIRGroupBy;
    }

    private static TopicIRGroupByJsonUnmarshaller instance;

    public static TopicIRGroupByJsonUnmarshaller getInstance() {
        if (instance == null)
            instance = new TopicIRGroupByJsonUnmarshaller();
        return instance;
    }
}
