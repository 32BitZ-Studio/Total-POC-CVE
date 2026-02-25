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
package com.amazonaws.services.qapps.model.transform;

import java.math.*;

import javax.annotation.Generated;

import com.amazonaws.services.qapps.model.*;
import com.amazonaws.transform.SimpleTypeJsonUnmarshallers.*;
import com.amazonaws.transform.*;

import com.fasterxml.jackson.core.JsonToken;
import static com.fasterxml.jackson.core.JsonToken.*;

/**
 * QQueryCard JSON Unmarshaller
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class QQueryCardJsonUnmarshaller implements Unmarshaller<QQueryCard, JsonUnmarshallerContext> {

    public QQueryCard unmarshall(JsonUnmarshallerContext context) throws Exception {
        QQueryCard qQueryCard = new QQueryCard();

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
                if (context.testExpression("id", targetDepth)) {
                    context.nextToken();
                    qQueryCard.setId(context.getUnmarshaller(String.class).unmarshall(context));
                }
                if (context.testExpression("title", targetDepth)) {
                    context.nextToken();
                    qQueryCard.setTitle(context.getUnmarshaller(String.class).unmarshall(context));
                }
                if (context.testExpression("dependencies", targetDepth)) {
                    context.nextToken();
                    qQueryCard.setDependencies(new ListUnmarshaller<String>(context.getUnmarshaller(String.class))

                    .unmarshall(context));
                }
                if (context.testExpression("type", targetDepth)) {
                    context.nextToken();
                    qQueryCard.setType(context.getUnmarshaller(String.class).unmarshall(context));
                }
                if (context.testExpression("prompt", targetDepth)) {
                    context.nextToken();
                    qQueryCard.setPrompt(context.getUnmarshaller(String.class).unmarshall(context));
                }
                if (context.testExpression("outputSource", targetDepth)) {
                    context.nextToken();
                    qQueryCard.setOutputSource(context.getUnmarshaller(String.class).unmarshall(context));
                }
                if (context.testExpression("attributeFilter", targetDepth)) {
                    context.nextToken();
                    qQueryCard.setAttributeFilter(AttributeFilterJsonUnmarshaller.getInstance().unmarshall(context));
                }
            } else if (token == END_ARRAY || token == END_OBJECT) {
                if (context.getLastParsedParentElement() == null || context.getLastParsedParentElement().equals(currentParentElement)) {
                    if (context.getCurrentDepth() <= originalDepth)
                        break;
                }
            }
            token = context.nextToken();
        }

        return qQueryCard;
    }

    private static QQueryCardJsonUnmarshaller instance;

    public static QQueryCardJsonUnmarshaller getInstance() {
        if (instance == null)
            instance = new QQueryCardJsonUnmarshaller();
        return instance;
    }
}
