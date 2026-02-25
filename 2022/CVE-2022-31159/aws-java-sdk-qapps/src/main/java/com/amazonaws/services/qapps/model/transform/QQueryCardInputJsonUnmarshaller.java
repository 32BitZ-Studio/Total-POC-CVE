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
 * QQueryCardInput JSON Unmarshaller
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class QQueryCardInputJsonUnmarshaller implements Unmarshaller<QQueryCardInput, JsonUnmarshallerContext> {

    public QQueryCardInput unmarshall(JsonUnmarshallerContext context) throws Exception {
        QQueryCardInput qQueryCardInput = new QQueryCardInput();

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
                if (context.testExpression("title", targetDepth)) {
                    context.nextToken();
                    qQueryCardInput.setTitle(context.getUnmarshaller(String.class).unmarshall(context));
                }
                if (context.testExpression("id", targetDepth)) {
                    context.nextToken();
                    qQueryCardInput.setId(context.getUnmarshaller(String.class).unmarshall(context));
                }
                if (context.testExpression("type", targetDepth)) {
                    context.nextToken();
                    qQueryCardInput.setType(context.getUnmarshaller(String.class).unmarshall(context));
                }
                if (context.testExpression("prompt", targetDepth)) {
                    context.nextToken();
                    qQueryCardInput.setPrompt(context.getUnmarshaller(String.class).unmarshall(context));
                }
                if (context.testExpression("outputSource", targetDepth)) {
                    context.nextToken();
                    qQueryCardInput.setOutputSource(context.getUnmarshaller(String.class).unmarshall(context));
                }
                if (context.testExpression("attributeFilter", targetDepth)) {
                    context.nextToken();
                    qQueryCardInput.setAttributeFilter(AttributeFilterJsonUnmarshaller.getInstance().unmarshall(context));
                }
            } else if (token == END_ARRAY || token == END_OBJECT) {
                if (context.getLastParsedParentElement() == null || context.getLastParsedParentElement().equals(currentParentElement)) {
                    if (context.getCurrentDepth() <= originalDepth)
                        break;
                }
            }
            token = context.nextToken();
        }

        return qQueryCardInput;
    }

    private static QQueryCardInputJsonUnmarshaller instance;

    public static QQueryCardInputJsonUnmarshaller getInstance() {
        if (instance == null)
            instance = new QQueryCardInputJsonUnmarshaller();
        return instance;
    }
}
