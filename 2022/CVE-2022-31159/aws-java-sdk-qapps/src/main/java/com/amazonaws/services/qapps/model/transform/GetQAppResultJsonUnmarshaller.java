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
 * GetQAppResult JSON Unmarshaller
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class GetQAppResultJsonUnmarshaller implements Unmarshaller<GetQAppResult, JsonUnmarshallerContext> {

    public GetQAppResult unmarshall(JsonUnmarshallerContext context) throws Exception {
        GetQAppResult getQAppResult = new GetQAppResult();

        int originalDepth = context.getCurrentDepth();
        String currentParentElement = context.getCurrentParentElement();
        int targetDepth = originalDepth + 1;

        JsonToken token = context.getCurrentToken();
        if (token == null)
            token = context.nextToken();
        if (token == VALUE_NULL) {
            return getQAppResult;
        }

        while (true) {
            if (token == null)
                break;

            if (token == FIELD_NAME || token == START_OBJECT) {
                if (context.testExpression("appId", targetDepth)) {
                    context.nextToken();
                    getQAppResult.setAppId(context.getUnmarshaller(String.class).unmarshall(context));
                }
                if (context.testExpression("appArn", targetDepth)) {
                    context.nextToken();
                    getQAppResult.setAppArn(context.getUnmarshaller(String.class).unmarshall(context));
                }
                if (context.testExpression("title", targetDepth)) {
                    context.nextToken();
                    getQAppResult.setTitle(context.getUnmarshaller(String.class).unmarshall(context));
                }
                if (context.testExpression("description", targetDepth)) {
                    context.nextToken();
                    getQAppResult.setDescription(context.getUnmarshaller(String.class).unmarshall(context));
                }
                if (context.testExpression("initialPrompt", targetDepth)) {
                    context.nextToken();
                    getQAppResult.setInitialPrompt(context.getUnmarshaller(String.class).unmarshall(context));
                }
                if (context.testExpression("appVersion", targetDepth)) {
                    context.nextToken();
                    getQAppResult.setAppVersion(context.getUnmarshaller(Integer.class).unmarshall(context));
                }
                if (context.testExpression("status", targetDepth)) {
                    context.nextToken();
                    getQAppResult.setStatus(context.getUnmarshaller(String.class).unmarshall(context));
                }
                if (context.testExpression("createdAt", targetDepth)) {
                    context.nextToken();
                    getQAppResult.setCreatedAt(DateJsonUnmarshallerFactory.getInstance("iso8601").unmarshall(context));
                }
                if (context.testExpression("createdBy", targetDepth)) {
                    context.nextToken();
                    getQAppResult.setCreatedBy(context.getUnmarshaller(String.class).unmarshall(context));
                }
                if (context.testExpression("updatedAt", targetDepth)) {
                    context.nextToken();
                    getQAppResult.setUpdatedAt(DateJsonUnmarshallerFactory.getInstance("iso8601").unmarshall(context));
                }
                if (context.testExpression("updatedBy", targetDepth)) {
                    context.nextToken();
                    getQAppResult.setUpdatedBy(context.getUnmarshaller(String.class).unmarshall(context));
                }
                if (context.testExpression("requiredCapabilities", targetDepth)) {
                    context.nextToken();
                    getQAppResult.setRequiredCapabilities(new ListUnmarshaller<String>(context.getUnmarshaller(String.class))

                    .unmarshall(context));
                }
                if (context.testExpression("appDefinition", targetDepth)) {
                    context.nextToken();
                    getQAppResult.setAppDefinition(AppDefinitionJsonUnmarshaller.getInstance().unmarshall(context));
                }
            } else if (token == END_ARRAY || token == END_OBJECT) {
                if (context.getLastParsedParentElement() == null || context.getLastParsedParentElement().equals(currentParentElement)) {
                    if (context.getCurrentDepth() <= originalDepth)
                        break;
                }
            }
            token = context.nextToken();
        }

        return getQAppResult;
    }

    private static GetQAppResultJsonUnmarshaller instance;

    public static GetQAppResultJsonUnmarshaller getInstance() {
        if (instance == null)
            instance = new GetQAppResultJsonUnmarshaller();
        return instance;
    }
}
