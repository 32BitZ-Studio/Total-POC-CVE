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
 * UserAppItem JSON Unmarshaller
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class UserAppItemJsonUnmarshaller implements Unmarshaller<UserAppItem, JsonUnmarshallerContext> {

    public UserAppItem unmarshall(JsonUnmarshallerContext context) throws Exception {
        UserAppItem userAppItem = new UserAppItem();

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
                if (context.testExpression("appId", targetDepth)) {
                    context.nextToken();
                    userAppItem.setAppId(context.getUnmarshaller(String.class).unmarshall(context));
                }
                if (context.testExpression("appArn", targetDepth)) {
                    context.nextToken();
                    userAppItem.setAppArn(context.getUnmarshaller(String.class).unmarshall(context));
                }
                if (context.testExpression("title", targetDepth)) {
                    context.nextToken();
                    userAppItem.setTitle(context.getUnmarshaller(String.class).unmarshall(context));
                }
                if (context.testExpression("description", targetDepth)) {
                    context.nextToken();
                    userAppItem.setDescription(context.getUnmarshaller(String.class).unmarshall(context));
                }
                if (context.testExpression("createdAt", targetDepth)) {
                    context.nextToken();
                    userAppItem.setCreatedAt(DateJsonUnmarshallerFactory.getInstance("iso8601").unmarshall(context));
                }
                if (context.testExpression("canEdit", targetDepth)) {
                    context.nextToken();
                    userAppItem.setCanEdit(context.getUnmarshaller(Boolean.class).unmarshall(context));
                }
                if (context.testExpression("status", targetDepth)) {
                    context.nextToken();
                    userAppItem.setStatus(context.getUnmarshaller(String.class).unmarshall(context));
                }
            } else if (token == END_ARRAY || token == END_OBJECT) {
                if (context.getLastParsedParentElement() == null || context.getLastParsedParentElement().equals(currentParentElement)) {
                    if (context.getCurrentDepth() <= originalDepth)
                        break;
                }
            }
            token = context.nextToken();
        }

        return userAppItem;
    }

    private static UserAppItemJsonUnmarshaller instance;

    public static UserAppItemJsonUnmarshaller getInstance() {
        if (instance == null)
            instance = new UserAppItemJsonUnmarshaller();
        return instance;
    }
}
