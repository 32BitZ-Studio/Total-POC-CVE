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
package com.amazonaws.services.workspaces.model.transform;

import java.math.*;

import javax.annotation.Generated;

import com.amazonaws.services.workspaces.model.*;
import com.amazonaws.transform.SimpleTypeJsonUnmarshallers.*;
import com.amazonaws.transform.*;

import com.fasterxml.jackson.core.JsonToken;
import static com.fasterxml.jackson.core.JsonToken.*;

/**
 * WorkspacesPoolSession JSON Unmarshaller
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class WorkspacesPoolSessionJsonUnmarshaller implements Unmarshaller<WorkspacesPoolSession, JsonUnmarshallerContext> {

    public WorkspacesPoolSession unmarshall(JsonUnmarshallerContext context) throws Exception {
        WorkspacesPoolSession workspacesPoolSession = new WorkspacesPoolSession();

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
                if (context.testExpression("AuthenticationType", targetDepth)) {
                    context.nextToken();
                    workspacesPoolSession.setAuthenticationType(context.getUnmarshaller(String.class).unmarshall(context));
                }
                if (context.testExpression("ConnectionState", targetDepth)) {
                    context.nextToken();
                    workspacesPoolSession.setConnectionState(context.getUnmarshaller(String.class).unmarshall(context));
                }
                if (context.testExpression("SessionId", targetDepth)) {
                    context.nextToken();
                    workspacesPoolSession.setSessionId(context.getUnmarshaller(String.class).unmarshall(context));
                }
                if (context.testExpression("InstanceId", targetDepth)) {
                    context.nextToken();
                    workspacesPoolSession.setInstanceId(context.getUnmarshaller(String.class).unmarshall(context));
                }
                if (context.testExpression("PoolId", targetDepth)) {
                    context.nextToken();
                    workspacesPoolSession.setPoolId(context.getUnmarshaller(String.class).unmarshall(context));
                }
                if (context.testExpression("ExpirationTime", targetDepth)) {
                    context.nextToken();
                    workspacesPoolSession.setExpirationTime(DateJsonUnmarshallerFactory.getInstance("unixTimestamp").unmarshall(context));
                }
                if (context.testExpression("NetworkAccessConfiguration", targetDepth)) {
                    context.nextToken();
                    workspacesPoolSession.setNetworkAccessConfiguration(NetworkAccessConfigurationJsonUnmarshaller.getInstance().unmarshall(context));
                }
                if (context.testExpression("StartTime", targetDepth)) {
                    context.nextToken();
                    workspacesPoolSession.setStartTime(DateJsonUnmarshallerFactory.getInstance("unixTimestamp").unmarshall(context));
                }
                if (context.testExpression("UserId", targetDepth)) {
                    context.nextToken();
                    workspacesPoolSession.setUserId(context.getUnmarshaller(String.class).unmarshall(context));
                }
            } else if (token == END_ARRAY || token == END_OBJECT) {
                if (context.getLastParsedParentElement() == null || context.getLastParsedParentElement().equals(currentParentElement)) {
                    if (context.getCurrentDepth() <= originalDepth)
                        break;
                }
            }
            token = context.nextToken();
        }

        return workspacesPoolSession;
    }

    private static WorkspacesPoolSessionJsonUnmarshaller instance;

    public static WorkspacesPoolSessionJsonUnmarshaller getInstance() {
        if (instance == null)
            instance = new WorkspacesPoolSessionJsonUnmarshaller();
        return instance;
    }
}
