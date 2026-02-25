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
 * WorkspacesPool JSON Unmarshaller
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class WorkspacesPoolJsonUnmarshaller implements Unmarshaller<WorkspacesPool, JsonUnmarshallerContext> {

    public WorkspacesPool unmarshall(JsonUnmarshallerContext context) throws Exception {
        WorkspacesPool workspacesPool = new WorkspacesPool();

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
                if (context.testExpression("PoolId", targetDepth)) {
                    context.nextToken();
                    workspacesPool.setPoolId(context.getUnmarshaller(String.class).unmarshall(context));
                }
                if (context.testExpression("PoolArn", targetDepth)) {
                    context.nextToken();
                    workspacesPool.setPoolArn(context.getUnmarshaller(String.class).unmarshall(context));
                }
                if (context.testExpression("CapacityStatus", targetDepth)) {
                    context.nextToken();
                    workspacesPool.setCapacityStatus(CapacityStatusJsonUnmarshaller.getInstance().unmarshall(context));
                }
                if (context.testExpression("PoolName", targetDepth)) {
                    context.nextToken();
                    workspacesPool.setPoolName(context.getUnmarshaller(String.class).unmarshall(context));
                }
                if (context.testExpression("Description", targetDepth)) {
                    context.nextToken();
                    workspacesPool.setDescription(context.getUnmarshaller(String.class).unmarshall(context));
                }
                if (context.testExpression("State", targetDepth)) {
                    context.nextToken();
                    workspacesPool.setState(context.getUnmarshaller(String.class).unmarshall(context));
                }
                if (context.testExpression("CreatedAt", targetDepth)) {
                    context.nextToken();
                    workspacesPool.setCreatedAt(DateJsonUnmarshallerFactory.getInstance("unixTimestamp").unmarshall(context));
                }
                if (context.testExpression("BundleId", targetDepth)) {
                    context.nextToken();
                    workspacesPool.setBundleId(context.getUnmarshaller(String.class).unmarshall(context));
                }
                if (context.testExpression("DirectoryId", targetDepth)) {
                    context.nextToken();
                    workspacesPool.setDirectoryId(context.getUnmarshaller(String.class).unmarshall(context));
                }
                if (context.testExpression("Errors", targetDepth)) {
                    context.nextToken();
                    workspacesPool.setErrors(new ListUnmarshaller<WorkspacesPoolError>(WorkspacesPoolErrorJsonUnmarshaller.getInstance())

                    .unmarshall(context));
                }
                if (context.testExpression("ApplicationSettings", targetDepth)) {
                    context.nextToken();
                    workspacesPool.setApplicationSettings(ApplicationSettingsResponseJsonUnmarshaller.getInstance().unmarshall(context));
                }
                if (context.testExpression("TimeoutSettings", targetDepth)) {
                    context.nextToken();
                    workspacesPool.setTimeoutSettings(TimeoutSettingsJsonUnmarshaller.getInstance().unmarshall(context));
                }
            } else if (token == END_ARRAY || token == END_OBJECT) {
                if (context.getLastParsedParentElement() == null || context.getLastParsedParentElement().equals(currentParentElement)) {
                    if (context.getCurrentDepth() <= originalDepth)
                        break;
                }
            }
            token = context.nextToken();
        }

        return workspacesPool;
    }

    private static WorkspacesPoolJsonUnmarshaller instance;

    public static WorkspacesPoolJsonUnmarshaller getInstance() {
        if (instance == null)
            instance = new WorkspacesPoolJsonUnmarshaller();
        return instance;
    }
}
