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
package com.amazonaws.services.sagemaker.model.transform;

import java.math.*;

import javax.annotation.Generated;

import com.amazonaws.services.sagemaker.model.*;
import com.amazonaws.transform.SimpleTypeJsonUnmarshallers.*;
import com.amazonaws.transform.*;

import com.fasterxml.jackson.core.JsonToken;
import static com.fasterxml.jackson.core.JsonToken.*;

/**
 * DescribeMlflowTrackingServerResult JSON Unmarshaller
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class DescribeMlflowTrackingServerResultJsonUnmarshaller implements Unmarshaller<DescribeMlflowTrackingServerResult, JsonUnmarshallerContext> {

    public DescribeMlflowTrackingServerResult unmarshall(JsonUnmarshallerContext context) throws Exception {
        DescribeMlflowTrackingServerResult describeMlflowTrackingServerResult = new DescribeMlflowTrackingServerResult();

        int originalDepth = context.getCurrentDepth();
        String currentParentElement = context.getCurrentParentElement();
        int targetDepth = originalDepth + 1;

        JsonToken token = context.getCurrentToken();
        if (token == null)
            token = context.nextToken();
        if (token == VALUE_NULL) {
            return describeMlflowTrackingServerResult;
        }

        while (true) {
            if (token == null)
                break;

            if (token == FIELD_NAME || token == START_OBJECT) {
                if (context.testExpression("TrackingServerArn", targetDepth)) {
                    context.nextToken();
                    describeMlflowTrackingServerResult.setTrackingServerArn(context.getUnmarshaller(String.class).unmarshall(context));
                }
                if (context.testExpression("TrackingServerName", targetDepth)) {
                    context.nextToken();
                    describeMlflowTrackingServerResult.setTrackingServerName(context.getUnmarshaller(String.class).unmarshall(context));
                }
                if (context.testExpression("ArtifactStoreUri", targetDepth)) {
                    context.nextToken();
                    describeMlflowTrackingServerResult.setArtifactStoreUri(context.getUnmarshaller(String.class).unmarshall(context));
                }
                if (context.testExpression("TrackingServerSize", targetDepth)) {
                    context.nextToken();
                    describeMlflowTrackingServerResult.setTrackingServerSize(context.getUnmarshaller(String.class).unmarshall(context));
                }
                if (context.testExpression("MlflowVersion", targetDepth)) {
                    context.nextToken();
                    describeMlflowTrackingServerResult.setMlflowVersion(context.getUnmarshaller(String.class).unmarshall(context));
                }
                if (context.testExpression("RoleArn", targetDepth)) {
                    context.nextToken();
                    describeMlflowTrackingServerResult.setRoleArn(context.getUnmarshaller(String.class).unmarshall(context));
                }
                if (context.testExpression("TrackingServerStatus", targetDepth)) {
                    context.nextToken();
                    describeMlflowTrackingServerResult.setTrackingServerStatus(context.getUnmarshaller(String.class).unmarshall(context));
                }
                if (context.testExpression("IsActive", targetDepth)) {
                    context.nextToken();
                    describeMlflowTrackingServerResult.setIsActive(context.getUnmarshaller(String.class).unmarshall(context));
                }
                if (context.testExpression("TrackingServerUrl", targetDepth)) {
                    context.nextToken();
                    describeMlflowTrackingServerResult.setTrackingServerUrl(context.getUnmarshaller(String.class).unmarshall(context));
                }
                if (context.testExpression("WeeklyMaintenanceWindowStart", targetDepth)) {
                    context.nextToken();
                    describeMlflowTrackingServerResult.setWeeklyMaintenanceWindowStart(context.getUnmarshaller(String.class).unmarshall(context));
                }
                if (context.testExpression("AutomaticModelRegistration", targetDepth)) {
                    context.nextToken();
                    describeMlflowTrackingServerResult.setAutomaticModelRegistration(context.getUnmarshaller(Boolean.class).unmarshall(context));
                }
                if (context.testExpression("CreationTime", targetDepth)) {
                    context.nextToken();
                    describeMlflowTrackingServerResult.setCreationTime(DateJsonUnmarshallerFactory.getInstance("unixTimestamp").unmarshall(context));
                }
                if (context.testExpression("CreatedBy", targetDepth)) {
                    context.nextToken();
                    describeMlflowTrackingServerResult.setCreatedBy(UserContextJsonUnmarshaller.getInstance().unmarshall(context));
                }
                if (context.testExpression("LastModifiedTime", targetDepth)) {
                    context.nextToken();
                    describeMlflowTrackingServerResult.setLastModifiedTime(DateJsonUnmarshallerFactory.getInstance("unixTimestamp").unmarshall(context));
                }
                if (context.testExpression("LastModifiedBy", targetDepth)) {
                    context.nextToken();
                    describeMlflowTrackingServerResult.setLastModifiedBy(UserContextJsonUnmarshaller.getInstance().unmarshall(context));
                }
            } else if (token == END_ARRAY || token == END_OBJECT) {
                if (context.getLastParsedParentElement() == null || context.getLastParsedParentElement().equals(currentParentElement)) {
                    if (context.getCurrentDepth() <= originalDepth)
                        break;
                }
            }
            token = context.nextToken();
        }

        return describeMlflowTrackingServerResult;
    }

    private static DescribeMlflowTrackingServerResultJsonUnmarshaller instance;

    public static DescribeMlflowTrackingServerResultJsonUnmarshaller getInstance() {
        if (instance == null)
            instance = new DescribeMlflowTrackingServerResultJsonUnmarshaller();
        return instance;
    }
}
