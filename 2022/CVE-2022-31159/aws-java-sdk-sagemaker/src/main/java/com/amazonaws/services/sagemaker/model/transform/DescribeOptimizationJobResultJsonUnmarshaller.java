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
 * DescribeOptimizationJobResult JSON Unmarshaller
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class DescribeOptimizationJobResultJsonUnmarshaller implements Unmarshaller<DescribeOptimizationJobResult, JsonUnmarshallerContext> {

    public DescribeOptimizationJobResult unmarshall(JsonUnmarshallerContext context) throws Exception {
        DescribeOptimizationJobResult describeOptimizationJobResult = new DescribeOptimizationJobResult();

        int originalDepth = context.getCurrentDepth();
        String currentParentElement = context.getCurrentParentElement();
        int targetDepth = originalDepth + 1;

        JsonToken token = context.getCurrentToken();
        if (token == null)
            token = context.nextToken();
        if (token == VALUE_NULL) {
            return describeOptimizationJobResult;
        }

        while (true) {
            if (token == null)
                break;

            if (token == FIELD_NAME || token == START_OBJECT) {
                if (context.testExpression("OptimizationJobArn", targetDepth)) {
                    context.nextToken();
                    describeOptimizationJobResult.setOptimizationJobArn(context.getUnmarshaller(String.class).unmarshall(context));
                }
                if (context.testExpression("OptimizationJobStatus", targetDepth)) {
                    context.nextToken();
                    describeOptimizationJobResult.setOptimizationJobStatus(context.getUnmarshaller(String.class).unmarshall(context));
                }
                if (context.testExpression("OptimizationStartTime", targetDepth)) {
                    context.nextToken();
                    describeOptimizationJobResult.setOptimizationStartTime(DateJsonUnmarshallerFactory.getInstance("unixTimestamp").unmarshall(context));
                }
                if (context.testExpression("OptimizationEndTime", targetDepth)) {
                    context.nextToken();
                    describeOptimizationJobResult.setOptimizationEndTime(DateJsonUnmarshallerFactory.getInstance("unixTimestamp").unmarshall(context));
                }
                if (context.testExpression("CreationTime", targetDepth)) {
                    context.nextToken();
                    describeOptimizationJobResult.setCreationTime(DateJsonUnmarshallerFactory.getInstance("unixTimestamp").unmarshall(context));
                }
                if (context.testExpression("LastModifiedTime", targetDepth)) {
                    context.nextToken();
                    describeOptimizationJobResult.setLastModifiedTime(DateJsonUnmarshallerFactory.getInstance("unixTimestamp").unmarshall(context));
                }
                if (context.testExpression("FailureReason", targetDepth)) {
                    context.nextToken();
                    describeOptimizationJobResult.setFailureReason(context.getUnmarshaller(String.class).unmarshall(context));
                }
                if (context.testExpression("OptimizationJobName", targetDepth)) {
                    context.nextToken();
                    describeOptimizationJobResult.setOptimizationJobName(context.getUnmarshaller(String.class).unmarshall(context));
                }
                if (context.testExpression("ModelSource", targetDepth)) {
                    context.nextToken();
                    describeOptimizationJobResult.setModelSource(OptimizationJobModelSourceJsonUnmarshaller.getInstance().unmarshall(context));
                }
                if (context.testExpression("OptimizationEnvironment", targetDepth)) {
                    context.nextToken();
                    describeOptimizationJobResult.setOptimizationEnvironment(new MapUnmarshaller<String, String>(context.getUnmarshaller(String.class), context
                            .getUnmarshaller(String.class)).unmarshall(context));
                }
                if (context.testExpression("DeploymentInstanceType", targetDepth)) {
                    context.nextToken();
                    describeOptimizationJobResult.setDeploymentInstanceType(context.getUnmarshaller(String.class).unmarshall(context));
                }
                if (context.testExpression("OptimizationConfigs", targetDepth)) {
                    context.nextToken();
                    describeOptimizationJobResult.setOptimizationConfigs(new ListUnmarshaller<OptimizationConfig>(OptimizationConfigJsonUnmarshaller
                            .getInstance())

                    .unmarshall(context));
                }
                if (context.testExpression("OutputConfig", targetDepth)) {
                    context.nextToken();
                    describeOptimizationJobResult.setOutputConfig(OptimizationJobOutputConfigJsonUnmarshaller.getInstance().unmarshall(context));
                }
                if (context.testExpression("OptimizationOutput", targetDepth)) {
                    context.nextToken();
                    describeOptimizationJobResult.setOptimizationOutput(OptimizationOutputJsonUnmarshaller.getInstance().unmarshall(context));
                }
                if (context.testExpression("RoleArn", targetDepth)) {
                    context.nextToken();
                    describeOptimizationJobResult.setRoleArn(context.getUnmarshaller(String.class).unmarshall(context));
                }
                if (context.testExpression("StoppingCondition", targetDepth)) {
                    context.nextToken();
                    describeOptimizationJobResult.setStoppingCondition(StoppingConditionJsonUnmarshaller.getInstance().unmarshall(context));
                }
                if (context.testExpression("VpcConfig", targetDepth)) {
                    context.nextToken();
                    describeOptimizationJobResult.setVpcConfig(OptimizationVpcConfigJsonUnmarshaller.getInstance().unmarshall(context));
                }
            } else if (token == END_ARRAY || token == END_OBJECT) {
                if (context.getLastParsedParentElement() == null || context.getLastParsedParentElement().equals(currentParentElement)) {
                    if (context.getCurrentDepth() <= originalDepth)
                        break;
                }
            }
            token = context.nextToken();
        }

        return describeOptimizationJobResult;
    }

    private static DescribeOptimizationJobResultJsonUnmarshaller instance;

    public static DescribeOptimizationJobResultJsonUnmarshaller getInstance() {
        if (instance == null)
            instance = new DescribeOptimizationJobResultJsonUnmarshaller();
        return instance;
    }
}
