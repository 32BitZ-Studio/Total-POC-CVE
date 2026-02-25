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
 * BatchCreateTopicReviewedAnswerResult JSON Unmarshaller
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class BatchCreateTopicReviewedAnswerResultJsonUnmarshaller implements Unmarshaller<BatchCreateTopicReviewedAnswerResult, JsonUnmarshallerContext> {

    public BatchCreateTopicReviewedAnswerResult unmarshall(JsonUnmarshallerContext context) throws Exception {
        BatchCreateTopicReviewedAnswerResult batchCreateTopicReviewedAnswerResult = new BatchCreateTopicReviewedAnswerResult();

        batchCreateTopicReviewedAnswerResult.setStatus(context.getHttpResponse().getStatusCode());

        int originalDepth = context.getCurrentDepth();
        String currentParentElement = context.getCurrentParentElement();
        int targetDepth = originalDepth + 1;

        JsonToken token = context.getCurrentToken();
        if (token == null)
            token = context.nextToken();
        if (token == VALUE_NULL) {
            return batchCreateTopicReviewedAnswerResult;
        }

        while (true) {
            if (token == null)
                break;

            if (token == FIELD_NAME || token == START_OBJECT) {
                if (context.testExpression("TopicId", targetDepth)) {
                    context.nextToken();
                    batchCreateTopicReviewedAnswerResult.setTopicId(context.getUnmarshaller(String.class).unmarshall(context));
                }
                if (context.testExpression("TopicArn", targetDepth)) {
                    context.nextToken();
                    batchCreateTopicReviewedAnswerResult.setTopicArn(context.getUnmarshaller(String.class).unmarshall(context));
                }
                if (context.testExpression("SucceededAnswers", targetDepth)) {
                    context.nextToken();
                    batchCreateTopicReviewedAnswerResult.setSucceededAnswers(new ListUnmarshaller<SucceededTopicReviewedAnswer>(
                            SucceededTopicReviewedAnswerJsonUnmarshaller.getInstance())

                    .unmarshall(context));
                }
                if (context.testExpression("InvalidAnswers", targetDepth)) {
                    context.nextToken();
                    batchCreateTopicReviewedAnswerResult.setInvalidAnswers(new ListUnmarshaller<InvalidTopicReviewedAnswer>(
                            InvalidTopicReviewedAnswerJsonUnmarshaller.getInstance())

                    .unmarshall(context));
                }
                if (context.testExpression("RequestId", targetDepth)) {
                    context.nextToken();
                    batchCreateTopicReviewedAnswerResult.setRequestId(context.getUnmarshaller(String.class).unmarshall(context));
                }
            } else if (token == END_ARRAY || token == END_OBJECT) {
                if (context.getLastParsedParentElement() == null || context.getLastParsedParentElement().equals(currentParentElement)) {
                    if (context.getCurrentDepth() <= originalDepth)
                        break;
                }
            }
            token = context.nextToken();
        }

        return batchCreateTopicReviewedAnswerResult;
    }

    private static BatchCreateTopicReviewedAnswerResultJsonUnmarshaller instance;

    public static BatchCreateTopicReviewedAnswerResultJsonUnmarshaller getInstance() {
        if (instance == null)
            instance = new BatchCreateTopicReviewedAnswerResultJsonUnmarshaller();
        return instance;
    }
}
