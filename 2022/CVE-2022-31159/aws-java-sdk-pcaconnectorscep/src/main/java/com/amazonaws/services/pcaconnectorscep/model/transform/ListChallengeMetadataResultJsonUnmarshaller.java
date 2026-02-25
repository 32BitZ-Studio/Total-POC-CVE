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
package com.amazonaws.services.pcaconnectorscep.model.transform;

import java.math.*;

import javax.annotation.Generated;

import com.amazonaws.services.pcaconnectorscep.model.*;
import com.amazonaws.transform.SimpleTypeJsonUnmarshallers.*;
import com.amazonaws.transform.*;

import com.fasterxml.jackson.core.JsonToken;
import static com.fasterxml.jackson.core.JsonToken.*;

/**
 * ListChallengeMetadataResult JSON Unmarshaller
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class ListChallengeMetadataResultJsonUnmarshaller implements Unmarshaller<ListChallengeMetadataResult, JsonUnmarshallerContext> {

    public ListChallengeMetadataResult unmarshall(JsonUnmarshallerContext context) throws Exception {
        ListChallengeMetadataResult listChallengeMetadataResult = new ListChallengeMetadataResult();

        int originalDepth = context.getCurrentDepth();
        String currentParentElement = context.getCurrentParentElement();
        int targetDepth = originalDepth + 1;

        JsonToken token = context.getCurrentToken();
        if (token == null)
            token = context.nextToken();
        if (token == VALUE_NULL) {
            return listChallengeMetadataResult;
        }

        while (true) {
            if (token == null)
                break;

            if (token == FIELD_NAME || token == START_OBJECT) {
                if (context.testExpression("Challenges", targetDepth)) {
                    context.nextToken();
                    listChallengeMetadataResult.setChallenges(new ListUnmarshaller<ChallengeMetadataSummary>(ChallengeMetadataSummaryJsonUnmarshaller
                            .getInstance())

                    .unmarshall(context));
                }
                if (context.testExpression("NextToken", targetDepth)) {
                    context.nextToken();
                    listChallengeMetadataResult.setNextToken(context.getUnmarshaller(String.class).unmarshall(context));
                }
            } else if (token == END_ARRAY || token == END_OBJECT) {
                if (context.getLastParsedParentElement() == null || context.getLastParsedParentElement().equals(currentParentElement)) {
                    if (context.getCurrentDepth() <= originalDepth)
                        break;
                }
            }
            token = context.nextToken();
        }

        return listChallengeMetadataResult;
    }

    private static ListChallengeMetadataResultJsonUnmarshaller instance;

    public static ListChallengeMetadataResultJsonUnmarshaller getInstance() {
        if (instance == null)
            instance = new ListChallengeMetadataResultJsonUnmarshaller();
        return instance;
    }
}
