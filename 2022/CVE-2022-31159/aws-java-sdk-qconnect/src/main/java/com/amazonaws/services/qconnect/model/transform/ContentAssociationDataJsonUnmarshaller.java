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
package com.amazonaws.services.qconnect.model.transform;

import java.math.*;

import javax.annotation.Generated;

import com.amazonaws.services.qconnect.model.*;
import com.amazonaws.transform.SimpleTypeJsonUnmarshallers.*;
import com.amazonaws.transform.*;

import com.fasterxml.jackson.core.JsonToken;
import static com.fasterxml.jackson.core.JsonToken.*;

/**
 * ContentAssociationData JSON Unmarshaller
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class ContentAssociationDataJsonUnmarshaller implements Unmarshaller<ContentAssociationData, JsonUnmarshallerContext> {

    public ContentAssociationData unmarshall(JsonUnmarshallerContext context) throws Exception {
        ContentAssociationData contentAssociationData = new ContentAssociationData();

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
                if (context.testExpression("associationData", targetDepth)) {
                    context.nextToken();
                    contentAssociationData.setAssociationData(ContentAssociationContentsJsonUnmarshaller.getInstance().unmarshall(context));
                }
                if (context.testExpression("associationType", targetDepth)) {
                    context.nextToken();
                    contentAssociationData.setAssociationType(context.getUnmarshaller(String.class).unmarshall(context));
                }
                if (context.testExpression("contentArn", targetDepth)) {
                    context.nextToken();
                    contentAssociationData.setContentArn(context.getUnmarshaller(String.class).unmarshall(context));
                }
                if (context.testExpression("contentAssociationArn", targetDepth)) {
                    context.nextToken();
                    contentAssociationData.setContentAssociationArn(context.getUnmarshaller(String.class).unmarshall(context));
                }
                if (context.testExpression("contentAssociationId", targetDepth)) {
                    context.nextToken();
                    contentAssociationData.setContentAssociationId(context.getUnmarshaller(String.class).unmarshall(context));
                }
                if (context.testExpression("contentId", targetDepth)) {
                    context.nextToken();
                    contentAssociationData.setContentId(context.getUnmarshaller(String.class).unmarshall(context));
                }
                if (context.testExpression("knowledgeBaseArn", targetDepth)) {
                    context.nextToken();
                    contentAssociationData.setKnowledgeBaseArn(context.getUnmarshaller(String.class).unmarshall(context));
                }
                if (context.testExpression("knowledgeBaseId", targetDepth)) {
                    context.nextToken();
                    contentAssociationData.setKnowledgeBaseId(context.getUnmarshaller(String.class).unmarshall(context));
                }
                if (context.testExpression("tags", targetDepth)) {
                    context.nextToken();
                    contentAssociationData.setTags(new MapUnmarshaller<String, String>(context.getUnmarshaller(String.class), context
                            .getUnmarshaller(String.class)).unmarshall(context));
                }
            } else if (token == END_ARRAY || token == END_OBJECT) {
                if (context.getLastParsedParentElement() == null || context.getLastParsedParentElement().equals(currentParentElement)) {
                    if (context.getCurrentDepth() <= originalDepth)
                        break;
                }
            }
            token = context.nextToken();
        }

        return contentAssociationData;
    }

    private static ContentAssociationDataJsonUnmarshaller instance;

    public static ContentAssociationDataJsonUnmarshaller getInstance() {
        if (instance == null)
            instance = new ContentAssociationDataJsonUnmarshaller();
        return instance;
    }
}
