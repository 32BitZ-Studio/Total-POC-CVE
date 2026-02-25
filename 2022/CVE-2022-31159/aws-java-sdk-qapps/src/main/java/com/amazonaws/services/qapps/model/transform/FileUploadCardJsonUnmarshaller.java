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
 * FileUploadCard JSON Unmarshaller
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class FileUploadCardJsonUnmarshaller implements Unmarshaller<FileUploadCard, JsonUnmarshallerContext> {

    public FileUploadCard unmarshall(JsonUnmarshallerContext context) throws Exception {
        FileUploadCard fileUploadCard = new FileUploadCard();

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
                if (context.testExpression("id", targetDepth)) {
                    context.nextToken();
                    fileUploadCard.setId(context.getUnmarshaller(String.class).unmarshall(context));
                }
                if (context.testExpression("title", targetDepth)) {
                    context.nextToken();
                    fileUploadCard.setTitle(context.getUnmarshaller(String.class).unmarshall(context));
                }
                if (context.testExpression("dependencies", targetDepth)) {
                    context.nextToken();
                    fileUploadCard.setDependencies(new ListUnmarshaller<String>(context.getUnmarshaller(String.class))

                    .unmarshall(context));
                }
                if (context.testExpression("type", targetDepth)) {
                    context.nextToken();
                    fileUploadCard.setType(context.getUnmarshaller(String.class).unmarshall(context));
                }
                if (context.testExpression("filename", targetDepth)) {
                    context.nextToken();
                    fileUploadCard.setFilename(context.getUnmarshaller(String.class).unmarshall(context));
                }
                if (context.testExpression("fileId", targetDepth)) {
                    context.nextToken();
                    fileUploadCard.setFileId(context.getUnmarshaller(String.class).unmarshall(context));
                }
                if (context.testExpression("allowOverride", targetDepth)) {
                    context.nextToken();
                    fileUploadCard.setAllowOverride(context.getUnmarshaller(Boolean.class).unmarshall(context));
                }
            } else if (token == END_ARRAY || token == END_OBJECT) {
                if (context.getLastParsedParentElement() == null || context.getLastParsedParentElement().equals(currentParentElement)) {
                    if (context.getCurrentDepth() <= originalDepth)
                        break;
                }
            }
            token = context.nextToken();
        }

        return fileUploadCard;
    }

    private static FileUploadCardJsonUnmarshaller instance;

    public static FileUploadCardJsonUnmarshaller getInstance() {
        if (instance == null)
            instance = new FileUploadCardJsonUnmarshaller();
        return instance;
    }
}
