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
 * FileUploadCardInput JSON Unmarshaller
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class FileUploadCardInputJsonUnmarshaller implements Unmarshaller<FileUploadCardInput, JsonUnmarshallerContext> {

    public FileUploadCardInput unmarshall(JsonUnmarshallerContext context) throws Exception {
        FileUploadCardInput fileUploadCardInput = new FileUploadCardInput();

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
                if (context.testExpression("title", targetDepth)) {
                    context.nextToken();
                    fileUploadCardInput.setTitle(context.getUnmarshaller(String.class).unmarshall(context));
                }
                if (context.testExpression("id", targetDepth)) {
                    context.nextToken();
                    fileUploadCardInput.setId(context.getUnmarshaller(String.class).unmarshall(context));
                }
                if (context.testExpression("type", targetDepth)) {
                    context.nextToken();
                    fileUploadCardInput.setType(context.getUnmarshaller(String.class).unmarshall(context));
                }
                if (context.testExpression("filename", targetDepth)) {
                    context.nextToken();
                    fileUploadCardInput.setFilename(context.getUnmarshaller(String.class).unmarshall(context));
                }
                if (context.testExpression("fileId", targetDepth)) {
                    context.nextToken();
                    fileUploadCardInput.setFileId(context.getUnmarshaller(String.class).unmarshall(context));
                }
                if (context.testExpression("allowOverride", targetDepth)) {
                    context.nextToken();
                    fileUploadCardInput.setAllowOverride(context.getUnmarshaller(Boolean.class).unmarshall(context));
                }
            } else if (token == END_ARRAY || token == END_OBJECT) {
                if (context.getLastParsedParentElement() == null || context.getLastParsedParentElement().equals(currentParentElement)) {
                    if (context.getCurrentDepth() <= originalDepth)
                        break;
                }
            }
            token = context.nextToken();
        }

        return fileUploadCardInput;
    }

    private static FileUploadCardInputJsonUnmarshaller instance;

    public static FileUploadCardInputJsonUnmarshaller getInstance() {
        if (instance == null)
            instance = new FileUploadCardInputJsonUnmarshaller();
        return instance;
    }
}
