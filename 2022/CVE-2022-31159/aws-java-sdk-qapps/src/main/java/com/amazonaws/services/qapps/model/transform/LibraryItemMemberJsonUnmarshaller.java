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
 * LibraryItemMember JSON Unmarshaller
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class LibraryItemMemberJsonUnmarshaller implements Unmarshaller<LibraryItemMember, JsonUnmarshallerContext> {

    public LibraryItemMember unmarshall(JsonUnmarshallerContext context) throws Exception {
        LibraryItemMember libraryItemMember = new LibraryItemMember();

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
                if (context.testExpression("libraryItemId", targetDepth)) {
                    context.nextToken();
                    libraryItemMember.setLibraryItemId(context.getUnmarshaller(String.class).unmarshall(context));
                }
                if (context.testExpression("appId", targetDepth)) {
                    context.nextToken();
                    libraryItemMember.setAppId(context.getUnmarshaller(String.class).unmarshall(context));
                }
                if (context.testExpression("appVersion", targetDepth)) {
                    context.nextToken();
                    libraryItemMember.setAppVersion(context.getUnmarshaller(Integer.class).unmarshall(context));
                }
                if (context.testExpression("categories", targetDepth)) {
                    context.nextToken();
                    libraryItemMember.setCategories(new ListUnmarshaller<Category>(CategoryJsonUnmarshaller.getInstance())

                    .unmarshall(context));
                }
                if (context.testExpression("status", targetDepth)) {
                    context.nextToken();
                    libraryItemMember.setStatus(context.getUnmarshaller(String.class).unmarshall(context));
                }
                if (context.testExpression("createdAt", targetDepth)) {
                    context.nextToken();
                    libraryItemMember.setCreatedAt(DateJsonUnmarshallerFactory.getInstance("iso8601").unmarshall(context));
                }
                if (context.testExpression("createdBy", targetDepth)) {
                    context.nextToken();
                    libraryItemMember.setCreatedBy(context.getUnmarshaller(String.class).unmarshall(context));
                }
                if (context.testExpression("updatedAt", targetDepth)) {
                    context.nextToken();
                    libraryItemMember.setUpdatedAt(DateJsonUnmarshallerFactory.getInstance("iso8601").unmarshall(context));
                }
                if (context.testExpression("updatedBy", targetDepth)) {
                    context.nextToken();
                    libraryItemMember.setUpdatedBy(context.getUnmarshaller(String.class).unmarshall(context));
                }
                if (context.testExpression("ratingCount", targetDepth)) {
                    context.nextToken();
                    libraryItemMember.setRatingCount(context.getUnmarshaller(Integer.class).unmarshall(context));
                }
                if (context.testExpression("isRatedByUser", targetDepth)) {
                    context.nextToken();
                    libraryItemMember.setIsRatedByUser(context.getUnmarshaller(Boolean.class).unmarshall(context));
                }
                if (context.testExpression("userCount", targetDepth)) {
                    context.nextToken();
                    libraryItemMember.setUserCount(context.getUnmarshaller(Integer.class).unmarshall(context));
                }
            } else if (token == END_ARRAY || token == END_OBJECT) {
                if (context.getLastParsedParentElement() == null || context.getLastParsedParentElement().equals(currentParentElement)) {
                    if (context.getCurrentDepth() <= originalDepth)
                        break;
                }
            }
            token = context.nextToken();
        }

        return libraryItemMember;
    }

    private static LibraryItemMemberJsonUnmarshaller instance;

    public static LibraryItemMemberJsonUnmarshaller getInstance() {
        if (instance == null)
            instance = new LibraryItemMemberJsonUnmarshaller();
        return instance;
    }
}
