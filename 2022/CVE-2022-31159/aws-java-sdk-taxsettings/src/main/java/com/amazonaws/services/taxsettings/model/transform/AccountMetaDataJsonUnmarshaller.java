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
package com.amazonaws.services.taxsettings.model.transform;

import java.math.*;

import javax.annotation.Generated;

import com.amazonaws.services.taxsettings.model.*;
import com.amazonaws.transform.SimpleTypeJsonUnmarshallers.*;
import com.amazonaws.transform.*;

import com.fasterxml.jackson.core.JsonToken;
import static com.fasterxml.jackson.core.JsonToken.*;

/**
 * AccountMetaData JSON Unmarshaller
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class AccountMetaDataJsonUnmarshaller implements Unmarshaller<AccountMetaData, JsonUnmarshallerContext> {

    public AccountMetaData unmarshall(JsonUnmarshallerContext context) throws Exception {
        AccountMetaData accountMetaData = new AccountMetaData();

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
                if (context.testExpression("accountName", targetDepth)) {
                    context.nextToken();
                    accountMetaData.setAccountName(context.getUnmarshaller(String.class).unmarshall(context));
                }
                if (context.testExpression("address", targetDepth)) {
                    context.nextToken();
                    accountMetaData.setAddress(AddressJsonUnmarshaller.getInstance().unmarshall(context));
                }
                if (context.testExpression("addressRoleMap", targetDepth)) {
                    context.nextToken();
                    accountMetaData.setAddressRoleMap(new MapUnmarshaller<String, Jurisdiction>(context.getUnmarshaller(String.class),
                            JurisdictionJsonUnmarshaller.getInstance()).unmarshall(context));
                }
                if (context.testExpression("addressType", targetDepth)) {
                    context.nextToken();
                    accountMetaData.setAddressType(context.getUnmarshaller(String.class).unmarshall(context));
                }
                if (context.testExpression("seller", targetDepth)) {
                    context.nextToken();
                    accountMetaData.setSeller(context.getUnmarshaller(String.class).unmarshall(context));
                }
            } else if (token == END_ARRAY || token == END_OBJECT) {
                if (context.getLastParsedParentElement() == null || context.getLastParsedParentElement().equals(currentParentElement)) {
                    if (context.getCurrentDepth() <= originalDepth)
                        break;
                }
            }
            token = context.nextToken();
        }

        return accountMetaData;
    }

    private static AccountMetaDataJsonUnmarshaller instance;

    public static AccountMetaDataJsonUnmarshaller getInstance() {
        if (instance == null)
            instance = new AccountMetaDataJsonUnmarshaller();
        return instance;
    }
}
