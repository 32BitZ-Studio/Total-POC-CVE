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
 * TaxRegistration JSON Unmarshaller
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class TaxRegistrationJsonUnmarshaller implements Unmarshaller<TaxRegistration, JsonUnmarshallerContext> {

    public TaxRegistration unmarshall(JsonUnmarshallerContext context) throws Exception {
        TaxRegistration taxRegistration = new TaxRegistration();

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
                if (context.testExpression("additionalTaxInformation", targetDepth)) {
                    context.nextToken();
                    taxRegistration.setAdditionalTaxInformation(AdditionalInfoResponseJsonUnmarshaller.getInstance().unmarshall(context));
                }
                if (context.testExpression("certifiedEmailId", targetDepth)) {
                    context.nextToken();
                    taxRegistration.setCertifiedEmailId(context.getUnmarshaller(String.class).unmarshall(context));
                }
                if (context.testExpression("legalAddress", targetDepth)) {
                    context.nextToken();
                    taxRegistration.setLegalAddress(AddressJsonUnmarshaller.getInstance().unmarshall(context));
                }
                if (context.testExpression("legalName", targetDepth)) {
                    context.nextToken();
                    taxRegistration.setLegalName(context.getUnmarshaller(String.class).unmarshall(context));
                }
                if (context.testExpression("registrationId", targetDepth)) {
                    context.nextToken();
                    taxRegistration.setRegistrationId(context.getUnmarshaller(String.class).unmarshall(context));
                }
                if (context.testExpression("registrationType", targetDepth)) {
                    context.nextToken();
                    taxRegistration.setRegistrationType(context.getUnmarshaller(String.class).unmarshall(context));
                }
                if (context.testExpression("sector", targetDepth)) {
                    context.nextToken();
                    taxRegistration.setSector(context.getUnmarshaller(String.class).unmarshall(context));
                }
                if (context.testExpression("status", targetDepth)) {
                    context.nextToken();
                    taxRegistration.setStatus(context.getUnmarshaller(String.class).unmarshall(context));
                }
                if (context.testExpression("taxDocumentMetadatas", targetDepth)) {
                    context.nextToken();
                    taxRegistration.setTaxDocumentMetadatas(new ListUnmarshaller<TaxDocumentMetadata>(TaxDocumentMetadataJsonUnmarshaller.getInstance())

                    .unmarshall(context));
                }
            } else if (token == END_ARRAY || token == END_OBJECT) {
                if (context.getLastParsedParentElement() == null || context.getLastParsedParentElement().equals(currentParentElement)) {
                    if (context.getCurrentDepth() <= originalDepth)
                        break;
                }
            }
            token = context.nextToken();
        }

        return taxRegistration;
    }

    private static TaxRegistrationJsonUnmarshaller instance;

    public static TaxRegistrationJsonUnmarshaller getInstance() {
        if (instance == null)
            instance = new TaxRegistrationJsonUnmarshaller();
        return instance;
    }
}
