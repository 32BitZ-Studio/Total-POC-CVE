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
 * TaxRegistrationWithJurisdiction JSON Unmarshaller
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class TaxRegistrationWithJurisdictionJsonUnmarshaller implements Unmarshaller<TaxRegistrationWithJurisdiction, JsonUnmarshallerContext> {

    public TaxRegistrationWithJurisdiction unmarshall(JsonUnmarshallerContext context) throws Exception {
        TaxRegistrationWithJurisdiction taxRegistrationWithJurisdiction = new TaxRegistrationWithJurisdiction();

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
                    taxRegistrationWithJurisdiction.setAdditionalTaxInformation(AdditionalInfoResponseJsonUnmarshaller.getInstance().unmarshall(context));
                }
                if (context.testExpression("certifiedEmailId", targetDepth)) {
                    context.nextToken();
                    taxRegistrationWithJurisdiction.setCertifiedEmailId(context.getUnmarshaller(String.class).unmarshall(context));
                }
                if (context.testExpression("jurisdiction", targetDepth)) {
                    context.nextToken();
                    taxRegistrationWithJurisdiction.setJurisdiction(JurisdictionJsonUnmarshaller.getInstance().unmarshall(context));
                }
                if (context.testExpression("legalName", targetDepth)) {
                    context.nextToken();
                    taxRegistrationWithJurisdiction.setLegalName(context.getUnmarshaller(String.class).unmarshall(context));
                }
                if (context.testExpression("registrationId", targetDepth)) {
                    context.nextToken();
                    taxRegistrationWithJurisdiction.setRegistrationId(context.getUnmarshaller(String.class).unmarshall(context));
                }
                if (context.testExpression("registrationType", targetDepth)) {
                    context.nextToken();
                    taxRegistrationWithJurisdiction.setRegistrationType(context.getUnmarshaller(String.class).unmarshall(context));
                }
                if (context.testExpression("sector", targetDepth)) {
                    context.nextToken();
                    taxRegistrationWithJurisdiction.setSector(context.getUnmarshaller(String.class).unmarshall(context));
                }
                if (context.testExpression("status", targetDepth)) {
                    context.nextToken();
                    taxRegistrationWithJurisdiction.setStatus(context.getUnmarshaller(String.class).unmarshall(context));
                }
                if (context.testExpression("taxDocumentMetadatas", targetDepth)) {
                    context.nextToken();
                    taxRegistrationWithJurisdiction.setTaxDocumentMetadatas(new ListUnmarshaller<TaxDocumentMetadata>(TaxDocumentMetadataJsonUnmarshaller
                            .getInstance())

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

        return taxRegistrationWithJurisdiction;
    }

    private static TaxRegistrationWithJurisdictionJsonUnmarshaller instance;

    public static TaxRegistrationWithJurisdictionJsonUnmarshaller getInstance() {
        if (instance == null)
            instance = new TaxRegistrationWithJurisdictionJsonUnmarshaller();
        return instance;
    }
}
