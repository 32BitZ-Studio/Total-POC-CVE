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
 * AdditionalInfoResponse JSON Unmarshaller
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class AdditionalInfoResponseJsonUnmarshaller implements Unmarshaller<AdditionalInfoResponse, JsonUnmarshallerContext> {

    public AdditionalInfoResponse unmarshall(JsonUnmarshallerContext context) throws Exception {
        AdditionalInfoResponse additionalInfoResponse = new AdditionalInfoResponse();

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
                if (context.testExpression("brazilAdditionalInfo", targetDepth)) {
                    context.nextToken();
                    additionalInfoResponse.setBrazilAdditionalInfo(BrazilAdditionalInfoJsonUnmarshaller.getInstance().unmarshall(context));
                }
                if (context.testExpression("canadaAdditionalInfo", targetDepth)) {
                    context.nextToken();
                    additionalInfoResponse.setCanadaAdditionalInfo(CanadaAdditionalInfoJsonUnmarshaller.getInstance().unmarshall(context));
                }
                if (context.testExpression("estoniaAdditionalInfo", targetDepth)) {
                    context.nextToken();
                    additionalInfoResponse.setEstoniaAdditionalInfo(EstoniaAdditionalInfoJsonUnmarshaller.getInstance().unmarshall(context));
                }
                if (context.testExpression("georgiaAdditionalInfo", targetDepth)) {
                    context.nextToken();
                    additionalInfoResponse.setGeorgiaAdditionalInfo(GeorgiaAdditionalInfoJsonUnmarshaller.getInstance().unmarshall(context));
                }
                if (context.testExpression("indiaAdditionalInfo", targetDepth)) {
                    context.nextToken();
                    additionalInfoResponse.setIndiaAdditionalInfo(IndiaAdditionalInfoJsonUnmarshaller.getInstance().unmarshall(context));
                }
                if (context.testExpression("israelAdditionalInfo", targetDepth)) {
                    context.nextToken();
                    additionalInfoResponse.setIsraelAdditionalInfo(IsraelAdditionalInfoJsonUnmarshaller.getInstance().unmarshall(context));
                }
                if (context.testExpression("italyAdditionalInfo", targetDepth)) {
                    context.nextToken();
                    additionalInfoResponse.setItalyAdditionalInfo(ItalyAdditionalInfoJsonUnmarshaller.getInstance().unmarshall(context));
                }
                if (context.testExpression("kenyaAdditionalInfo", targetDepth)) {
                    context.nextToken();
                    additionalInfoResponse.setKenyaAdditionalInfo(KenyaAdditionalInfoJsonUnmarshaller.getInstance().unmarshall(context));
                }
                if (context.testExpression("malaysiaAdditionalInfo", targetDepth)) {
                    context.nextToken();
                    additionalInfoResponse.setMalaysiaAdditionalInfo(MalaysiaAdditionalInfoJsonUnmarshaller.getInstance().unmarshall(context));
                }
                if (context.testExpression("polandAdditionalInfo", targetDepth)) {
                    context.nextToken();
                    additionalInfoResponse.setPolandAdditionalInfo(PolandAdditionalInfoJsonUnmarshaller.getInstance().unmarshall(context));
                }
                if (context.testExpression("romaniaAdditionalInfo", targetDepth)) {
                    context.nextToken();
                    additionalInfoResponse.setRomaniaAdditionalInfo(RomaniaAdditionalInfoJsonUnmarshaller.getInstance().unmarshall(context));
                }
                if (context.testExpression("saudiArabiaAdditionalInfo", targetDepth)) {
                    context.nextToken();
                    additionalInfoResponse.setSaudiArabiaAdditionalInfo(SaudiArabiaAdditionalInfoJsonUnmarshaller.getInstance().unmarshall(context));
                }
                if (context.testExpression("southKoreaAdditionalInfo", targetDepth)) {
                    context.nextToken();
                    additionalInfoResponse.setSouthKoreaAdditionalInfo(SouthKoreaAdditionalInfoJsonUnmarshaller.getInstance().unmarshall(context));
                }
                if (context.testExpression("spainAdditionalInfo", targetDepth)) {
                    context.nextToken();
                    additionalInfoResponse.setSpainAdditionalInfo(SpainAdditionalInfoJsonUnmarshaller.getInstance().unmarshall(context));
                }
                if (context.testExpression("turkeyAdditionalInfo", targetDepth)) {
                    context.nextToken();
                    additionalInfoResponse.setTurkeyAdditionalInfo(TurkeyAdditionalInfoJsonUnmarshaller.getInstance().unmarshall(context));
                }
                if (context.testExpression("ukraineAdditionalInfo", targetDepth)) {
                    context.nextToken();
                    additionalInfoResponse.setUkraineAdditionalInfo(UkraineAdditionalInfoJsonUnmarshaller.getInstance().unmarshall(context));
                }
            } else if (token == END_ARRAY || token == END_OBJECT) {
                if (context.getLastParsedParentElement() == null || context.getLastParsedParentElement().equals(currentParentElement)) {
                    if (context.getCurrentDepth() <= originalDepth)
                        break;
                }
            }
            token = context.nextToken();
        }

        return additionalInfoResponse;
    }

    private static AdditionalInfoResponseJsonUnmarshaller instance;

    public static AdditionalInfoResponseJsonUnmarshaller getInstance() {
        if (instance == null)
            instance = new AdditionalInfoResponseJsonUnmarshaller();
        return instance;
    }
}
