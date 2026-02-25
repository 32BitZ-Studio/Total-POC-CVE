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

import javax.annotation.Generated;

import com.amazonaws.SdkClientException;
import com.amazonaws.services.qapps.model.*;

import com.amazonaws.protocol.*;
import com.amazonaws.annotation.SdkInternalApi;

/**
 * ImportDocumentRequestMarshaller
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
@SdkInternalApi
public class ImportDocumentRequestMarshaller {

    private static final MarshallingInfo<String> INSTANCEID_BINDING = MarshallingInfo.builder(MarshallingType.STRING).marshallLocation(MarshallLocation.HEADER)
            .marshallLocationName("instance-id").build();
    private static final MarshallingInfo<String> CARDID_BINDING = MarshallingInfo.builder(MarshallingType.STRING).marshallLocation(MarshallLocation.PAYLOAD)
            .marshallLocationName("cardId").build();
    private static final MarshallingInfo<String> APPID_BINDING = MarshallingInfo.builder(MarshallingType.STRING).marshallLocation(MarshallLocation.PAYLOAD)
            .marshallLocationName("appId").build();
    private static final MarshallingInfo<String> FILECONTENTSBASE64_BINDING = MarshallingInfo.builder(MarshallingType.STRING)
            .marshallLocation(MarshallLocation.PAYLOAD).marshallLocationName("fileContentsBase64").build();
    private static final MarshallingInfo<String> FILENAME_BINDING = MarshallingInfo.builder(MarshallingType.STRING).marshallLocation(MarshallLocation.PAYLOAD)
            .marshallLocationName("fileName").build();
    private static final MarshallingInfo<String> SCOPE_BINDING = MarshallingInfo.builder(MarshallingType.STRING).marshallLocation(MarshallLocation.PAYLOAD)
            .marshallLocationName("scope").build();
    private static final MarshallingInfo<String> SESSIONID_BINDING = MarshallingInfo.builder(MarshallingType.STRING).marshallLocation(MarshallLocation.PAYLOAD)
            .marshallLocationName("sessionId").build();

    private static final ImportDocumentRequestMarshaller instance = new ImportDocumentRequestMarshaller();

    public static ImportDocumentRequestMarshaller getInstance() {
        return instance;
    }

    /**
     * Marshall the given parameter object.
     */
    public void marshall(ImportDocumentRequest importDocumentRequest, ProtocolMarshaller protocolMarshaller) {

        if (importDocumentRequest == null) {
            throw new SdkClientException("Invalid argument passed to marshall(...)");
        }

        try {
            protocolMarshaller.marshall(importDocumentRequest.getInstanceId(), INSTANCEID_BINDING);
            protocolMarshaller.marshall(importDocumentRequest.getCardId(), CARDID_BINDING);
            protocolMarshaller.marshall(importDocumentRequest.getAppId(), APPID_BINDING);
            protocolMarshaller.marshall(importDocumentRequest.getFileContentsBase64(), FILECONTENTSBASE64_BINDING);
            protocolMarshaller.marshall(importDocumentRequest.getFileName(), FILENAME_BINDING);
            protocolMarshaller.marshall(importDocumentRequest.getScope(), SCOPE_BINDING);
            protocolMarshaller.marshall(importDocumentRequest.getSessionId(), SESSIONID_BINDING);
        } catch (Exception e) {
            throw new SdkClientException("Unable to marshall request to JSON: " + e.getMessage(), e);
        }
    }

}
