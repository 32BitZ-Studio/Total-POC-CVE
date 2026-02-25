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
package com.amazonaws.services.pcaconnectorscep;

import javax.annotation.Generated;

import com.amazonaws.services.pcaconnectorscep.model.*;
import com.amazonaws.*;

/**
 * Abstract implementation of {@code AWSPcaConnectorScep}. Convenient method forms pass through to the corresponding
 * overload that takes a request object, which throws an {@code UnsupportedOperationException}.
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class AbstractAWSPcaConnectorScep implements AWSPcaConnectorScep {

    protected AbstractAWSPcaConnectorScep() {
    }

    @Override
    public CreateChallengeResult createChallenge(CreateChallengeRequest request) {
        throw new java.lang.UnsupportedOperationException();
    }

    @Override
    public CreateConnectorResult createConnector(CreateConnectorRequest request) {
        throw new java.lang.UnsupportedOperationException();
    }

    @Override
    public DeleteChallengeResult deleteChallenge(DeleteChallengeRequest request) {
        throw new java.lang.UnsupportedOperationException();
    }

    @Override
    public DeleteConnectorResult deleteConnector(DeleteConnectorRequest request) {
        throw new java.lang.UnsupportedOperationException();
    }

    @Override
    public GetChallengeMetadataResult getChallengeMetadata(GetChallengeMetadataRequest request) {
        throw new java.lang.UnsupportedOperationException();
    }

    @Override
    public GetChallengePasswordResult getChallengePassword(GetChallengePasswordRequest request) {
        throw new java.lang.UnsupportedOperationException();
    }

    @Override
    public GetConnectorResult getConnector(GetConnectorRequest request) {
        throw new java.lang.UnsupportedOperationException();
    }

    @Override
    public ListChallengeMetadataResult listChallengeMetadata(ListChallengeMetadataRequest request) {
        throw new java.lang.UnsupportedOperationException();
    }

    @Override
    public ListConnectorsResult listConnectors(ListConnectorsRequest request) {
        throw new java.lang.UnsupportedOperationException();
    }

    @Override
    public ListTagsForResourceResult listTagsForResource(ListTagsForResourceRequest request) {
        throw new java.lang.UnsupportedOperationException();
    }

    @Override
    public TagResourceResult tagResource(TagResourceRequest request) {
        throw new java.lang.UnsupportedOperationException();
    }

    @Override
    public UntagResourceResult untagResource(UntagResourceRequest request) {
        throw new java.lang.UnsupportedOperationException();
    }

    @Override
    public void shutdown() {
        throw new java.lang.UnsupportedOperationException();
    }

    @Override
    public com.amazonaws.ResponseMetadata getCachedResponseMetadata(com.amazonaws.AmazonWebServiceRequest request) {
        throw new java.lang.UnsupportedOperationException();
    }

}
