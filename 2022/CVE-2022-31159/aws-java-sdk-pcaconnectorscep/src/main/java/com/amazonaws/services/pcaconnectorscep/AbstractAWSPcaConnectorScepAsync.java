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

/**
 * Abstract implementation of {@code AWSPcaConnectorScepAsync}. Convenient method forms pass through to the
 * corresponding overload that takes a request object and an {@code AsyncHandler}, which throws an
 * {@code UnsupportedOperationException}.
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class AbstractAWSPcaConnectorScepAsync extends AbstractAWSPcaConnectorScep implements AWSPcaConnectorScepAsync {

    protected AbstractAWSPcaConnectorScepAsync() {
    }

    @Override
    public java.util.concurrent.Future<CreateChallengeResult> createChallengeAsync(CreateChallengeRequest request) {

        return createChallengeAsync(request, null);
    }

    @Override
    public java.util.concurrent.Future<CreateChallengeResult> createChallengeAsync(CreateChallengeRequest request,
            com.amazonaws.handlers.AsyncHandler<CreateChallengeRequest, CreateChallengeResult> asyncHandler) {

        throw new java.lang.UnsupportedOperationException();
    }

    @Override
    public java.util.concurrent.Future<CreateConnectorResult> createConnectorAsync(CreateConnectorRequest request) {

        return createConnectorAsync(request, null);
    }

    @Override
    public java.util.concurrent.Future<CreateConnectorResult> createConnectorAsync(CreateConnectorRequest request,
            com.amazonaws.handlers.AsyncHandler<CreateConnectorRequest, CreateConnectorResult> asyncHandler) {

        throw new java.lang.UnsupportedOperationException();
    }

    @Override
    public java.util.concurrent.Future<DeleteChallengeResult> deleteChallengeAsync(DeleteChallengeRequest request) {

        return deleteChallengeAsync(request, null);
    }

    @Override
    public java.util.concurrent.Future<DeleteChallengeResult> deleteChallengeAsync(DeleteChallengeRequest request,
            com.amazonaws.handlers.AsyncHandler<DeleteChallengeRequest, DeleteChallengeResult> asyncHandler) {

        throw new java.lang.UnsupportedOperationException();
    }

    @Override
    public java.util.concurrent.Future<DeleteConnectorResult> deleteConnectorAsync(DeleteConnectorRequest request) {

        return deleteConnectorAsync(request, null);
    }

    @Override
    public java.util.concurrent.Future<DeleteConnectorResult> deleteConnectorAsync(DeleteConnectorRequest request,
            com.amazonaws.handlers.AsyncHandler<DeleteConnectorRequest, DeleteConnectorResult> asyncHandler) {

        throw new java.lang.UnsupportedOperationException();
    }

    @Override
    public java.util.concurrent.Future<GetChallengeMetadataResult> getChallengeMetadataAsync(GetChallengeMetadataRequest request) {

        return getChallengeMetadataAsync(request, null);
    }

    @Override
    public java.util.concurrent.Future<GetChallengeMetadataResult> getChallengeMetadataAsync(GetChallengeMetadataRequest request,
            com.amazonaws.handlers.AsyncHandler<GetChallengeMetadataRequest, GetChallengeMetadataResult> asyncHandler) {

        throw new java.lang.UnsupportedOperationException();
    }

    @Override
    public java.util.concurrent.Future<GetChallengePasswordResult> getChallengePasswordAsync(GetChallengePasswordRequest request) {

        return getChallengePasswordAsync(request, null);
    }

    @Override
    public java.util.concurrent.Future<GetChallengePasswordResult> getChallengePasswordAsync(GetChallengePasswordRequest request,
            com.amazonaws.handlers.AsyncHandler<GetChallengePasswordRequest, GetChallengePasswordResult> asyncHandler) {

        throw new java.lang.UnsupportedOperationException();
    }

    @Override
    public java.util.concurrent.Future<GetConnectorResult> getConnectorAsync(GetConnectorRequest request) {

        return getConnectorAsync(request, null);
    }

    @Override
    public java.util.concurrent.Future<GetConnectorResult> getConnectorAsync(GetConnectorRequest request,
            com.amazonaws.handlers.AsyncHandler<GetConnectorRequest, GetConnectorResult> asyncHandler) {

        throw new java.lang.UnsupportedOperationException();
    }

    @Override
    public java.util.concurrent.Future<ListChallengeMetadataResult> listChallengeMetadataAsync(ListChallengeMetadataRequest request) {

        return listChallengeMetadataAsync(request, null);
    }

    @Override
    public java.util.concurrent.Future<ListChallengeMetadataResult> listChallengeMetadataAsync(ListChallengeMetadataRequest request,
            com.amazonaws.handlers.AsyncHandler<ListChallengeMetadataRequest, ListChallengeMetadataResult> asyncHandler) {

        throw new java.lang.UnsupportedOperationException();
    }

    @Override
    public java.util.concurrent.Future<ListConnectorsResult> listConnectorsAsync(ListConnectorsRequest request) {

        return listConnectorsAsync(request, null);
    }

    @Override
    public java.util.concurrent.Future<ListConnectorsResult> listConnectorsAsync(ListConnectorsRequest request,
            com.amazonaws.handlers.AsyncHandler<ListConnectorsRequest, ListConnectorsResult> asyncHandler) {

        throw new java.lang.UnsupportedOperationException();
    }

    @Override
    public java.util.concurrent.Future<ListTagsForResourceResult> listTagsForResourceAsync(ListTagsForResourceRequest request) {

        return listTagsForResourceAsync(request, null);
    }

    @Override
    public java.util.concurrent.Future<ListTagsForResourceResult> listTagsForResourceAsync(ListTagsForResourceRequest request,
            com.amazonaws.handlers.AsyncHandler<ListTagsForResourceRequest, ListTagsForResourceResult> asyncHandler) {

        throw new java.lang.UnsupportedOperationException();
    }

    @Override
    public java.util.concurrent.Future<TagResourceResult> tagResourceAsync(TagResourceRequest request) {

        return tagResourceAsync(request, null);
    }

    @Override
    public java.util.concurrent.Future<TagResourceResult> tagResourceAsync(TagResourceRequest request,
            com.amazonaws.handlers.AsyncHandler<TagResourceRequest, TagResourceResult> asyncHandler) {

        throw new java.lang.UnsupportedOperationException();
    }

    @Override
    public java.util.concurrent.Future<UntagResourceResult> untagResourceAsync(UntagResourceRequest request) {

        return untagResourceAsync(request, null);
    }

    @Override
    public java.util.concurrent.Future<UntagResourceResult> untagResourceAsync(UntagResourceRequest request,
            com.amazonaws.handlers.AsyncHandler<UntagResourceRequest, UntagResourceResult> asyncHandler) {

        throw new java.lang.UnsupportedOperationException();
    }

}
