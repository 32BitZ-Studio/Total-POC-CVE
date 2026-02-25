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
package com.amazonaws.services.taxsettings;

import javax.annotation.Generated;

import com.amazonaws.services.taxsettings.model.*;

/**
 * Abstract implementation of {@code AWSTaxSettingsAsync}. Convenient method forms pass through to the corresponding
 * overload that takes a request object and an {@code AsyncHandler}, which throws an
 * {@code UnsupportedOperationException}.
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class AbstractAWSTaxSettingsAsync extends AbstractAWSTaxSettings implements AWSTaxSettingsAsync {

    protected AbstractAWSTaxSettingsAsync() {
    }

    @Override
    public java.util.concurrent.Future<BatchDeleteTaxRegistrationResult> batchDeleteTaxRegistrationAsync(BatchDeleteTaxRegistrationRequest request) {

        return batchDeleteTaxRegistrationAsync(request, null);
    }

    @Override
    public java.util.concurrent.Future<BatchDeleteTaxRegistrationResult> batchDeleteTaxRegistrationAsync(BatchDeleteTaxRegistrationRequest request,
            com.amazonaws.handlers.AsyncHandler<BatchDeleteTaxRegistrationRequest, BatchDeleteTaxRegistrationResult> asyncHandler) {

        throw new java.lang.UnsupportedOperationException();
    }

    @Override
    public java.util.concurrent.Future<BatchPutTaxRegistrationResult> batchPutTaxRegistrationAsync(BatchPutTaxRegistrationRequest request) {

        return batchPutTaxRegistrationAsync(request, null);
    }

    @Override
    public java.util.concurrent.Future<BatchPutTaxRegistrationResult> batchPutTaxRegistrationAsync(BatchPutTaxRegistrationRequest request,
            com.amazonaws.handlers.AsyncHandler<BatchPutTaxRegistrationRequest, BatchPutTaxRegistrationResult> asyncHandler) {

        throw new java.lang.UnsupportedOperationException();
    }

    @Override
    public java.util.concurrent.Future<DeleteTaxRegistrationResult> deleteTaxRegistrationAsync(DeleteTaxRegistrationRequest request) {

        return deleteTaxRegistrationAsync(request, null);
    }

    @Override
    public java.util.concurrent.Future<DeleteTaxRegistrationResult> deleteTaxRegistrationAsync(DeleteTaxRegistrationRequest request,
            com.amazonaws.handlers.AsyncHandler<DeleteTaxRegistrationRequest, DeleteTaxRegistrationResult> asyncHandler) {

        throw new java.lang.UnsupportedOperationException();
    }

    @Override
    public java.util.concurrent.Future<GetTaxRegistrationResult> getTaxRegistrationAsync(GetTaxRegistrationRequest request) {

        return getTaxRegistrationAsync(request, null);
    }

    @Override
    public java.util.concurrent.Future<GetTaxRegistrationResult> getTaxRegistrationAsync(GetTaxRegistrationRequest request,
            com.amazonaws.handlers.AsyncHandler<GetTaxRegistrationRequest, GetTaxRegistrationResult> asyncHandler) {

        throw new java.lang.UnsupportedOperationException();
    }

    @Override
    public java.util.concurrent.Future<GetTaxRegistrationDocumentResult> getTaxRegistrationDocumentAsync(GetTaxRegistrationDocumentRequest request) {

        return getTaxRegistrationDocumentAsync(request, null);
    }

    @Override
    public java.util.concurrent.Future<GetTaxRegistrationDocumentResult> getTaxRegistrationDocumentAsync(GetTaxRegistrationDocumentRequest request,
            com.amazonaws.handlers.AsyncHandler<GetTaxRegistrationDocumentRequest, GetTaxRegistrationDocumentResult> asyncHandler) {

        throw new java.lang.UnsupportedOperationException();
    }

    @Override
    public java.util.concurrent.Future<ListTaxRegistrationsResult> listTaxRegistrationsAsync(ListTaxRegistrationsRequest request) {

        return listTaxRegistrationsAsync(request, null);
    }

    @Override
    public java.util.concurrent.Future<ListTaxRegistrationsResult> listTaxRegistrationsAsync(ListTaxRegistrationsRequest request,
            com.amazonaws.handlers.AsyncHandler<ListTaxRegistrationsRequest, ListTaxRegistrationsResult> asyncHandler) {

        throw new java.lang.UnsupportedOperationException();
    }

    @Override
    public java.util.concurrent.Future<PutTaxRegistrationResult> putTaxRegistrationAsync(PutTaxRegistrationRequest request) {

        return putTaxRegistrationAsync(request, null);
    }

    @Override
    public java.util.concurrent.Future<PutTaxRegistrationResult> putTaxRegistrationAsync(PutTaxRegistrationRequest request,
            com.amazonaws.handlers.AsyncHandler<PutTaxRegistrationRequest, PutTaxRegistrationResult> asyncHandler) {

        throw new java.lang.UnsupportedOperationException();
    }

}
