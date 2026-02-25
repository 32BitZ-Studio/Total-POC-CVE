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
import com.amazonaws.client.AwsAsyncClientParams;
import com.amazonaws.annotation.ThreadSafe;

import java.util.concurrent.ExecutorService;

/**
 * Client for accessing Tax Settings asynchronously. Each asynchronous method will return a Java Future object
 * representing the asynchronous operation; overloads which accept an {@code AsyncHandler} can be used to receive
 * notification when an asynchronous operation completes.
 * <p>
 * <p>
 * You can use the tax setting API to programmatically set, modify, and delete the tax registration number (TRN),
 * associated business legal name, and address (Collectively referred to as "TRN information"). You can also
 * programmatically view TRN information and tax addresses ("Tax profiles").
 * </p>
 * <p>
 * You can use this API to automate your TRN information settings instead of manually using the console.
 * </p>
 * <p>
 * Service Endpoint
 * </p>
 * <ul>
 * <li>
 * <p>
 * https://tax.us-east-1.amazonaws.com
 * </p>
 * </li>
 * </ul>
 */
@ThreadSafe
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class AWSTaxSettingsAsyncClient extends AWSTaxSettingsClient implements AWSTaxSettingsAsync {

    private static final int DEFAULT_THREAD_POOL_SIZE = 50;

    private final java.util.concurrent.ExecutorService executorService;

    public static AWSTaxSettingsAsyncClientBuilder asyncBuilder() {
        return AWSTaxSettingsAsyncClientBuilder.standard();
    }

    /**
     * Constructs a new asynchronous client to invoke service methods on Tax Settings using the specified parameters.
     *
     * @param asyncClientParams
     *        Object providing client parameters.
     */
    AWSTaxSettingsAsyncClient(AwsAsyncClientParams asyncClientParams) {
        this(asyncClientParams, false);
    }

    /**
     * Constructs a new asynchronous client to invoke service methods on Tax Settings using the specified parameters.
     *
     * @param asyncClientParams
     *        Object providing client parameters.
     * @param endpointDiscoveryEnabled
     *        true will enable endpoint discovery if the service supports it.
     */
    AWSTaxSettingsAsyncClient(AwsAsyncClientParams asyncClientParams, boolean endpointDiscoveryEnabled) {
        super(asyncClientParams, endpointDiscoveryEnabled);
        this.executorService = asyncClientParams.getExecutor();
    }

    /**
     * Returns the executor service used by this client to execute async requests.
     *
     * @return The executor service used by this client to execute async requests.
     */
    public ExecutorService getExecutorService() {
        return executorService;
    }

    @Override
    public java.util.concurrent.Future<BatchDeleteTaxRegistrationResult> batchDeleteTaxRegistrationAsync(BatchDeleteTaxRegistrationRequest request) {

        return batchDeleteTaxRegistrationAsync(request, null);
    }

    @Override
    public java.util.concurrent.Future<BatchDeleteTaxRegistrationResult> batchDeleteTaxRegistrationAsync(final BatchDeleteTaxRegistrationRequest request,
            final com.amazonaws.handlers.AsyncHandler<BatchDeleteTaxRegistrationRequest, BatchDeleteTaxRegistrationResult> asyncHandler) {
        final BatchDeleteTaxRegistrationRequest finalRequest = beforeClientExecution(request);

        return executorService.submit(new java.util.concurrent.Callable<BatchDeleteTaxRegistrationResult>() {
            @Override
            public BatchDeleteTaxRegistrationResult call() throws Exception {
                BatchDeleteTaxRegistrationResult result = null;

                try {
                    result = executeBatchDeleteTaxRegistration(finalRequest);
                } catch (Exception ex) {
                    if (asyncHandler != null) {
                        asyncHandler.onError(ex);
                    }
                    throw ex;
                }

                if (asyncHandler != null) {
                    asyncHandler.onSuccess(finalRequest, result);
                }
                return result;
            }
        });
    }

    @Override
    public java.util.concurrent.Future<BatchPutTaxRegistrationResult> batchPutTaxRegistrationAsync(BatchPutTaxRegistrationRequest request) {

        return batchPutTaxRegistrationAsync(request, null);
    }

    @Override
    public java.util.concurrent.Future<BatchPutTaxRegistrationResult> batchPutTaxRegistrationAsync(final BatchPutTaxRegistrationRequest request,
            final com.amazonaws.handlers.AsyncHandler<BatchPutTaxRegistrationRequest, BatchPutTaxRegistrationResult> asyncHandler) {
        final BatchPutTaxRegistrationRequest finalRequest = beforeClientExecution(request);

        return executorService.submit(new java.util.concurrent.Callable<BatchPutTaxRegistrationResult>() {
            @Override
            public BatchPutTaxRegistrationResult call() throws Exception {
                BatchPutTaxRegistrationResult result = null;

                try {
                    result = executeBatchPutTaxRegistration(finalRequest);
                } catch (Exception ex) {
                    if (asyncHandler != null) {
                        asyncHandler.onError(ex);
                    }
                    throw ex;
                }

                if (asyncHandler != null) {
                    asyncHandler.onSuccess(finalRequest, result);
                }
                return result;
            }
        });
    }

    @Override
    public java.util.concurrent.Future<DeleteTaxRegistrationResult> deleteTaxRegistrationAsync(DeleteTaxRegistrationRequest request) {

        return deleteTaxRegistrationAsync(request, null);
    }

    @Override
    public java.util.concurrent.Future<DeleteTaxRegistrationResult> deleteTaxRegistrationAsync(final DeleteTaxRegistrationRequest request,
            final com.amazonaws.handlers.AsyncHandler<DeleteTaxRegistrationRequest, DeleteTaxRegistrationResult> asyncHandler) {
        final DeleteTaxRegistrationRequest finalRequest = beforeClientExecution(request);

        return executorService.submit(new java.util.concurrent.Callable<DeleteTaxRegistrationResult>() {
            @Override
            public DeleteTaxRegistrationResult call() throws Exception {
                DeleteTaxRegistrationResult result = null;

                try {
                    result = executeDeleteTaxRegistration(finalRequest);
                } catch (Exception ex) {
                    if (asyncHandler != null) {
                        asyncHandler.onError(ex);
                    }
                    throw ex;
                }

                if (asyncHandler != null) {
                    asyncHandler.onSuccess(finalRequest, result);
                }
                return result;
            }
        });
    }

    @Override
    public java.util.concurrent.Future<GetTaxRegistrationResult> getTaxRegistrationAsync(GetTaxRegistrationRequest request) {

        return getTaxRegistrationAsync(request, null);
    }

    @Override
    public java.util.concurrent.Future<GetTaxRegistrationResult> getTaxRegistrationAsync(final GetTaxRegistrationRequest request,
            final com.amazonaws.handlers.AsyncHandler<GetTaxRegistrationRequest, GetTaxRegistrationResult> asyncHandler) {
        final GetTaxRegistrationRequest finalRequest = beforeClientExecution(request);

        return executorService.submit(new java.util.concurrent.Callable<GetTaxRegistrationResult>() {
            @Override
            public GetTaxRegistrationResult call() throws Exception {
                GetTaxRegistrationResult result = null;

                try {
                    result = executeGetTaxRegistration(finalRequest);
                } catch (Exception ex) {
                    if (asyncHandler != null) {
                        asyncHandler.onError(ex);
                    }
                    throw ex;
                }

                if (asyncHandler != null) {
                    asyncHandler.onSuccess(finalRequest, result);
                }
                return result;
            }
        });
    }

    @Override
    public java.util.concurrent.Future<GetTaxRegistrationDocumentResult> getTaxRegistrationDocumentAsync(GetTaxRegistrationDocumentRequest request) {

        return getTaxRegistrationDocumentAsync(request, null);
    }

    @Override
    public java.util.concurrent.Future<GetTaxRegistrationDocumentResult> getTaxRegistrationDocumentAsync(final GetTaxRegistrationDocumentRequest request,
            final com.amazonaws.handlers.AsyncHandler<GetTaxRegistrationDocumentRequest, GetTaxRegistrationDocumentResult> asyncHandler) {
        final GetTaxRegistrationDocumentRequest finalRequest = beforeClientExecution(request);

        return executorService.submit(new java.util.concurrent.Callable<GetTaxRegistrationDocumentResult>() {
            @Override
            public GetTaxRegistrationDocumentResult call() throws Exception {
                GetTaxRegistrationDocumentResult result = null;

                try {
                    result = executeGetTaxRegistrationDocument(finalRequest);
                } catch (Exception ex) {
                    if (asyncHandler != null) {
                        asyncHandler.onError(ex);
                    }
                    throw ex;
                }

                if (asyncHandler != null) {
                    asyncHandler.onSuccess(finalRequest, result);
                }
                return result;
            }
        });
    }

    @Override
    public java.util.concurrent.Future<ListTaxRegistrationsResult> listTaxRegistrationsAsync(ListTaxRegistrationsRequest request) {

        return listTaxRegistrationsAsync(request, null);
    }

    @Override
    public java.util.concurrent.Future<ListTaxRegistrationsResult> listTaxRegistrationsAsync(final ListTaxRegistrationsRequest request,
            final com.amazonaws.handlers.AsyncHandler<ListTaxRegistrationsRequest, ListTaxRegistrationsResult> asyncHandler) {
        final ListTaxRegistrationsRequest finalRequest = beforeClientExecution(request);

        return executorService.submit(new java.util.concurrent.Callable<ListTaxRegistrationsResult>() {
            @Override
            public ListTaxRegistrationsResult call() throws Exception {
                ListTaxRegistrationsResult result = null;

                try {
                    result = executeListTaxRegistrations(finalRequest);
                } catch (Exception ex) {
                    if (asyncHandler != null) {
                        asyncHandler.onError(ex);
                    }
                    throw ex;
                }

                if (asyncHandler != null) {
                    asyncHandler.onSuccess(finalRequest, result);
                }
                return result;
            }
        });
    }

    @Override
    public java.util.concurrent.Future<PutTaxRegistrationResult> putTaxRegistrationAsync(PutTaxRegistrationRequest request) {

        return putTaxRegistrationAsync(request, null);
    }

    @Override
    public java.util.concurrent.Future<PutTaxRegistrationResult> putTaxRegistrationAsync(final PutTaxRegistrationRequest request,
            final com.amazonaws.handlers.AsyncHandler<PutTaxRegistrationRequest, PutTaxRegistrationResult> asyncHandler) {
        final PutTaxRegistrationRequest finalRequest = beforeClientExecution(request);

        return executorService.submit(new java.util.concurrent.Callable<PutTaxRegistrationResult>() {
            @Override
            public PutTaxRegistrationResult call() throws Exception {
                PutTaxRegistrationResult result = null;

                try {
                    result = executePutTaxRegistration(finalRequest);
                } catch (Exception ex) {
                    if (asyncHandler != null) {
                        asyncHandler.onError(ex);
                    }
                    throw ex;
                }

                if (asyncHandler != null) {
                    asyncHandler.onSuccess(finalRequest, result);
                }
                return result;
            }
        });
    }

    /**
     * Shuts down the client, releasing all managed resources. This includes forcibly terminating all pending
     * asynchronous service calls. Clients who wish to give pending asynchronous service calls time to complete should
     * call {@code getExecutorService().shutdown()} followed by {@code getExecutorService().awaitTermination()} prior to
     * calling this method.
     */
    @Override
    public void shutdown() {
        super.shutdown();
        executorService.shutdownNow();
    }
}
