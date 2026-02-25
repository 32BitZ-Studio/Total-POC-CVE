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
import com.amazonaws.client.AwsAsyncClientParams;
import com.amazonaws.annotation.ThreadSafe;

import java.util.concurrent.ExecutorService;

/**
 * Client for accessing Private CA Connector for SCEP asynchronously. Each asynchronous method will return a Java Future
 * object representing the asynchronous operation; overloads which accept an {@code AsyncHandler} can be used to receive
 * notification when an asynchronous operation completes.
 * <p>
 * <note>
 * <p>
 * Connector for SCEP (Preview) is in preview release for Amazon Web Services Private Certificate Authority and is
 * subject to change.
 * </p>
 * </note>
 * <p>
 * Connector for SCEP (Preview) creates a connector between Amazon Web Services Private CA and your SCEP-enabled clients
 * and devices. For more information, see <a
 * href="https://docs.aws.amazon.com/privateca/latest/userguide/scep-connector.html">Connector for SCEP</a> in the
 * <i>Amazon Web Services Private CA User Guide</i>.
 * </p>
 */
@ThreadSafe
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class AWSPcaConnectorScepAsyncClient extends AWSPcaConnectorScepClient implements AWSPcaConnectorScepAsync {

    private static final int DEFAULT_THREAD_POOL_SIZE = 50;

    private final java.util.concurrent.ExecutorService executorService;

    public static AWSPcaConnectorScepAsyncClientBuilder asyncBuilder() {
        return AWSPcaConnectorScepAsyncClientBuilder.standard();
    }

    /**
     * Constructs a new asynchronous client to invoke service methods on Private CA Connector for SCEP using the
     * specified parameters.
     *
     * @param asyncClientParams
     *        Object providing client parameters.
     */
    AWSPcaConnectorScepAsyncClient(AwsAsyncClientParams asyncClientParams) {
        this(asyncClientParams, false);
    }

    /**
     * Constructs a new asynchronous client to invoke service methods on Private CA Connector for SCEP using the
     * specified parameters.
     *
     * @param asyncClientParams
     *        Object providing client parameters.
     * @param endpointDiscoveryEnabled
     *        true will enable endpoint discovery if the service supports it.
     */
    AWSPcaConnectorScepAsyncClient(AwsAsyncClientParams asyncClientParams, boolean endpointDiscoveryEnabled) {
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
    public java.util.concurrent.Future<CreateChallengeResult> createChallengeAsync(CreateChallengeRequest request) {

        return createChallengeAsync(request, null);
    }

    @Override
    public java.util.concurrent.Future<CreateChallengeResult> createChallengeAsync(final CreateChallengeRequest request,
            final com.amazonaws.handlers.AsyncHandler<CreateChallengeRequest, CreateChallengeResult> asyncHandler) {
        final CreateChallengeRequest finalRequest = beforeClientExecution(request);

        return executorService.submit(new java.util.concurrent.Callable<CreateChallengeResult>() {
            @Override
            public CreateChallengeResult call() throws Exception {
                CreateChallengeResult result = null;

                try {
                    result = executeCreateChallenge(finalRequest);
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
    public java.util.concurrent.Future<CreateConnectorResult> createConnectorAsync(CreateConnectorRequest request) {

        return createConnectorAsync(request, null);
    }

    @Override
    public java.util.concurrent.Future<CreateConnectorResult> createConnectorAsync(final CreateConnectorRequest request,
            final com.amazonaws.handlers.AsyncHandler<CreateConnectorRequest, CreateConnectorResult> asyncHandler) {
        final CreateConnectorRequest finalRequest = beforeClientExecution(request);

        return executorService.submit(new java.util.concurrent.Callable<CreateConnectorResult>() {
            @Override
            public CreateConnectorResult call() throws Exception {
                CreateConnectorResult result = null;

                try {
                    result = executeCreateConnector(finalRequest);
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
    public java.util.concurrent.Future<DeleteChallengeResult> deleteChallengeAsync(DeleteChallengeRequest request) {

        return deleteChallengeAsync(request, null);
    }

    @Override
    public java.util.concurrent.Future<DeleteChallengeResult> deleteChallengeAsync(final DeleteChallengeRequest request,
            final com.amazonaws.handlers.AsyncHandler<DeleteChallengeRequest, DeleteChallengeResult> asyncHandler) {
        final DeleteChallengeRequest finalRequest = beforeClientExecution(request);

        return executorService.submit(new java.util.concurrent.Callable<DeleteChallengeResult>() {
            @Override
            public DeleteChallengeResult call() throws Exception {
                DeleteChallengeResult result = null;

                try {
                    result = executeDeleteChallenge(finalRequest);
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
    public java.util.concurrent.Future<DeleteConnectorResult> deleteConnectorAsync(DeleteConnectorRequest request) {

        return deleteConnectorAsync(request, null);
    }

    @Override
    public java.util.concurrent.Future<DeleteConnectorResult> deleteConnectorAsync(final DeleteConnectorRequest request,
            final com.amazonaws.handlers.AsyncHandler<DeleteConnectorRequest, DeleteConnectorResult> asyncHandler) {
        final DeleteConnectorRequest finalRequest = beforeClientExecution(request);

        return executorService.submit(new java.util.concurrent.Callable<DeleteConnectorResult>() {
            @Override
            public DeleteConnectorResult call() throws Exception {
                DeleteConnectorResult result = null;

                try {
                    result = executeDeleteConnector(finalRequest);
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
    public java.util.concurrent.Future<GetChallengeMetadataResult> getChallengeMetadataAsync(GetChallengeMetadataRequest request) {

        return getChallengeMetadataAsync(request, null);
    }

    @Override
    public java.util.concurrent.Future<GetChallengeMetadataResult> getChallengeMetadataAsync(final GetChallengeMetadataRequest request,
            final com.amazonaws.handlers.AsyncHandler<GetChallengeMetadataRequest, GetChallengeMetadataResult> asyncHandler) {
        final GetChallengeMetadataRequest finalRequest = beforeClientExecution(request);

        return executorService.submit(new java.util.concurrent.Callable<GetChallengeMetadataResult>() {
            @Override
            public GetChallengeMetadataResult call() throws Exception {
                GetChallengeMetadataResult result = null;

                try {
                    result = executeGetChallengeMetadata(finalRequest);
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
    public java.util.concurrent.Future<GetChallengePasswordResult> getChallengePasswordAsync(GetChallengePasswordRequest request) {

        return getChallengePasswordAsync(request, null);
    }

    @Override
    public java.util.concurrent.Future<GetChallengePasswordResult> getChallengePasswordAsync(final GetChallengePasswordRequest request,
            final com.amazonaws.handlers.AsyncHandler<GetChallengePasswordRequest, GetChallengePasswordResult> asyncHandler) {
        final GetChallengePasswordRequest finalRequest = beforeClientExecution(request);

        return executorService.submit(new java.util.concurrent.Callable<GetChallengePasswordResult>() {
            @Override
            public GetChallengePasswordResult call() throws Exception {
                GetChallengePasswordResult result = null;

                try {
                    result = executeGetChallengePassword(finalRequest);
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
    public java.util.concurrent.Future<GetConnectorResult> getConnectorAsync(GetConnectorRequest request) {

        return getConnectorAsync(request, null);
    }

    @Override
    public java.util.concurrent.Future<GetConnectorResult> getConnectorAsync(final GetConnectorRequest request,
            final com.amazonaws.handlers.AsyncHandler<GetConnectorRequest, GetConnectorResult> asyncHandler) {
        final GetConnectorRequest finalRequest = beforeClientExecution(request);

        return executorService.submit(new java.util.concurrent.Callable<GetConnectorResult>() {
            @Override
            public GetConnectorResult call() throws Exception {
                GetConnectorResult result = null;

                try {
                    result = executeGetConnector(finalRequest);
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
    public java.util.concurrent.Future<ListChallengeMetadataResult> listChallengeMetadataAsync(ListChallengeMetadataRequest request) {

        return listChallengeMetadataAsync(request, null);
    }

    @Override
    public java.util.concurrent.Future<ListChallengeMetadataResult> listChallengeMetadataAsync(final ListChallengeMetadataRequest request,
            final com.amazonaws.handlers.AsyncHandler<ListChallengeMetadataRequest, ListChallengeMetadataResult> asyncHandler) {
        final ListChallengeMetadataRequest finalRequest = beforeClientExecution(request);

        return executorService.submit(new java.util.concurrent.Callable<ListChallengeMetadataResult>() {
            @Override
            public ListChallengeMetadataResult call() throws Exception {
                ListChallengeMetadataResult result = null;

                try {
                    result = executeListChallengeMetadata(finalRequest);
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
    public java.util.concurrent.Future<ListConnectorsResult> listConnectorsAsync(ListConnectorsRequest request) {

        return listConnectorsAsync(request, null);
    }

    @Override
    public java.util.concurrent.Future<ListConnectorsResult> listConnectorsAsync(final ListConnectorsRequest request,
            final com.amazonaws.handlers.AsyncHandler<ListConnectorsRequest, ListConnectorsResult> asyncHandler) {
        final ListConnectorsRequest finalRequest = beforeClientExecution(request);

        return executorService.submit(new java.util.concurrent.Callable<ListConnectorsResult>() {
            @Override
            public ListConnectorsResult call() throws Exception {
                ListConnectorsResult result = null;

                try {
                    result = executeListConnectors(finalRequest);
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
    public java.util.concurrent.Future<ListTagsForResourceResult> listTagsForResourceAsync(ListTagsForResourceRequest request) {

        return listTagsForResourceAsync(request, null);
    }

    @Override
    public java.util.concurrent.Future<ListTagsForResourceResult> listTagsForResourceAsync(final ListTagsForResourceRequest request,
            final com.amazonaws.handlers.AsyncHandler<ListTagsForResourceRequest, ListTagsForResourceResult> asyncHandler) {
        final ListTagsForResourceRequest finalRequest = beforeClientExecution(request);

        return executorService.submit(new java.util.concurrent.Callable<ListTagsForResourceResult>() {
            @Override
            public ListTagsForResourceResult call() throws Exception {
                ListTagsForResourceResult result = null;

                try {
                    result = executeListTagsForResource(finalRequest);
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
    public java.util.concurrent.Future<TagResourceResult> tagResourceAsync(TagResourceRequest request) {

        return tagResourceAsync(request, null);
    }

    @Override
    public java.util.concurrent.Future<TagResourceResult> tagResourceAsync(final TagResourceRequest request,
            final com.amazonaws.handlers.AsyncHandler<TagResourceRequest, TagResourceResult> asyncHandler) {
        final TagResourceRequest finalRequest = beforeClientExecution(request);

        return executorService.submit(new java.util.concurrent.Callable<TagResourceResult>() {
            @Override
            public TagResourceResult call() throws Exception {
                TagResourceResult result = null;

                try {
                    result = executeTagResource(finalRequest);
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
    public java.util.concurrent.Future<UntagResourceResult> untagResourceAsync(UntagResourceRequest request) {

        return untagResourceAsync(request, null);
    }

    @Override
    public java.util.concurrent.Future<UntagResourceResult> untagResourceAsync(final UntagResourceRequest request,
            final com.amazonaws.handlers.AsyncHandler<UntagResourceRequest, UntagResourceResult> asyncHandler) {
        final UntagResourceRequest finalRequest = beforeClientExecution(request);

        return executorService.submit(new java.util.concurrent.Callable<UntagResourceResult>() {
            @Override
            public UntagResourceResult call() throws Exception {
                UntagResourceResult result = null;

                try {
                    result = executeUntagResource(finalRequest);
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
