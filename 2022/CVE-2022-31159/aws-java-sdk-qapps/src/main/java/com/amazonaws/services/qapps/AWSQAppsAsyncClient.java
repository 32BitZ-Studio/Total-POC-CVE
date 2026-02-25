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
package com.amazonaws.services.qapps;

import javax.annotation.Generated;

import com.amazonaws.services.qapps.model.*;
import com.amazonaws.client.AwsAsyncClientParams;
import com.amazonaws.annotation.ThreadSafe;

import java.util.concurrent.ExecutorService;

/**
 * Client for accessing QApps asynchronously. Each asynchronous method will return a Java Future object representing the
 * asynchronous operation; overloads which accept an {@code AsyncHandler} can be used to receive notification when an
 * asynchronous operation completes.
 * <p>
 * <p>
 * The Amazon Q Apps feature capability within Amazon Q Business allows web experience users to create lightweight,
 * purpose-built AI apps to fulfill specific tasks from within their web experience. For example, users can create an Q
 * Appthat exclusively generates marketing-related content to improve your marketing team's productivity or a Q App for
 * marketing content-generation like writing customer emails and creating promotional content using a certain style of
 * voice, tone, and branding. For more information, see <a
 * href="https://docs.aws.amazon.com/amazonq/latest/qbusiness-ug/purpose-built-qapps.html">Amazon Q App</a> in the
 * <i>Amazon Q Business User Guide</i>.
 * </p>
 */
@ThreadSafe
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class AWSQAppsAsyncClient extends AWSQAppsClient implements AWSQAppsAsync {

    private static final int DEFAULT_THREAD_POOL_SIZE = 50;

    private final java.util.concurrent.ExecutorService executorService;

    public static AWSQAppsAsyncClientBuilder asyncBuilder() {
        return AWSQAppsAsyncClientBuilder.standard();
    }

    /**
     * Constructs a new asynchronous client to invoke service methods on QApps using the specified parameters.
     *
     * @param asyncClientParams
     *        Object providing client parameters.
     */
    AWSQAppsAsyncClient(AwsAsyncClientParams asyncClientParams) {
        this(asyncClientParams, false);
    }

    /**
     * Constructs a new asynchronous client to invoke service methods on QApps using the specified parameters.
     *
     * @param asyncClientParams
     *        Object providing client parameters.
     * @param endpointDiscoveryEnabled
     *        true will enable endpoint discovery if the service supports it.
     */
    AWSQAppsAsyncClient(AwsAsyncClientParams asyncClientParams, boolean endpointDiscoveryEnabled) {
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
    public java.util.concurrent.Future<AssociateLibraryItemReviewResult> associateLibraryItemReviewAsync(AssociateLibraryItemReviewRequest request) {

        return associateLibraryItemReviewAsync(request, null);
    }

    @Override
    public java.util.concurrent.Future<AssociateLibraryItemReviewResult> associateLibraryItemReviewAsync(final AssociateLibraryItemReviewRequest request,
            final com.amazonaws.handlers.AsyncHandler<AssociateLibraryItemReviewRequest, AssociateLibraryItemReviewResult> asyncHandler) {
        final AssociateLibraryItemReviewRequest finalRequest = beforeClientExecution(request);

        return executorService.submit(new java.util.concurrent.Callable<AssociateLibraryItemReviewResult>() {
            @Override
            public AssociateLibraryItemReviewResult call() throws Exception {
                AssociateLibraryItemReviewResult result = null;

                try {
                    result = executeAssociateLibraryItemReview(finalRequest);
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
    public java.util.concurrent.Future<AssociateQAppWithUserResult> associateQAppWithUserAsync(AssociateQAppWithUserRequest request) {

        return associateQAppWithUserAsync(request, null);
    }

    @Override
    public java.util.concurrent.Future<AssociateQAppWithUserResult> associateQAppWithUserAsync(final AssociateQAppWithUserRequest request,
            final com.amazonaws.handlers.AsyncHandler<AssociateQAppWithUserRequest, AssociateQAppWithUserResult> asyncHandler) {
        final AssociateQAppWithUserRequest finalRequest = beforeClientExecution(request);

        return executorService.submit(new java.util.concurrent.Callable<AssociateQAppWithUserResult>() {
            @Override
            public AssociateQAppWithUserResult call() throws Exception {
                AssociateQAppWithUserResult result = null;

                try {
                    result = executeAssociateQAppWithUser(finalRequest);
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
    public java.util.concurrent.Future<CreateLibraryItemResult> createLibraryItemAsync(CreateLibraryItemRequest request) {

        return createLibraryItemAsync(request, null);
    }

    @Override
    public java.util.concurrent.Future<CreateLibraryItemResult> createLibraryItemAsync(final CreateLibraryItemRequest request,
            final com.amazonaws.handlers.AsyncHandler<CreateLibraryItemRequest, CreateLibraryItemResult> asyncHandler) {
        final CreateLibraryItemRequest finalRequest = beforeClientExecution(request);

        return executorService.submit(new java.util.concurrent.Callable<CreateLibraryItemResult>() {
            @Override
            public CreateLibraryItemResult call() throws Exception {
                CreateLibraryItemResult result = null;

                try {
                    result = executeCreateLibraryItem(finalRequest);
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
    public java.util.concurrent.Future<CreateQAppResult> createQAppAsync(CreateQAppRequest request) {

        return createQAppAsync(request, null);
    }

    @Override
    public java.util.concurrent.Future<CreateQAppResult> createQAppAsync(final CreateQAppRequest request,
            final com.amazonaws.handlers.AsyncHandler<CreateQAppRequest, CreateQAppResult> asyncHandler) {
        final CreateQAppRequest finalRequest = beforeClientExecution(request);

        return executorService.submit(new java.util.concurrent.Callable<CreateQAppResult>() {
            @Override
            public CreateQAppResult call() throws Exception {
                CreateQAppResult result = null;

                try {
                    result = executeCreateQApp(finalRequest);
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
    public java.util.concurrent.Future<DeleteLibraryItemResult> deleteLibraryItemAsync(DeleteLibraryItemRequest request) {

        return deleteLibraryItemAsync(request, null);
    }

    @Override
    public java.util.concurrent.Future<DeleteLibraryItemResult> deleteLibraryItemAsync(final DeleteLibraryItemRequest request,
            final com.amazonaws.handlers.AsyncHandler<DeleteLibraryItemRequest, DeleteLibraryItemResult> asyncHandler) {
        final DeleteLibraryItemRequest finalRequest = beforeClientExecution(request);

        return executorService.submit(new java.util.concurrent.Callable<DeleteLibraryItemResult>() {
            @Override
            public DeleteLibraryItemResult call() throws Exception {
                DeleteLibraryItemResult result = null;

                try {
                    result = executeDeleteLibraryItem(finalRequest);
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
    public java.util.concurrent.Future<DeleteQAppResult> deleteQAppAsync(DeleteQAppRequest request) {

        return deleteQAppAsync(request, null);
    }

    @Override
    public java.util.concurrent.Future<DeleteQAppResult> deleteQAppAsync(final DeleteQAppRequest request,
            final com.amazonaws.handlers.AsyncHandler<DeleteQAppRequest, DeleteQAppResult> asyncHandler) {
        final DeleteQAppRequest finalRequest = beforeClientExecution(request);

        return executorService.submit(new java.util.concurrent.Callable<DeleteQAppResult>() {
            @Override
            public DeleteQAppResult call() throws Exception {
                DeleteQAppResult result = null;

                try {
                    result = executeDeleteQApp(finalRequest);
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
    public java.util.concurrent.Future<DisassociateLibraryItemReviewResult> disassociateLibraryItemReviewAsync(DisassociateLibraryItemReviewRequest request) {

        return disassociateLibraryItemReviewAsync(request, null);
    }

    @Override
    public java.util.concurrent.Future<DisassociateLibraryItemReviewResult> disassociateLibraryItemReviewAsync(
            final DisassociateLibraryItemReviewRequest request,
            final com.amazonaws.handlers.AsyncHandler<DisassociateLibraryItemReviewRequest, DisassociateLibraryItemReviewResult> asyncHandler) {
        final DisassociateLibraryItemReviewRequest finalRequest = beforeClientExecution(request);

        return executorService.submit(new java.util.concurrent.Callable<DisassociateLibraryItemReviewResult>() {
            @Override
            public DisassociateLibraryItemReviewResult call() throws Exception {
                DisassociateLibraryItemReviewResult result = null;

                try {
                    result = executeDisassociateLibraryItemReview(finalRequest);
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
    public java.util.concurrent.Future<DisassociateQAppFromUserResult> disassociateQAppFromUserAsync(DisassociateQAppFromUserRequest request) {

        return disassociateQAppFromUserAsync(request, null);
    }

    @Override
    public java.util.concurrent.Future<DisassociateQAppFromUserResult> disassociateQAppFromUserAsync(final DisassociateQAppFromUserRequest request,
            final com.amazonaws.handlers.AsyncHandler<DisassociateQAppFromUserRequest, DisassociateQAppFromUserResult> asyncHandler) {
        final DisassociateQAppFromUserRequest finalRequest = beforeClientExecution(request);

        return executorService.submit(new java.util.concurrent.Callable<DisassociateQAppFromUserResult>() {
            @Override
            public DisassociateQAppFromUserResult call() throws Exception {
                DisassociateQAppFromUserResult result = null;

                try {
                    result = executeDisassociateQAppFromUser(finalRequest);
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
    public java.util.concurrent.Future<GetLibraryItemResult> getLibraryItemAsync(GetLibraryItemRequest request) {

        return getLibraryItemAsync(request, null);
    }

    @Override
    public java.util.concurrent.Future<GetLibraryItemResult> getLibraryItemAsync(final GetLibraryItemRequest request,
            final com.amazonaws.handlers.AsyncHandler<GetLibraryItemRequest, GetLibraryItemResult> asyncHandler) {
        final GetLibraryItemRequest finalRequest = beforeClientExecution(request);

        return executorService.submit(new java.util.concurrent.Callable<GetLibraryItemResult>() {
            @Override
            public GetLibraryItemResult call() throws Exception {
                GetLibraryItemResult result = null;

                try {
                    result = executeGetLibraryItem(finalRequest);
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
    public java.util.concurrent.Future<GetQAppResult> getQAppAsync(GetQAppRequest request) {

        return getQAppAsync(request, null);
    }

    @Override
    public java.util.concurrent.Future<GetQAppResult> getQAppAsync(final GetQAppRequest request,
            final com.amazonaws.handlers.AsyncHandler<GetQAppRequest, GetQAppResult> asyncHandler) {
        final GetQAppRequest finalRequest = beforeClientExecution(request);

        return executorService.submit(new java.util.concurrent.Callable<GetQAppResult>() {
            @Override
            public GetQAppResult call() throws Exception {
                GetQAppResult result = null;

                try {
                    result = executeGetQApp(finalRequest);
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
    public java.util.concurrent.Future<GetQAppSessionResult> getQAppSessionAsync(GetQAppSessionRequest request) {

        return getQAppSessionAsync(request, null);
    }

    @Override
    public java.util.concurrent.Future<GetQAppSessionResult> getQAppSessionAsync(final GetQAppSessionRequest request,
            final com.amazonaws.handlers.AsyncHandler<GetQAppSessionRequest, GetQAppSessionResult> asyncHandler) {
        final GetQAppSessionRequest finalRequest = beforeClientExecution(request);

        return executorService.submit(new java.util.concurrent.Callable<GetQAppSessionResult>() {
            @Override
            public GetQAppSessionResult call() throws Exception {
                GetQAppSessionResult result = null;

                try {
                    result = executeGetQAppSession(finalRequest);
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
    public java.util.concurrent.Future<ImportDocumentResult> importDocumentAsync(ImportDocumentRequest request) {

        return importDocumentAsync(request, null);
    }

    @Override
    public java.util.concurrent.Future<ImportDocumentResult> importDocumentAsync(final ImportDocumentRequest request,
            final com.amazonaws.handlers.AsyncHandler<ImportDocumentRequest, ImportDocumentResult> asyncHandler) {
        final ImportDocumentRequest finalRequest = beforeClientExecution(request);

        return executorService.submit(new java.util.concurrent.Callable<ImportDocumentResult>() {
            @Override
            public ImportDocumentResult call() throws Exception {
                ImportDocumentResult result = null;

                try {
                    result = executeImportDocument(finalRequest);
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
    public java.util.concurrent.Future<ListLibraryItemsResult> listLibraryItemsAsync(ListLibraryItemsRequest request) {

        return listLibraryItemsAsync(request, null);
    }

    @Override
    public java.util.concurrent.Future<ListLibraryItemsResult> listLibraryItemsAsync(final ListLibraryItemsRequest request,
            final com.amazonaws.handlers.AsyncHandler<ListLibraryItemsRequest, ListLibraryItemsResult> asyncHandler) {
        final ListLibraryItemsRequest finalRequest = beforeClientExecution(request);

        return executorService.submit(new java.util.concurrent.Callable<ListLibraryItemsResult>() {
            @Override
            public ListLibraryItemsResult call() throws Exception {
                ListLibraryItemsResult result = null;

                try {
                    result = executeListLibraryItems(finalRequest);
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
    public java.util.concurrent.Future<ListQAppsResult> listQAppsAsync(ListQAppsRequest request) {

        return listQAppsAsync(request, null);
    }

    @Override
    public java.util.concurrent.Future<ListQAppsResult> listQAppsAsync(final ListQAppsRequest request,
            final com.amazonaws.handlers.AsyncHandler<ListQAppsRequest, ListQAppsResult> asyncHandler) {
        final ListQAppsRequest finalRequest = beforeClientExecution(request);

        return executorService.submit(new java.util.concurrent.Callable<ListQAppsResult>() {
            @Override
            public ListQAppsResult call() throws Exception {
                ListQAppsResult result = null;

                try {
                    result = executeListQApps(finalRequest);
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
    public java.util.concurrent.Future<PredictQAppResult> predictQAppAsync(PredictQAppRequest request) {

        return predictQAppAsync(request, null);
    }

    @Override
    public java.util.concurrent.Future<PredictQAppResult> predictQAppAsync(final PredictQAppRequest request,
            final com.amazonaws.handlers.AsyncHandler<PredictQAppRequest, PredictQAppResult> asyncHandler) {
        final PredictQAppRequest finalRequest = beforeClientExecution(request);

        return executorService.submit(new java.util.concurrent.Callable<PredictQAppResult>() {
            @Override
            public PredictQAppResult call() throws Exception {
                PredictQAppResult result = null;

                try {
                    result = executePredictQApp(finalRequest);
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
    public java.util.concurrent.Future<StartQAppSessionResult> startQAppSessionAsync(StartQAppSessionRequest request) {

        return startQAppSessionAsync(request, null);
    }

    @Override
    public java.util.concurrent.Future<StartQAppSessionResult> startQAppSessionAsync(final StartQAppSessionRequest request,
            final com.amazonaws.handlers.AsyncHandler<StartQAppSessionRequest, StartQAppSessionResult> asyncHandler) {
        final StartQAppSessionRequest finalRequest = beforeClientExecution(request);

        return executorService.submit(new java.util.concurrent.Callable<StartQAppSessionResult>() {
            @Override
            public StartQAppSessionResult call() throws Exception {
                StartQAppSessionResult result = null;

                try {
                    result = executeStartQAppSession(finalRequest);
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
    public java.util.concurrent.Future<StopQAppSessionResult> stopQAppSessionAsync(StopQAppSessionRequest request) {

        return stopQAppSessionAsync(request, null);
    }

    @Override
    public java.util.concurrent.Future<StopQAppSessionResult> stopQAppSessionAsync(final StopQAppSessionRequest request,
            final com.amazonaws.handlers.AsyncHandler<StopQAppSessionRequest, StopQAppSessionResult> asyncHandler) {
        final StopQAppSessionRequest finalRequest = beforeClientExecution(request);

        return executorService.submit(new java.util.concurrent.Callable<StopQAppSessionResult>() {
            @Override
            public StopQAppSessionResult call() throws Exception {
                StopQAppSessionResult result = null;

                try {
                    result = executeStopQAppSession(finalRequest);
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

    @Override
    public java.util.concurrent.Future<UpdateLibraryItemResult> updateLibraryItemAsync(UpdateLibraryItemRequest request) {

        return updateLibraryItemAsync(request, null);
    }

    @Override
    public java.util.concurrent.Future<UpdateLibraryItemResult> updateLibraryItemAsync(final UpdateLibraryItemRequest request,
            final com.amazonaws.handlers.AsyncHandler<UpdateLibraryItemRequest, UpdateLibraryItemResult> asyncHandler) {
        final UpdateLibraryItemRequest finalRequest = beforeClientExecution(request);

        return executorService.submit(new java.util.concurrent.Callable<UpdateLibraryItemResult>() {
            @Override
            public UpdateLibraryItemResult call() throws Exception {
                UpdateLibraryItemResult result = null;

                try {
                    result = executeUpdateLibraryItem(finalRequest);
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
    public java.util.concurrent.Future<UpdateQAppResult> updateQAppAsync(UpdateQAppRequest request) {

        return updateQAppAsync(request, null);
    }

    @Override
    public java.util.concurrent.Future<UpdateQAppResult> updateQAppAsync(final UpdateQAppRequest request,
            final com.amazonaws.handlers.AsyncHandler<UpdateQAppRequest, UpdateQAppResult> asyncHandler) {
        final UpdateQAppRequest finalRequest = beforeClientExecution(request);

        return executorService.submit(new java.util.concurrent.Callable<UpdateQAppResult>() {
            @Override
            public UpdateQAppResult call() throws Exception {
                UpdateQAppResult result = null;

                try {
                    result = executeUpdateQApp(finalRequest);
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
    public java.util.concurrent.Future<UpdateQAppSessionResult> updateQAppSessionAsync(UpdateQAppSessionRequest request) {

        return updateQAppSessionAsync(request, null);
    }

    @Override
    public java.util.concurrent.Future<UpdateQAppSessionResult> updateQAppSessionAsync(final UpdateQAppSessionRequest request,
            final com.amazonaws.handlers.AsyncHandler<UpdateQAppSessionRequest, UpdateQAppSessionResult> asyncHandler) {
        final UpdateQAppSessionRequest finalRequest = beforeClientExecution(request);

        return executorService.submit(new java.util.concurrent.Callable<UpdateQAppSessionResult>() {
            @Override
            public UpdateQAppSessionResult call() throws Exception {
                UpdateQAppSessionResult result = null;

                try {
                    result = executeUpdateQAppSession(finalRequest);
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
