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

/**
 * Interface for accessing QApps asynchronously. Each asynchronous method will return a Java Future object representing
 * the asynchronous operation; overloads which accept an {@code AsyncHandler} can be used to receive notification when
 * an asynchronous operation completes.
 * <p>
 * <b>Note:</b> Do not directly implement this interface, new methods are added to it regularly. Extend from
 * {@link com.amazonaws.services.qapps.AbstractAWSQAppsAsync} instead.
 * </p>
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
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public interface AWSQAppsAsync extends AWSQApps {

    /**
     * <p>
     * Associates a rating or review for a library item with the user submitting the request. This increments the rating
     * count for the specified library item.
     * </p>
     * 
     * @param associateLibraryItemReviewRequest
     * @return A Java Future containing the result of the AssociateLibraryItemReview operation returned by the service.
     * @sample AWSQAppsAsync.AssociateLibraryItemReview
     * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/qapps-2023-11-27/AssociateLibraryItemReview"
     *      target="_top">AWS API Documentation</a>
     */
    java.util.concurrent.Future<AssociateLibraryItemReviewResult> associateLibraryItemReviewAsync(
            AssociateLibraryItemReviewRequest associateLibraryItemReviewRequest);

    /**
     * <p>
     * Associates a rating or review for a library item with the user submitting the request. This increments the rating
     * count for the specified library item.
     * </p>
     * 
     * @param associateLibraryItemReviewRequest
     * @param asyncHandler
     *        Asynchronous callback handler for events in the lifecycle of the request. Users can provide an
     *        implementation of the callback methods in this interface to receive notification of successful or
     *        unsuccessful completion of the operation.
     * @return A Java Future containing the result of the AssociateLibraryItemReview operation returned by the service.
     * @sample AWSQAppsAsyncHandler.AssociateLibraryItemReview
     * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/qapps-2023-11-27/AssociateLibraryItemReview"
     *      target="_top">AWS API Documentation</a>
     */
    java.util.concurrent.Future<AssociateLibraryItemReviewResult> associateLibraryItemReviewAsync(
            AssociateLibraryItemReviewRequest associateLibraryItemReviewRequest,
            com.amazonaws.handlers.AsyncHandler<AssociateLibraryItemReviewRequest, AssociateLibraryItemReviewResult> asyncHandler);

    /**
     * <p>
     * This operation creates a link between the user's identity calling the operation and a specific Q App. This is
     * useful to mark the Q App as a <i>favorite</i> for the user if the user doesn't own the Amazon Q App so they can
     * still run it and see it in their inventory of Q Apps.
     * </p>
     * 
     * @param associateQAppWithUserRequest
     * @return A Java Future containing the result of the AssociateQAppWithUser operation returned by the service.
     * @sample AWSQAppsAsync.AssociateQAppWithUser
     * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/qapps-2023-11-27/AssociateQAppWithUser" target="_top">AWS
     *      API Documentation</a>
     */
    java.util.concurrent.Future<AssociateQAppWithUserResult> associateQAppWithUserAsync(AssociateQAppWithUserRequest associateQAppWithUserRequest);

    /**
     * <p>
     * This operation creates a link between the user's identity calling the operation and a specific Q App. This is
     * useful to mark the Q App as a <i>favorite</i> for the user if the user doesn't own the Amazon Q App so they can
     * still run it and see it in their inventory of Q Apps.
     * </p>
     * 
     * @param associateQAppWithUserRequest
     * @param asyncHandler
     *        Asynchronous callback handler for events in the lifecycle of the request. Users can provide an
     *        implementation of the callback methods in this interface to receive notification of successful or
     *        unsuccessful completion of the operation.
     * @return A Java Future containing the result of the AssociateQAppWithUser operation returned by the service.
     * @sample AWSQAppsAsyncHandler.AssociateQAppWithUser
     * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/qapps-2023-11-27/AssociateQAppWithUser" target="_top">AWS
     *      API Documentation</a>
     */
    java.util.concurrent.Future<AssociateQAppWithUserResult> associateQAppWithUserAsync(AssociateQAppWithUserRequest associateQAppWithUserRequest,
            com.amazonaws.handlers.AsyncHandler<AssociateQAppWithUserRequest, AssociateQAppWithUserResult> asyncHandler);

    /**
     * <p>
     * Creates a new library item for an Amazon Q App, allowing it to be discovered and used by other allowed users.
     * </p>
     * 
     * @param createLibraryItemRequest
     * @return A Java Future containing the result of the CreateLibraryItem operation returned by the service.
     * @sample AWSQAppsAsync.CreateLibraryItem
     * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/qapps-2023-11-27/CreateLibraryItem" target="_top">AWS API
     *      Documentation</a>
     */
    java.util.concurrent.Future<CreateLibraryItemResult> createLibraryItemAsync(CreateLibraryItemRequest createLibraryItemRequest);

    /**
     * <p>
     * Creates a new library item for an Amazon Q App, allowing it to be discovered and used by other allowed users.
     * </p>
     * 
     * @param createLibraryItemRequest
     * @param asyncHandler
     *        Asynchronous callback handler for events in the lifecycle of the request. Users can provide an
     *        implementation of the callback methods in this interface to receive notification of successful or
     *        unsuccessful completion of the operation.
     * @return A Java Future containing the result of the CreateLibraryItem operation returned by the service.
     * @sample AWSQAppsAsyncHandler.CreateLibraryItem
     * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/qapps-2023-11-27/CreateLibraryItem" target="_top">AWS API
     *      Documentation</a>
     */
    java.util.concurrent.Future<CreateLibraryItemResult> createLibraryItemAsync(CreateLibraryItemRequest createLibraryItemRequest,
            com.amazonaws.handlers.AsyncHandler<CreateLibraryItemRequest, CreateLibraryItemResult> asyncHandler);

    /**
     * <p>
     * Creates a new Amazon Q App based on the provided definition. The Q App definition specifies the cards and flow of
     * the Q App. This operation also calculates the dependencies between the cards by inspecting the references in the
     * prompts.
     * </p>
     * 
     * @param createQAppRequest
     * @return A Java Future containing the result of the CreateQApp operation returned by the service.
     * @sample AWSQAppsAsync.CreateQApp
     * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/qapps-2023-11-27/CreateQApp" target="_top">AWS API
     *      Documentation</a>
     */
    java.util.concurrent.Future<CreateQAppResult> createQAppAsync(CreateQAppRequest createQAppRequest);

    /**
     * <p>
     * Creates a new Amazon Q App based on the provided definition. The Q App definition specifies the cards and flow of
     * the Q App. This operation also calculates the dependencies between the cards by inspecting the references in the
     * prompts.
     * </p>
     * 
     * @param createQAppRequest
     * @param asyncHandler
     *        Asynchronous callback handler for events in the lifecycle of the request. Users can provide an
     *        implementation of the callback methods in this interface to receive notification of successful or
     *        unsuccessful completion of the operation.
     * @return A Java Future containing the result of the CreateQApp operation returned by the service.
     * @sample AWSQAppsAsyncHandler.CreateQApp
     * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/qapps-2023-11-27/CreateQApp" target="_top">AWS API
     *      Documentation</a>
     */
    java.util.concurrent.Future<CreateQAppResult> createQAppAsync(CreateQAppRequest createQAppRequest,
            com.amazonaws.handlers.AsyncHandler<CreateQAppRequest, CreateQAppResult> asyncHandler);

    /**
     * <p>
     * Deletes a library item for an Amazon Q App, removing it from the library so it can no longer be discovered or
     * used by other users.
     * </p>
     * 
     * @param deleteLibraryItemRequest
     * @return A Java Future containing the result of the DeleteLibraryItem operation returned by the service.
     * @sample AWSQAppsAsync.DeleteLibraryItem
     * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/qapps-2023-11-27/DeleteLibraryItem" target="_top">AWS API
     *      Documentation</a>
     */
    java.util.concurrent.Future<DeleteLibraryItemResult> deleteLibraryItemAsync(DeleteLibraryItemRequest deleteLibraryItemRequest);

    /**
     * <p>
     * Deletes a library item for an Amazon Q App, removing it from the library so it can no longer be discovered or
     * used by other users.
     * </p>
     * 
     * @param deleteLibraryItemRequest
     * @param asyncHandler
     *        Asynchronous callback handler for events in the lifecycle of the request. Users can provide an
     *        implementation of the callback methods in this interface to receive notification of successful or
     *        unsuccessful completion of the operation.
     * @return A Java Future containing the result of the DeleteLibraryItem operation returned by the service.
     * @sample AWSQAppsAsyncHandler.DeleteLibraryItem
     * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/qapps-2023-11-27/DeleteLibraryItem" target="_top">AWS API
     *      Documentation</a>
     */
    java.util.concurrent.Future<DeleteLibraryItemResult> deleteLibraryItemAsync(DeleteLibraryItemRequest deleteLibraryItemRequest,
            com.amazonaws.handlers.AsyncHandler<DeleteLibraryItemRequest, DeleteLibraryItemResult> asyncHandler);

    /**
     * <p>
     * Deletes an Amazon Q App owned by the user. If the Q App was previously published to the library, it is also
     * removed from the library.
     * </p>
     * 
     * @param deleteQAppRequest
     * @return A Java Future containing the result of the DeleteQApp operation returned by the service.
     * @sample AWSQAppsAsync.DeleteQApp
     * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/qapps-2023-11-27/DeleteQApp" target="_top">AWS API
     *      Documentation</a>
     */
    java.util.concurrent.Future<DeleteQAppResult> deleteQAppAsync(DeleteQAppRequest deleteQAppRequest);

    /**
     * <p>
     * Deletes an Amazon Q App owned by the user. If the Q App was previously published to the library, it is also
     * removed from the library.
     * </p>
     * 
     * @param deleteQAppRequest
     * @param asyncHandler
     *        Asynchronous callback handler for events in the lifecycle of the request. Users can provide an
     *        implementation of the callback methods in this interface to receive notification of successful or
     *        unsuccessful completion of the operation.
     * @return A Java Future containing the result of the DeleteQApp operation returned by the service.
     * @sample AWSQAppsAsyncHandler.DeleteQApp
     * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/qapps-2023-11-27/DeleteQApp" target="_top">AWS API
     *      Documentation</a>
     */
    java.util.concurrent.Future<DeleteQAppResult> deleteQAppAsync(DeleteQAppRequest deleteQAppRequest,
            com.amazonaws.handlers.AsyncHandler<DeleteQAppRequest, DeleteQAppResult> asyncHandler);

    /**
     * <p>
     * Removes a rating or review previously submitted by the user for a library item.
     * </p>
     * 
     * @param disassociateLibraryItemReviewRequest
     * @return A Java Future containing the result of the DisassociateLibraryItemReview operation returned by the
     *         service.
     * @sample AWSQAppsAsync.DisassociateLibraryItemReview
     * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/qapps-2023-11-27/DisassociateLibraryItemReview"
     *      target="_top">AWS API Documentation</a>
     */
    java.util.concurrent.Future<DisassociateLibraryItemReviewResult> disassociateLibraryItemReviewAsync(
            DisassociateLibraryItemReviewRequest disassociateLibraryItemReviewRequest);

    /**
     * <p>
     * Removes a rating or review previously submitted by the user for a library item.
     * </p>
     * 
     * @param disassociateLibraryItemReviewRequest
     * @param asyncHandler
     *        Asynchronous callback handler for events in the lifecycle of the request. Users can provide an
     *        implementation of the callback methods in this interface to receive notification of successful or
     *        unsuccessful completion of the operation.
     * @return A Java Future containing the result of the DisassociateLibraryItemReview operation returned by the
     *         service.
     * @sample AWSQAppsAsyncHandler.DisassociateLibraryItemReview
     * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/qapps-2023-11-27/DisassociateLibraryItemReview"
     *      target="_top">AWS API Documentation</a>
     */
    java.util.concurrent.Future<DisassociateLibraryItemReviewResult> disassociateLibraryItemReviewAsync(
            DisassociateLibraryItemReviewRequest disassociateLibraryItemReviewRequest,
            com.amazonaws.handlers.AsyncHandler<DisassociateLibraryItemReviewRequest, DisassociateLibraryItemReviewResult> asyncHandler);

    /**
     * <p>
     * Disassociates a Q App from a user removing the user's access to run the Q App.
     * </p>
     * 
     * @param disassociateQAppFromUserRequest
     * @return A Java Future containing the result of the DisassociateQAppFromUser operation returned by the service.
     * @sample AWSQAppsAsync.DisassociateQAppFromUser
     * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/qapps-2023-11-27/DisassociateQAppFromUser" target="_top">AWS
     *      API Documentation</a>
     */
    java.util.concurrent.Future<DisassociateQAppFromUserResult> disassociateQAppFromUserAsync(DisassociateQAppFromUserRequest disassociateQAppFromUserRequest);

    /**
     * <p>
     * Disassociates a Q App from a user removing the user's access to run the Q App.
     * </p>
     * 
     * @param disassociateQAppFromUserRequest
     * @param asyncHandler
     *        Asynchronous callback handler for events in the lifecycle of the request. Users can provide an
     *        implementation of the callback methods in this interface to receive notification of successful or
     *        unsuccessful completion of the operation.
     * @return A Java Future containing the result of the DisassociateQAppFromUser operation returned by the service.
     * @sample AWSQAppsAsyncHandler.DisassociateQAppFromUser
     * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/qapps-2023-11-27/DisassociateQAppFromUser" target="_top">AWS
     *      API Documentation</a>
     */
    java.util.concurrent.Future<DisassociateQAppFromUserResult> disassociateQAppFromUserAsync(DisassociateQAppFromUserRequest disassociateQAppFromUserRequest,
            com.amazonaws.handlers.AsyncHandler<DisassociateQAppFromUserRequest, DisassociateQAppFromUserResult> asyncHandler);

    /**
     * <p>
     * Retrieves details about a library item for an Amazon Q App, including its metadata, categories, ratings, and
     * usage statistics.
     * </p>
     * 
     * @param getLibraryItemRequest
     * @return A Java Future containing the result of the GetLibraryItem operation returned by the service.
     * @sample AWSQAppsAsync.GetLibraryItem
     * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/qapps-2023-11-27/GetLibraryItem" target="_top">AWS API
     *      Documentation</a>
     */
    java.util.concurrent.Future<GetLibraryItemResult> getLibraryItemAsync(GetLibraryItemRequest getLibraryItemRequest);

    /**
     * <p>
     * Retrieves details about a library item for an Amazon Q App, including its metadata, categories, ratings, and
     * usage statistics.
     * </p>
     * 
     * @param getLibraryItemRequest
     * @param asyncHandler
     *        Asynchronous callback handler for events in the lifecycle of the request. Users can provide an
     *        implementation of the callback methods in this interface to receive notification of successful or
     *        unsuccessful completion of the operation.
     * @return A Java Future containing the result of the GetLibraryItem operation returned by the service.
     * @sample AWSQAppsAsyncHandler.GetLibraryItem
     * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/qapps-2023-11-27/GetLibraryItem" target="_top">AWS API
     *      Documentation</a>
     */
    java.util.concurrent.Future<GetLibraryItemResult> getLibraryItemAsync(GetLibraryItemRequest getLibraryItemRequest,
            com.amazonaws.handlers.AsyncHandler<GetLibraryItemRequest, GetLibraryItemResult> asyncHandler);

    /**
     * <p>
     * Retrieves the full details of an Q App, including its definition specifying the cards and flow.
     * </p>
     * 
     * @param getQAppRequest
     * @return A Java Future containing the result of the GetQApp operation returned by the service.
     * @sample AWSQAppsAsync.GetQApp
     * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/qapps-2023-11-27/GetQApp" target="_top">AWS API
     *      Documentation</a>
     */
    java.util.concurrent.Future<GetQAppResult> getQAppAsync(GetQAppRequest getQAppRequest);

    /**
     * <p>
     * Retrieves the full details of an Q App, including its definition specifying the cards and flow.
     * </p>
     * 
     * @param getQAppRequest
     * @param asyncHandler
     *        Asynchronous callback handler for events in the lifecycle of the request. Users can provide an
     *        implementation of the callback methods in this interface to receive notification of successful or
     *        unsuccessful completion of the operation.
     * @return A Java Future containing the result of the GetQApp operation returned by the service.
     * @sample AWSQAppsAsyncHandler.GetQApp
     * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/qapps-2023-11-27/GetQApp" target="_top">AWS API
     *      Documentation</a>
     */
    java.util.concurrent.Future<GetQAppResult> getQAppAsync(GetQAppRequest getQAppRequest,
            com.amazonaws.handlers.AsyncHandler<GetQAppRequest, GetQAppResult> asyncHandler);

    /**
     * <p>
     * Retrieves the current state and results for an active session of an Amazon Q App.
     * </p>
     * 
     * @param getQAppSessionRequest
     * @return A Java Future containing the result of the GetQAppSession operation returned by the service.
     * @sample AWSQAppsAsync.GetQAppSession
     * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/qapps-2023-11-27/GetQAppSession" target="_top">AWS API
     *      Documentation</a>
     */
    java.util.concurrent.Future<GetQAppSessionResult> getQAppSessionAsync(GetQAppSessionRequest getQAppSessionRequest);

    /**
     * <p>
     * Retrieves the current state and results for an active session of an Amazon Q App.
     * </p>
     * 
     * @param getQAppSessionRequest
     * @param asyncHandler
     *        Asynchronous callback handler for events in the lifecycle of the request. Users can provide an
     *        implementation of the callback methods in this interface to receive notification of successful or
     *        unsuccessful completion of the operation.
     * @return A Java Future containing the result of the GetQAppSession operation returned by the service.
     * @sample AWSQAppsAsyncHandler.GetQAppSession
     * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/qapps-2023-11-27/GetQAppSession" target="_top">AWS API
     *      Documentation</a>
     */
    java.util.concurrent.Future<GetQAppSessionResult> getQAppSessionAsync(GetQAppSessionRequest getQAppSessionRequest,
            com.amazonaws.handlers.AsyncHandler<GetQAppSessionRequest, GetQAppSessionResult> asyncHandler);

    /**
     * <p>
     * Uploads a file that can then be used either as a default in a <code>FileUploadCard</code> from Q App definition
     * or as a file that is used inside a single Q App run. The purpose of the document is determined by a scope
     * parameter that indicates whether it is at the app definition level or at the app session level.
     * </p>
     * 
     * @param importDocumentRequest
     * @return A Java Future containing the result of the ImportDocument operation returned by the service.
     * @sample AWSQAppsAsync.ImportDocument
     * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/qapps-2023-11-27/ImportDocument" target="_top">AWS API
     *      Documentation</a>
     */
    java.util.concurrent.Future<ImportDocumentResult> importDocumentAsync(ImportDocumentRequest importDocumentRequest);

    /**
     * <p>
     * Uploads a file that can then be used either as a default in a <code>FileUploadCard</code> from Q App definition
     * or as a file that is used inside a single Q App run. The purpose of the document is determined by a scope
     * parameter that indicates whether it is at the app definition level or at the app session level.
     * </p>
     * 
     * @param importDocumentRequest
     * @param asyncHandler
     *        Asynchronous callback handler for events in the lifecycle of the request. Users can provide an
     *        implementation of the callback methods in this interface to receive notification of successful or
     *        unsuccessful completion of the operation.
     * @return A Java Future containing the result of the ImportDocument operation returned by the service.
     * @sample AWSQAppsAsyncHandler.ImportDocument
     * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/qapps-2023-11-27/ImportDocument" target="_top">AWS API
     *      Documentation</a>
     */
    java.util.concurrent.Future<ImportDocumentResult> importDocumentAsync(ImportDocumentRequest importDocumentRequest,
            com.amazonaws.handlers.AsyncHandler<ImportDocumentRequest, ImportDocumentResult> asyncHandler);

    /**
     * <p>
     * Lists the library items for Amazon Q Apps that are published and available for users in your Amazon Web Services
     * account.
     * </p>
     * 
     * @param listLibraryItemsRequest
     * @return A Java Future containing the result of the ListLibraryItems operation returned by the service.
     * @sample AWSQAppsAsync.ListLibraryItems
     * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/qapps-2023-11-27/ListLibraryItems" target="_top">AWS API
     *      Documentation</a>
     */
    java.util.concurrent.Future<ListLibraryItemsResult> listLibraryItemsAsync(ListLibraryItemsRequest listLibraryItemsRequest);

    /**
     * <p>
     * Lists the library items for Amazon Q Apps that are published and available for users in your Amazon Web Services
     * account.
     * </p>
     * 
     * @param listLibraryItemsRequest
     * @param asyncHandler
     *        Asynchronous callback handler for events in the lifecycle of the request. Users can provide an
     *        implementation of the callback methods in this interface to receive notification of successful or
     *        unsuccessful completion of the operation.
     * @return A Java Future containing the result of the ListLibraryItems operation returned by the service.
     * @sample AWSQAppsAsyncHandler.ListLibraryItems
     * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/qapps-2023-11-27/ListLibraryItems" target="_top">AWS API
     *      Documentation</a>
     */
    java.util.concurrent.Future<ListLibraryItemsResult> listLibraryItemsAsync(ListLibraryItemsRequest listLibraryItemsRequest,
            com.amazonaws.handlers.AsyncHandler<ListLibraryItemsRequest, ListLibraryItemsResult> asyncHandler);

    /**
     * <p>
     * Lists the Amazon Q Apps owned by or associated with the user either because they created it or because they used
     * it from the library in the past. The user identity is extracted from the credentials used to invoke this
     * operation..
     * </p>
     * 
     * @param listQAppsRequest
     * @return A Java Future containing the result of the ListQApps operation returned by the service.
     * @sample AWSQAppsAsync.ListQApps
     * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/qapps-2023-11-27/ListQApps" target="_top">AWS API
     *      Documentation</a>
     */
    java.util.concurrent.Future<ListQAppsResult> listQAppsAsync(ListQAppsRequest listQAppsRequest);

    /**
     * <p>
     * Lists the Amazon Q Apps owned by or associated with the user either because they created it or because they used
     * it from the library in the past. The user identity is extracted from the credentials used to invoke this
     * operation..
     * </p>
     * 
     * @param listQAppsRequest
     * @param asyncHandler
     *        Asynchronous callback handler for events in the lifecycle of the request. Users can provide an
     *        implementation of the callback methods in this interface to receive notification of successful or
     *        unsuccessful completion of the operation.
     * @return A Java Future containing the result of the ListQApps operation returned by the service.
     * @sample AWSQAppsAsyncHandler.ListQApps
     * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/qapps-2023-11-27/ListQApps" target="_top">AWS API
     *      Documentation</a>
     */
    java.util.concurrent.Future<ListQAppsResult> listQAppsAsync(ListQAppsRequest listQAppsRequest,
            com.amazonaws.handlers.AsyncHandler<ListQAppsRequest, ListQAppsResult> asyncHandler);

    /**
     * <p>
     * Lists the tags associated with an Amazon Q Apps resource.
     * </p>
     * 
     * @param listTagsForResourceRequest
     * @return A Java Future containing the result of the ListTagsForResource operation returned by the service.
     * @sample AWSQAppsAsync.ListTagsForResource
     * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/qapps-2023-11-27/ListTagsForResource" target="_top">AWS API
     *      Documentation</a>
     */
    java.util.concurrent.Future<ListTagsForResourceResult> listTagsForResourceAsync(ListTagsForResourceRequest listTagsForResourceRequest);

    /**
     * <p>
     * Lists the tags associated with an Amazon Q Apps resource.
     * </p>
     * 
     * @param listTagsForResourceRequest
     * @param asyncHandler
     *        Asynchronous callback handler for events in the lifecycle of the request. Users can provide an
     *        implementation of the callback methods in this interface to receive notification of successful or
     *        unsuccessful completion of the operation.
     * @return A Java Future containing the result of the ListTagsForResource operation returned by the service.
     * @sample AWSQAppsAsyncHandler.ListTagsForResource
     * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/qapps-2023-11-27/ListTagsForResource" target="_top">AWS API
     *      Documentation</a>
     */
    java.util.concurrent.Future<ListTagsForResourceResult> listTagsForResourceAsync(ListTagsForResourceRequest listTagsForResourceRequest,
            com.amazonaws.handlers.AsyncHandler<ListTagsForResourceRequest, ListTagsForResourceResult> asyncHandler);

    /**
     * <p>
     * Generates an Amazon Q App definition based on either a conversation or a problem statement provided as input.The
     * resulting app definition can be used to call <code>CreateQApp</code>. This API doesn't create Amazon Q Apps
     * directly.
     * </p>
     * 
     * @param predictQAppRequest
     * @return A Java Future containing the result of the PredictQApp operation returned by the service.
     * @sample AWSQAppsAsync.PredictQApp
     * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/qapps-2023-11-27/PredictQApp" target="_top">AWS API
     *      Documentation</a>
     */
    java.util.concurrent.Future<PredictQAppResult> predictQAppAsync(PredictQAppRequest predictQAppRequest);

    /**
     * <p>
     * Generates an Amazon Q App definition based on either a conversation or a problem statement provided as input.The
     * resulting app definition can be used to call <code>CreateQApp</code>. This API doesn't create Amazon Q Apps
     * directly.
     * </p>
     * 
     * @param predictQAppRequest
     * @param asyncHandler
     *        Asynchronous callback handler for events in the lifecycle of the request. Users can provide an
     *        implementation of the callback methods in this interface to receive notification of successful or
     *        unsuccessful completion of the operation.
     * @return A Java Future containing the result of the PredictQApp operation returned by the service.
     * @sample AWSQAppsAsyncHandler.PredictQApp
     * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/qapps-2023-11-27/PredictQApp" target="_top">AWS API
     *      Documentation</a>
     */
    java.util.concurrent.Future<PredictQAppResult> predictQAppAsync(PredictQAppRequest predictQAppRequest,
            com.amazonaws.handlers.AsyncHandler<PredictQAppRequest, PredictQAppResult> asyncHandler);

    /**
     * <p>
     * Starts a new session for an Amazon Q App, allowing inputs to be provided and the app to be run.
     * </p>
     * <note>
     * <p>
     * Each Q App session will be condensed into a single conversation in the web experience.
     * </p>
     * </note>
     * 
     * @param startQAppSessionRequest
     * @return A Java Future containing the result of the StartQAppSession operation returned by the service.
     * @sample AWSQAppsAsync.StartQAppSession
     * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/qapps-2023-11-27/StartQAppSession" target="_top">AWS API
     *      Documentation</a>
     */
    java.util.concurrent.Future<StartQAppSessionResult> startQAppSessionAsync(StartQAppSessionRequest startQAppSessionRequest);

    /**
     * <p>
     * Starts a new session for an Amazon Q App, allowing inputs to be provided and the app to be run.
     * </p>
     * <note>
     * <p>
     * Each Q App session will be condensed into a single conversation in the web experience.
     * </p>
     * </note>
     * 
     * @param startQAppSessionRequest
     * @param asyncHandler
     *        Asynchronous callback handler for events in the lifecycle of the request. Users can provide an
     *        implementation of the callback methods in this interface to receive notification of successful or
     *        unsuccessful completion of the operation.
     * @return A Java Future containing the result of the StartQAppSession operation returned by the service.
     * @sample AWSQAppsAsyncHandler.StartQAppSession
     * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/qapps-2023-11-27/StartQAppSession" target="_top">AWS API
     *      Documentation</a>
     */
    java.util.concurrent.Future<StartQAppSessionResult> startQAppSessionAsync(StartQAppSessionRequest startQAppSessionRequest,
            com.amazonaws.handlers.AsyncHandler<StartQAppSessionRequest, StartQAppSessionResult> asyncHandler);

    /**
     * <p>
     * Stops an active session for an Amazon Q App.This deletes all data related to the session and makes it invalid for
     * future uses. The results of the session will be persisted as part of the conversation.
     * </p>
     * 
     * @param stopQAppSessionRequest
     * @return A Java Future containing the result of the StopQAppSession operation returned by the service.
     * @sample AWSQAppsAsync.StopQAppSession
     * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/qapps-2023-11-27/StopQAppSession" target="_top">AWS API
     *      Documentation</a>
     */
    java.util.concurrent.Future<StopQAppSessionResult> stopQAppSessionAsync(StopQAppSessionRequest stopQAppSessionRequest);

    /**
     * <p>
     * Stops an active session for an Amazon Q App.This deletes all data related to the session and makes it invalid for
     * future uses. The results of the session will be persisted as part of the conversation.
     * </p>
     * 
     * @param stopQAppSessionRequest
     * @param asyncHandler
     *        Asynchronous callback handler for events in the lifecycle of the request. Users can provide an
     *        implementation of the callback methods in this interface to receive notification of successful or
     *        unsuccessful completion of the operation.
     * @return A Java Future containing the result of the StopQAppSession operation returned by the service.
     * @sample AWSQAppsAsyncHandler.StopQAppSession
     * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/qapps-2023-11-27/StopQAppSession" target="_top">AWS API
     *      Documentation</a>
     */
    java.util.concurrent.Future<StopQAppSessionResult> stopQAppSessionAsync(StopQAppSessionRequest stopQAppSessionRequest,
            com.amazonaws.handlers.AsyncHandler<StopQAppSessionRequest, StopQAppSessionResult> asyncHandler);

    /**
     * <p>
     * Associates tags with an Amazon Q Apps resource.
     * </p>
     * 
     * @param tagResourceRequest
     * @return A Java Future containing the result of the TagResource operation returned by the service.
     * @sample AWSQAppsAsync.TagResource
     * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/qapps-2023-11-27/TagResource" target="_top">AWS API
     *      Documentation</a>
     */
    java.util.concurrent.Future<TagResourceResult> tagResourceAsync(TagResourceRequest tagResourceRequest);

    /**
     * <p>
     * Associates tags with an Amazon Q Apps resource.
     * </p>
     * 
     * @param tagResourceRequest
     * @param asyncHandler
     *        Asynchronous callback handler for events in the lifecycle of the request. Users can provide an
     *        implementation of the callback methods in this interface to receive notification of successful or
     *        unsuccessful completion of the operation.
     * @return A Java Future containing the result of the TagResource operation returned by the service.
     * @sample AWSQAppsAsyncHandler.TagResource
     * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/qapps-2023-11-27/TagResource" target="_top">AWS API
     *      Documentation</a>
     */
    java.util.concurrent.Future<TagResourceResult> tagResourceAsync(TagResourceRequest tagResourceRequest,
            com.amazonaws.handlers.AsyncHandler<TagResourceRequest, TagResourceResult> asyncHandler);

    /**
     * <p>
     * Disassociates tags from an Amazon Q Apps resource.
     * </p>
     * 
     * @param untagResourceRequest
     * @return A Java Future containing the result of the UntagResource operation returned by the service.
     * @sample AWSQAppsAsync.UntagResource
     * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/qapps-2023-11-27/UntagResource" target="_top">AWS API
     *      Documentation</a>
     */
    java.util.concurrent.Future<UntagResourceResult> untagResourceAsync(UntagResourceRequest untagResourceRequest);

    /**
     * <p>
     * Disassociates tags from an Amazon Q Apps resource.
     * </p>
     * 
     * @param untagResourceRequest
     * @param asyncHandler
     *        Asynchronous callback handler for events in the lifecycle of the request. Users can provide an
     *        implementation of the callback methods in this interface to receive notification of successful or
     *        unsuccessful completion of the operation.
     * @return A Java Future containing the result of the UntagResource operation returned by the service.
     * @sample AWSQAppsAsyncHandler.UntagResource
     * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/qapps-2023-11-27/UntagResource" target="_top">AWS API
     *      Documentation</a>
     */
    java.util.concurrent.Future<UntagResourceResult> untagResourceAsync(UntagResourceRequest untagResourceRequest,
            com.amazonaws.handlers.AsyncHandler<UntagResourceRequest, UntagResourceResult> asyncHandler);

    /**
     * <p>
     * Updates the metadata and status of a library item for an Amazon Q App.
     * </p>
     * 
     * @param updateLibraryItemRequest
     * @return A Java Future containing the result of the UpdateLibraryItem operation returned by the service.
     * @sample AWSQAppsAsync.UpdateLibraryItem
     * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/qapps-2023-11-27/UpdateLibraryItem" target="_top">AWS API
     *      Documentation</a>
     */
    java.util.concurrent.Future<UpdateLibraryItemResult> updateLibraryItemAsync(UpdateLibraryItemRequest updateLibraryItemRequest);

    /**
     * <p>
     * Updates the metadata and status of a library item for an Amazon Q App.
     * </p>
     * 
     * @param updateLibraryItemRequest
     * @param asyncHandler
     *        Asynchronous callback handler for events in the lifecycle of the request. Users can provide an
     *        implementation of the callback methods in this interface to receive notification of successful or
     *        unsuccessful completion of the operation.
     * @return A Java Future containing the result of the UpdateLibraryItem operation returned by the service.
     * @sample AWSQAppsAsyncHandler.UpdateLibraryItem
     * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/qapps-2023-11-27/UpdateLibraryItem" target="_top">AWS API
     *      Documentation</a>
     */
    java.util.concurrent.Future<UpdateLibraryItemResult> updateLibraryItemAsync(UpdateLibraryItemRequest updateLibraryItemRequest,
            com.amazonaws.handlers.AsyncHandler<UpdateLibraryItemRequest, UpdateLibraryItemResult> asyncHandler);

    /**
     * <p>
     * Updates an existing Amazon Q App, allowing modifications to its title, description, and definition.
     * </p>
     * 
     * @param updateQAppRequest
     * @return A Java Future containing the result of the UpdateQApp operation returned by the service.
     * @sample AWSQAppsAsync.UpdateQApp
     * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/qapps-2023-11-27/UpdateQApp" target="_top">AWS API
     *      Documentation</a>
     */
    java.util.concurrent.Future<UpdateQAppResult> updateQAppAsync(UpdateQAppRequest updateQAppRequest);

    /**
     * <p>
     * Updates an existing Amazon Q App, allowing modifications to its title, description, and definition.
     * </p>
     * 
     * @param updateQAppRequest
     * @param asyncHandler
     *        Asynchronous callback handler for events in the lifecycle of the request. Users can provide an
     *        implementation of the callback methods in this interface to receive notification of successful or
     *        unsuccessful completion of the operation.
     * @return A Java Future containing the result of the UpdateQApp operation returned by the service.
     * @sample AWSQAppsAsyncHandler.UpdateQApp
     * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/qapps-2023-11-27/UpdateQApp" target="_top">AWS API
     *      Documentation</a>
     */
    java.util.concurrent.Future<UpdateQAppResult> updateQAppAsync(UpdateQAppRequest updateQAppRequest,
            com.amazonaws.handlers.AsyncHandler<UpdateQAppRequest, UpdateQAppResult> asyncHandler);

    /**
     * <p>
     * Updates the session for a given Q App <code>sessionId</code>. This is only valid when at least one card of the
     * session is in the <code>WAITING</code> state. Data for each <code>WAITING</code> card can be provided as input.
     * If inputs are not provided, the call will be accepted but session will not move forward. Inputs for cards that
     * are not in the <code>WAITING</code> status will be ignored.
     * </p>
     * 
     * @param updateQAppSessionRequest
     * @return A Java Future containing the result of the UpdateQAppSession operation returned by the service.
     * @sample AWSQAppsAsync.UpdateQAppSession
     * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/qapps-2023-11-27/UpdateQAppSession" target="_top">AWS API
     *      Documentation</a>
     */
    java.util.concurrent.Future<UpdateQAppSessionResult> updateQAppSessionAsync(UpdateQAppSessionRequest updateQAppSessionRequest);

    /**
     * <p>
     * Updates the session for a given Q App <code>sessionId</code>. This is only valid when at least one card of the
     * session is in the <code>WAITING</code> state. Data for each <code>WAITING</code> card can be provided as input.
     * If inputs are not provided, the call will be accepted but session will not move forward. Inputs for cards that
     * are not in the <code>WAITING</code> status will be ignored.
     * </p>
     * 
     * @param updateQAppSessionRequest
     * @param asyncHandler
     *        Asynchronous callback handler for events in the lifecycle of the request. Users can provide an
     *        implementation of the callback methods in this interface to receive notification of successful or
     *        unsuccessful completion of the operation.
     * @return A Java Future containing the result of the UpdateQAppSession operation returned by the service.
     * @sample AWSQAppsAsyncHandler.UpdateQAppSession
     * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/qapps-2023-11-27/UpdateQAppSession" target="_top">AWS API
     *      Documentation</a>
     */
    java.util.concurrent.Future<UpdateQAppSessionResult> updateQAppSessionAsync(UpdateQAppSessionRequest updateQAppSessionRequest,
            com.amazonaws.handlers.AsyncHandler<UpdateQAppSessionRequest, UpdateQAppSessionResult> asyncHandler);

}
