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

import com.amazonaws.*;
import com.amazonaws.regions.*;

import com.amazonaws.services.qapps.model.*;

/**
 * Interface for accessing QApps.
 * <p>
 * <b>Note:</b> Do not directly implement this interface, new methods are added to it regularly. Extend from
 * {@link com.amazonaws.services.qapps.AbstractAWSQApps} instead.
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
public interface AWSQApps {

    /**
     * The region metadata service name for computing region endpoints. You can use this value to retrieve metadata
     * (such as supported regions) of the service.
     *
     * @see RegionUtils#getRegionsForService(String)
     */
    String ENDPOINT_PREFIX = "data.qapps";

    /**
     * <p>
     * Associates a rating or review for a library item with the user submitting the request. This increments the rating
     * count for the specified library item.
     * </p>
     * 
     * @param associateLibraryItemReviewRequest
     * @return Result of the AssociateLibraryItemReview operation returned by the service.
     * @throws ResourceNotFoundException
     *         The requested resource could not be found.
     * @throws AccessDeniedException
     *         The client is not authorized to perform the requested operation.
     * @throws ValidationException
     *         The input failed to satisfy the constraints specified by the service.
     * @throws InternalServerException
     *         An internal service error occurred while processing the request.
     * @throws UnauthorizedException
     *         The client is not authenticated or authorized to perform the requested operation.
     * @throws ServiceQuotaExceededException
     *         The requested operation could not be completed because it would exceed the service's quota or limit.
     * @throws ThrottlingException
     *         The requested operation could not be completed because too many requests were sent at once. Wait a bit
     *         and try again later.
     * @sample AWSQApps.AssociateLibraryItemReview
     * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/qapps-2023-11-27/AssociateLibraryItemReview"
     *      target="_top">AWS API Documentation</a>
     */
    AssociateLibraryItemReviewResult associateLibraryItemReview(AssociateLibraryItemReviewRequest associateLibraryItemReviewRequest);

    /**
     * <p>
     * This operation creates a link between the user's identity calling the operation and a specific Q App. This is
     * useful to mark the Q App as a <i>favorite</i> for the user if the user doesn't own the Amazon Q App so they can
     * still run it and see it in their inventory of Q Apps.
     * </p>
     * 
     * @param associateQAppWithUserRequest
     * @return Result of the AssociateQAppWithUser operation returned by the service.
     * @throws ResourceNotFoundException
     *         The requested resource could not be found.
     * @throws AccessDeniedException
     *         The client is not authorized to perform the requested operation.
     * @throws ValidationException
     *         The input failed to satisfy the constraints specified by the service.
     * @throws InternalServerException
     *         An internal service error occurred while processing the request.
     * @throws UnauthorizedException
     *         The client is not authenticated or authorized to perform the requested operation.
     * @throws ServiceQuotaExceededException
     *         The requested operation could not be completed because it would exceed the service's quota or limit.
     * @throws ThrottlingException
     *         The requested operation could not be completed because too many requests were sent at once. Wait a bit
     *         and try again later.
     * @sample AWSQApps.AssociateQAppWithUser
     * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/qapps-2023-11-27/AssociateQAppWithUser" target="_top">AWS
     *      API Documentation</a>
     */
    AssociateQAppWithUserResult associateQAppWithUser(AssociateQAppWithUserRequest associateQAppWithUserRequest);

    /**
     * <p>
     * Creates a new library item for an Amazon Q App, allowing it to be discovered and used by other allowed users.
     * </p>
     * 
     * @param createLibraryItemRequest
     * @return Result of the CreateLibraryItem operation returned by the service.
     * @throws ResourceNotFoundException
     *         The requested resource could not be found.
     * @throws AccessDeniedException
     *         The client is not authorized to perform the requested operation.
     * @throws ValidationException
     *         The input failed to satisfy the constraints specified by the service.
     * @throws InternalServerException
     *         An internal service error occurred while processing the request.
     * @throws UnauthorizedException
     *         The client is not authenticated or authorized to perform the requested operation.
     * @throws ServiceQuotaExceededException
     *         The requested operation could not be completed because it would exceed the service's quota or limit.
     * @throws ThrottlingException
     *         The requested operation could not be completed because too many requests were sent at once. Wait a bit
     *         and try again later.
     * @sample AWSQApps.CreateLibraryItem
     * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/qapps-2023-11-27/CreateLibraryItem" target="_top">AWS API
     *      Documentation</a>
     */
    CreateLibraryItemResult createLibraryItem(CreateLibraryItemRequest createLibraryItemRequest);

    /**
     * <p>
     * Creates a new Amazon Q App based on the provided definition. The Q App definition specifies the cards and flow of
     * the Q App. This operation also calculates the dependencies between the cards by inspecting the references in the
     * prompts.
     * </p>
     * 
     * @param createQAppRequest
     * @return Result of the CreateQApp operation returned by the service.
     * @throws AccessDeniedException
     *         The client is not authorized to perform the requested operation.
     * @throws ConflictException
     *         The requested operation could not be completed due to a conflict with the current state of the resource.
     * @throws ValidationException
     *         The input failed to satisfy the constraints specified by the service.
     * @throws InternalServerException
     *         An internal service error occurred while processing the request.
     * @throws UnauthorizedException
     *         The client is not authenticated or authorized to perform the requested operation.
     * @throws ServiceQuotaExceededException
     *         The requested operation could not be completed because it would exceed the service's quota or limit.
     * @throws ContentTooLargeException
     *         The requested operation could not be completed because the content exceeds the maximum allowed size.
     * @throws ThrottlingException
     *         The requested operation could not be completed because too many requests were sent at once. Wait a bit
     *         and try again later.
     * @sample AWSQApps.CreateQApp
     * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/qapps-2023-11-27/CreateQApp" target="_top">AWS API
     *      Documentation</a>
     */
    CreateQAppResult createQApp(CreateQAppRequest createQAppRequest);

    /**
     * <p>
     * Deletes a library item for an Amazon Q App, removing it from the library so it can no longer be discovered or
     * used by other users.
     * </p>
     * 
     * @param deleteLibraryItemRequest
     * @return Result of the DeleteLibraryItem operation returned by the service.
     * @throws ResourceNotFoundException
     *         The requested resource could not be found.
     * @throws AccessDeniedException
     *         The client is not authorized to perform the requested operation.
     * @throws ValidationException
     *         The input failed to satisfy the constraints specified by the service.
     * @throws InternalServerException
     *         An internal service error occurred while processing the request.
     * @throws UnauthorizedException
     *         The client is not authenticated or authorized to perform the requested operation.
     * @throws ServiceQuotaExceededException
     *         The requested operation could not be completed because it would exceed the service's quota or limit.
     * @throws ThrottlingException
     *         The requested operation could not be completed because too many requests were sent at once. Wait a bit
     *         and try again later.
     * @sample AWSQApps.DeleteLibraryItem
     * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/qapps-2023-11-27/DeleteLibraryItem" target="_top">AWS API
     *      Documentation</a>
     */
    DeleteLibraryItemResult deleteLibraryItem(DeleteLibraryItemRequest deleteLibraryItemRequest);

    /**
     * <p>
     * Deletes an Amazon Q App owned by the user. If the Q App was previously published to the library, it is also
     * removed from the library.
     * </p>
     * 
     * @param deleteQAppRequest
     * @return Result of the DeleteQApp operation returned by the service.
     * @throws ResourceNotFoundException
     *         The requested resource could not be found.
     * @throws AccessDeniedException
     *         The client is not authorized to perform the requested operation.
     * @throws ValidationException
     *         The input failed to satisfy the constraints specified by the service.
     * @throws InternalServerException
     *         An internal service error occurred while processing the request.
     * @throws UnauthorizedException
     *         The client is not authenticated or authorized to perform the requested operation.
     * @throws ThrottlingException
     *         The requested operation could not be completed because too many requests were sent at once. Wait a bit
     *         and try again later.
     * @sample AWSQApps.DeleteQApp
     * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/qapps-2023-11-27/DeleteQApp" target="_top">AWS API
     *      Documentation</a>
     */
    DeleteQAppResult deleteQApp(DeleteQAppRequest deleteQAppRequest);

    /**
     * <p>
     * Removes a rating or review previously submitted by the user for a library item.
     * </p>
     * 
     * @param disassociateLibraryItemReviewRequest
     * @return Result of the DisassociateLibraryItemReview operation returned by the service.
     * @throws ResourceNotFoundException
     *         The requested resource could not be found.
     * @throws AccessDeniedException
     *         The client is not authorized to perform the requested operation.
     * @throws ValidationException
     *         The input failed to satisfy the constraints specified by the service.
     * @throws InternalServerException
     *         An internal service error occurred while processing the request.
     * @throws UnauthorizedException
     *         The client is not authenticated or authorized to perform the requested operation.
     * @throws ServiceQuotaExceededException
     *         The requested operation could not be completed because it would exceed the service's quota or limit.
     * @throws ThrottlingException
     *         The requested operation could not be completed because too many requests were sent at once. Wait a bit
     *         and try again later.
     * @sample AWSQApps.DisassociateLibraryItemReview
     * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/qapps-2023-11-27/DisassociateLibraryItemReview"
     *      target="_top">AWS API Documentation</a>
     */
    DisassociateLibraryItemReviewResult disassociateLibraryItemReview(DisassociateLibraryItemReviewRequest disassociateLibraryItemReviewRequest);

    /**
     * <p>
     * Disassociates a Q App from a user removing the user's access to run the Q App.
     * </p>
     * 
     * @param disassociateQAppFromUserRequest
     * @return Result of the DisassociateQAppFromUser operation returned by the service.
     * @throws ResourceNotFoundException
     *         The requested resource could not be found.
     * @throws AccessDeniedException
     *         The client is not authorized to perform the requested operation.
     * @throws ValidationException
     *         The input failed to satisfy the constraints specified by the service.
     * @throws InternalServerException
     *         An internal service error occurred while processing the request.
     * @throws UnauthorizedException
     *         The client is not authenticated or authorized to perform the requested operation.
     * @throws ThrottlingException
     *         The requested operation could not be completed because too many requests were sent at once. Wait a bit
     *         and try again later.
     * @sample AWSQApps.DisassociateQAppFromUser
     * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/qapps-2023-11-27/DisassociateQAppFromUser" target="_top">AWS
     *      API Documentation</a>
     */
    DisassociateQAppFromUserResult disassociateQAppFromUser(DisassociateQAppFromUserRequest disassociateQAppFromUserRequest);

    /**
     * <p>
     * Retrieves details about a library item for an Amazon Q App, including its metadata, categories, ratings, and
     * usage statistics.
     * </p>
     * 
     * @param getLibraryItemRequest
     * @return Result of the GetLibraryItem operation returned by the service.
     * @throws ResourceNotFoundException
     *         The requested resource could not be found.
     * @throws AccessDeniedException
     *         The client is not authorized to perform the requested operation.
     * @throws ValidationException
     *         The input failed to satisfy the constraints specified by the service.
     * @throws InternalServerException
     *         An internal service error occurred while processing the request.
     * @throws UnauthorizedException
     *         The client is not authenticated or authorized to perform the requested operation.
     * @throws ThrottlingException
     *         The requested operation could not be completed because too many requests were sent at once. Wait a bit
     *         and try again later.
     * @sample AWSQApps.GetLibraryItem
     * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/qapps-2023-11-27/GetLibraryItem" target="_top">AWS API
     *      Documentation</a>
     */
    GetLibraryItemResult getLibraryItem(GetLibraryItemRequest getLibraryItemRequest);

    /**
     * <p>
     * Retrieves the full details of an Q App, including its definition specifying the cards and flow.
     * </p>
     * 
     * @param getQAppRequest
     * @return Result of the GetQApp operation returned by the service.
     * @throws ResourceNotFoundException
     *         The requested resource could not be found.
     * @throws AccessDeniedException
     *         The client is not authorized to perform the requested operation.
     * @throws ValidationException
     *         The input failed to satisfy the constraints specified by the service.
     * @throws InternalServerException
     *         An internal service error occurred while processing the request.
     * @throws UnauthorizedException
     *         The client is not authenticated or authorized to perform the requested operation.
     * @throws ThrottlingException
     *         The requested operation could not be completed because too many requests were sent at once. Wait a bit
     *         and try again later.
     * @sample AWSQApps.GetQApp
     * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/qapps-2023-11-27/GetQApp" target="_top">AWS API
     *      Documentation</a>
     */
    GetQAppResult getQApp(GetQAppRequest getQAppRequest);

    /**
     * <p>
     * Retrieves the current state and results for an active session of an Amazon Q App.
     * </p>
     * 
     * @param getQAppSessionRequest
     * @return Result of the GetQAppSession operation returned by the service.
     * @throws ResourceNotFoundException
     *         The requested resource could not be found.
     * @throws AccessDeniedException
     *         The client is not authorized to perform the requested operation.
     * @throws ValidationException
     *         The input failed to satisfy the constraints specified by the service.
     * @throws InternalServerException
     *         An internal service error occurred while processing the request.
     * @throws UnauthorizedException
     *         The client is not authenticated or authorized to perform the requested operation.
     * @throws ServiceQuotaExceededException
     *         The requested operation could not be completed because it would exceed the service's quota or limit.
     * @throws ThrottlingException
     *         The requested operation could not be completed because too many requests were sent at once. Wait a bit
     *         and try again later.
     * @sample AWSQApps.GetQAppSession
     * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/qapps-2023-11-27/GetQAppSession" target="_top">AWS API
     *      Documentation</a>
     */
    GetQAppSessionResult getQAppSession(GetQAppSessionRequest getQAppSessionRequest);

    /**
     * <p>
     * Uploads a file that can then be used either as a default in a <code>FileUploadCard</code> from Q App definition
     * or as a file that is used inside a single Q App run. The purpose of the document is determined by a scope
     * parameter that indicates whether it is at the app definition level or at the app session level.
     * </p>
     * 
     * @param importDocumentRequest
     * @return Result of the ImportDocument operation returned by the service.
     * @throws ResourceNotFoundException
     *         The requested resource could not be found.
     * @throws AccessDeniedException
     *         The client is not authorized to perform the requested operation.
     * @throws ValidationException
     *         The input failed to satisfy the constraints specified by the service.
     * @throws InternalServerException
     *         An internal service error occurred while processing the request.
     * @throws UnauthorizedException
     *         The client is not authenticated or authorized to perform the requested operation.
     * @throws ServiceQuotaExceededException
     *         The requested operation could not be completed because it would exceed the service's quota or limit.
     * @throws ContentTooLargeException
     *         The requested operation could not be completed because the content exceeds the maximum allowed size.
     * @throws ThrottlingException
     *         The requested operation could not be completed because too many requests were sent at once. Wait a bit
     *         and try again later.
     * @sample AWSQApps.ImportDocument
     * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/qapps-2023-11-27/ImportDocument" target="_top">AWS API
     *      Documentation</a>
     */
    ImportDocumentResult importDocument(ImportDocumentRequest importDocumentRequest);

    /**
     * <p>
     * Lists the library items for Amazon Q Apps that are published and available for users in your Amazon Web Services
     * account.
     * </p>
     * 
     * @param listLibraryItemsRequest
     * @return Result of the ListLibraryItems operation returned by the service.
     * @throws ResourceNotFoundException
     *         The requested resource could not be found.
     * @throws AccessDeniedException
     *         The client is not authorized to perform the requested operation.
     * @throws ValidationException
     *         The input failed to satisfy the constraints specified by the service.
     * @throws InternalServerException
     *         An internal service error occurred while processing the request.
     * @throws UnauthorizedException
     *         The client is not authenticated or authorized to perform the requested operation.
     * @throws ThrottlingException
     *         The requested operation could not be completed because too many requests were sent at once. Wait a bit
     *         and try again later.
     * @sample AWSQApps.ListLibraryItems
     * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/qapps-2023-11-27/ListLibraryItems" target="_top">AWS API
     *      Documentation</a>
     */
    ListLibraryItemsResult listLibraryItems(ListLibraryItemsRequest listLibraryItemsRequest);

    /**
     * <p>
     * Lists the Amazon Q Apps owned by or associated with the user either because they created it or because they used
     * it from the library in the past. The user identity is extracted from the credentials used to invoke this
     * operation..
     * </p>
     * 
     * @param listQAppsRequest
     * @return Result of the ListQApps operation returned by the service.
     * @throws AccessDeniedException
     *         The client is not authorized to perform the requested operation.
     * @throws ValidationException
     *         The input failed to satisfy the constraints specified by the service.
     * @throws InternalServerException
     *         An internal service error occurred while processing the request.
     * @throws UnauthorizedException
     *         The client is not authenticated or authorized to perform the requested operation.
     * @throws ThrottlingException
     *         The requested operation could not be completed because too many requests were sent at once. Wait a bit
     *         and try again later.
     * @sample AWSQApps.ListQApps
     * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/qapps-2023-11-27/ListQApps" target="_top">AWS API
     *      Documentation</a>
     */
    ListQAppsResult listQApps(ListQAppsRequest listQAppsRequest);

    /**
     * <p>
     * Lists the tags associated with an Amazon Q Apps resource.
     * </p>
     * 
     * @param listTagsForResourceRequest
     * @return Result of the ListTagsForResource operation returned by the service.
     * @throws ResourceNotFoundException
     *         The requested resource could not be found.
     * @throws AccessDeniedException
     *         The client is not authorized to perform the requested operation.
     * @throws ValidationException
     *         The input failed to satisfy the constraints specified by the service.
     * @throws InternalServerException
     *         An internal service error occurred while processing the request.
     * @throws ThrottlingException
     *         The requested operation could not be completed because too many requests were sent at once. Wait a bit
     *         and try again later.
     * @sample AWSQApps.ListTagsForResource
     * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/qapps-2023-11-27/ListTagsForResource" target="_top">AWS API
     *      Documentation</a>
     */
    ListTagsForResourceResult listTagsForResource(ListTagsForResourceRequest listTagsForResourceRequest);

    /**
     * <p>
     * Generates an Amazon Q App definition based on either a conversation or a problem statement provided as input.The
     * resulting app definition can be used to call <code>CreateQApp</code>. This API doesn't create Amazon Q Apps
     * directly.
     * </p>
     * 
     * @param predictQAppRequest
     * @return Result of the PredictQApp operation returned by the service.
     * @throws AccessDeniedException
     *         The client is not authorized to perform the requested operation.
     * @throws ValidationException
     *         The input failed to satisfy the constraints specified by the service.
     * @throws InternalServerException
     *         An internal service error occurred while processing the request.
     * @throws UnauthorizedException
     *         The client is not authenticated or authorized to perform the requested operation.
     * @throws ThrottlingException
     *         The requested operation could not be completed because too many requests were sent at once. Wait a bit
     *         and try again later.
     * @sample AWSQApps.PredictQApp
     * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/qapps-2023-11-27/PredictQApp" target="_top">AWS API
     *      Documentation</a>
     */
    PredictQAppResult predictQApp(PredictQAppRequest predictQAppRequest);

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
     * @return Result of the StartQAppSession operation returned by the service.
     * @throws ResourceNotFoundException
     *         The requested resource could not be found.
     * @throws AccessDeniedException
     *         The client is not authorized to perform the requested operation.
     * @throws ValidationException
     *         The input failed to satisfy the constraints specified by the service.
     * @throws InternalServerException
     *         An internal service error occurred while processing the request.
     * @throws UnauthorizedException
     *         The client is not authenticated or authorized to perform the requested operation.
     * @throws ServiceQuotaExceededException
     *         The requested operation could not be completed because it would exceed the service's quota or limit.
     * @throws ThrottlingException
     *         The requested operation could not be completed because too many requests were sent at once. Wait a bit
     *         and try again later.
     * @sample AWSQApps.StartQAppSession
     * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/qapps-2023-11-27/StartQAppSession" target="_top">AWS API
     *      Documentation</a>
     */
    StartQAppSessionResult startQAppSession(StartQAppSessionRequest startQAppSessionRequest);

    /**
     * <p>
     * Stops an active session for an Amazon Q App.This deletes all data related to the session and makes it invalid for
     * future uses. The results of the session will be persisted as part of the conversation.
     * </p>
     * 
     * @param stopQAppSessionRequest
     * @return Result of the StopQAppSession operation returned by the service.
     * @throws ResourceNotFoundException
     *         The requested resource could not be found.
     * @throws AccessDeniedException
     *         The client is not authorized to perform the requested operation.
     * @throws ValidationException
     *         The input failed to satisfy the constraints specified by the service.
     * @throws InternalServerException
     *         An internal service error occurred while processing the request.
     * @throws UnauthorizedException
     *         The client is not authenticated or authorized to perform the requested operation.
     * @throws ServiceQuotaExceededException
     *         The requested operation could not be completed because it would exceed the service's quota or limit.
     * @throws ThrottlingException
     *         The requested operation could not be completed because too many requests were sent at once. Wait a bit
     *         and try again later.
     * @sample AWSQApps.StopQAppSession
     * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/qapps-2023-11-27/StopQAppSession" target="_top">AWS API
     *      Documentation</a>
     */
    StopQAppSessionResult stopQAppSession(StopQAppSessionRequest stopQAppSessionRequest);

    /**
     * <p>
     * Associates tags with an Amazon Q Apps resource.
     * </p>
     * 
     * @param tagResourceRequest
     * @return Result of the TagResource operation returned by the service.
     * @throws ResourceNotFoundException
     *         The requested resource could not be found.
     * @throws AccessDeniedException
     *         The client is not authorized to perform the requested operation.
     * @throws ConflictException
     *         The requested operation could not be completed due to a conflict with the current state of the resource.
     * @throws ValidationException
     *         The input failed to satisfy the constraints specified by the service.
     * @throws InternalServerException
     *         An internal service error occurred while processing the request.
     * @throws ThrottlingException
     *         The requested operation could not be completed because too many requests were sent at once. Wait a bit
     *         and try again later.
     * @sample AWSQApps.TagResource
     * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/qapps-2023-11-27/TagResource" target="_top">AWS API
     *      Documentation</a>
     */
    TagResourceResult tagResource(TagResourceRequest tagResourceRequest);

    /**
     * <p>
     * Disassociates tags from an Amazon Q Apps resource.
     * </p>
     * 
     * @param untagResourceRequest
     * @return Result of the UntagResource operation returned by the service.
     * @throws ResourceNotFoundException
     *         The requested resource could not be found.
     * @throws AccessDeniedException
     *         The client is not authorized to perform the requested operation.
     * @throws ValidationException
     *         The input failed to satisfy the constraints specified by the service.
     * @throws InternalServerException
     *         An internal service error occurred while processing the request.
     * @throws ThrottlingException
     *         The requested operation could not be completed because too many requests were sent at once. Wait a bit
     *         and try again later.
     * @sample AWSQApps.UntagResource
     * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/qapps-2023-11-27/UntagResource" target="_top">AWS API
     *      Documentation</a>
     */
    UntagResourceResult untagResource(UntagResourceRequest untagResourceRequest);

    /**
     * <p>
     * Updates the metadata and status of a library item for an Amazon Q App.
     * </p>
     * 
     * @param updateLibraryItemRequest
     * @return Result of the UpdateLibraryItem operation returned by the service.
     * @throws ResourceNotFoundException
     *         The requested resource could not be found.
     * @throws AccessDeniedException
     *         The client is not authorized to perform the requested operation.
     * @throws ValidationException
     *         The input failed to satisfy the constraints specified by the service.
     * @throws InternalServerException
     *         An internal service error occurred while processing the request.
     * @throws UnauthorizedException
     *         The client is not authenticated or authorized to perform the requested operation.
     * @throws ThrottlingException
     *         The requested operation could not be completed because too many requests were sent at once. Wait a bit
     *         and try again later.
     * @sample AWSQApps.UpdateLibraryItem
     * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/qapps-2023-11-27/UpdateLibraryItem" target="_top">AWS API
     *      Documentation</a>
     */
    UpdateLibraryItemResult updateLibraryItem(UpdateLibraryItemRequest updateLibraryItemRequest);

    /**
     * <p>
     * Updates an existing Amazon Q App, allowing modifications to its title, description, and definition.
     * </p>
     * 
     * @param updateQAppRequest
     * @return Result of the UpdateQApp operation returned by the service.
     * @throws ResourceNotFoundException
     *         The requested resource could not be found.
     * @throws AccessDeniedException
     *         The client is not authorized to perform the requested operation.
     * @throws ValidationException
     *         The input failed to satisfy the constraints specified by the service.
     * @throws InternalServerException
     *         An internal service error occurred while processing the request.
     * @throws UnauthorizedException
     *         The client is not authenticated or authorized to perform the requested operation.
     * @throws ContentTooLargeException
     *         The requested operation could not be completed because the content exceeds the maximum allowed size.
     * @throws ThrottlingException
     *         The requested operation could not be completed because too many requests were sent at once. Wait a bit
     *         and try again later.
     * @sample AWSQApps.UpdateQApp
     * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/qapps-2023-11-27/UpdateQApp" target="_top">AWS API
     *      Documentation</a>
     */
    UpdateQAppResult updateQApp(UpdateQAppRequest updateQAppRequest);

    /**
     * <p>
     * Updates the session for a given Q App <code>sessionId</code>. This is only valid when at least one card of the
     * session is in the <code>WAITING</code> state. Data for each <code>WAITING</code> card can be provided as input.
     * If inputs are not provided, the call will be accepted but session will not move forward. Inputs for cards that
     * are not in the <code>WAITING</code> status will be ignored.
     * </p>
     * 
     * @param updateQAppSessionRequest
     * @return Result of the UpdateQAppSession operation returned by the service.
     * @throws ResourceNotFoundException
     *         The requested resource could not be found.
     * @throws AccessDeniedException
     *         The client is not authorized to perform the requested operation.
     * @throws ValidationException
     *         The input failed to satisfy the constraints specified by the service.
     * @throws InternalServerException
     *         An internal service error occurred while processing the request.
     * @throws UnauthorizedException
     *         The client is not authenticated or authorized to perform the requested operation.
     * @throws ServiceQuotaExceededException
     *         The requested operation could not be completed because it would exceed the service's quota or limit.
     * @throws ThrottlingException
     *         The requested operation could not be completed because too many requests were sent at once. Wait a bit
     *         and try again later.
     * @sample AWSQApps.UpdateQAppSession
     * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/qapps-2023-11-27/UpdateQAppSession" target="_top">AWS API
     *      Documentation</a>
     */
    UpdateQAppSessionResult updateQAppSession(UpdateQAppSessionRequest updateQAppSessionRequest);

    /**
     * Shuts down this client object, releasing any resources that might be held open. This is an optional method, and
     * callers are not expected to call it, but can if they want to explicitly release any open resources. Once a client
     * has been shutdown, it should not be used to make any more requests.
     */
    void shutdown();

    /**
     * Returns additional metadata for a previously executed successful request, typically used for debugging issues
     * where a service isn't acting as expected. This data isn't considered part of the result data returned by an
     * operation, so it's available through this separate, diagnostic interface.
     * <p>
     * Response metadata is only cached for a limited period of time, so if you need to access this extra diagnostic
     * information for an executed request, you should use this method to retrieve it as soon as possible after
     * executing a request.
     *
     * @param request
     *        The originally executed request.
     *
     * @return The response metadata for the specified request, or null if none is available.
     */
    ResponseMetadata getCachedResponseMetadata(AmazonWebServiceRequest request);

}
