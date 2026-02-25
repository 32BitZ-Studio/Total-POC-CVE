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

import org.w3c.dom.*;

import java.net.*;
import java.util.*;

import javax.annotation.Generated;

import org.apache.commons.logging.*;

import com.amazonaws.*;
import com.amazonaws.annotation.SdkInternalApi;
import com.amazonaws.auth.*;

import com.amazonaws.handlers.*;
import com.amazonaws.http.*;
import com.amazonaws.internal.*;
import com.amazonaws.internal.auth.*;
import com.amazonaws.metrics.*;
import com.amazonaws.regions.*;
import com.amazonaws.transform.*;
import com.amazonaws.util.*;
import com.amazonaws.protocol.json.*;
import com.amazonaws.util.AWSRequestMetrics.Field;
import com.amazonaws.annotation.ThreadSafe;
import com.amazonaws.client.AwsSyncClientParams;
import com.amazonaws.client.builder.AdvancedConfig;

import com.amazonaws.services.qapps.AWSQAppsClientBuilder;

import com.amazonaws.AmazonServiceException;

import com.amazonaws.services.qapps.model.*;

import com.amazonaws.services.qapps.model.transform.*;

/**
 * Client for accessing QApps. All service calls made using this client are blocking, and will not return until the
 * service call completes.
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
public class AWSQAppsClient extends AmazonWebServiceClient implements AWSQApps {

    /** Provider for AWS credentials. */
    private final AWSCredentialsProvider awsCredentialsProvider;

    private static final Log log = LogFactory.getLog(AWSQApps.class);

    /** Default signing name for the service. */
    private static final String DEFAULT_SIGNING_NAME = "qapps";

    /** Client configuration factory providing ClientConfigurations tailored to this client */
    protected static final ClientConfigurationFactory configFactory = new ClientConfigurationFactory();

    private final AdvancedConfig advancedConfig;

    private static final com.amazonaws.protocol.json.SdkJsonProtocolFactory protocolFactory = new com.amazonaws.protocol.json.SdkJsonProtocolFactory(
            new JsonClientMetadata()
                    .withProtocolVersion("1.1")
                    .withSupportsCbor(false)
                    .withSupportsIon(false)
                    .withContentTypeOverride("application/json")
                    .addErrorMetadata(
                            new JsonErrorShapeMetadata().withErrorCode("AccessDeniedException").withExceptionUnmarshaller(
                                    com.amazonaws.services.qapps.model.transform.AccessDeniedExceptionUnmarshaller.getInstance()))
                    .addErrorMetadata(
                            new JsonErrorShapeMetadata().withErrorCode("ConflictException").withExceptionUnmarshaller(
                                    com.amazonaws.services.qapps.model.transform.ConflictExceptionUnmarshaller.getInstance()))
                    .addErrorMetadata(
                            new JsonErrorShapeMetadata().withErrorCode("ResourceNotFoundException").withExceptionUnmarshaller(
                                    com.amazonaws.services.qapps.model.transform.ResourceNotFoundExceptionUnmarshaller.getInstance()))
                    .addErrorMetadata(
                            new JsonErrorShapeMetadata().withErrorCode("ThrottlingException").withExceptionUnmarshaller(
                                    com.amazonaws.services.qapps.model.transform.ThrottlingExceptionUnmarshaller.getInstance()))
                    .addErrorMetadata(
                            new JsonErrorShapeMetadata().withErrorCode("ContentTooLargeException").withExceptionUnmarshaller(
                                    com.amazonaws.services.qapps.model.transform.ContentTooLargeExceptionUnmarshaller.getInstance()))
                    .addErrorMetadata(
                            new JsonErrorShapeMetadata().withErrorCode("ValidationException").withExceptionUnmarshaller(
                                    com.amazonaws.services.qapps.model.transform.ValidationExceptionUnmarshaller.getInstance()))
                    .addErrorMetadata(
                            new JsonErrorShapeMetadata().withErrorCode("UnauthorizedException").withExceptionUnmarshaller(
                                    com.amazonaws.services.qapps.model.transform.UnauthorizedExceptionUnmarshaller.getInstance()))
                    .addErrorMetadata(
                            new JsonErrorShapeMetadata().withErrorCode("ServiceQuotaExceededException").withExceptionUnmarshaller(
                                    com.amazonaws.services.qapps.model.transform.ServiceQuotaExceededExceptionUnmarshaller.getInstance()))
                    .addErrorMetadata(
                            new JsonErrorShapeMetadata().withErrorCode("InternalServerException").withExceptionUnmarshaller(
                                    com.amazonaws.services.qapps.model.transform.InternalServerExceptionUnmarshaller.getInstance()))
                    .withBaseServiceExceptionClass(com.amazonaws.services.qapps.model.AWSQAppsException.class));

    public static AWSQAppsClientBuilder builder() {
        return AWSQAppsClientBuilder.standard();
    }

    /**
     * Constructs a new client to invoke service methods on QApps using the specified parameters.
     *
     * <p>
     * All service calls made using this new client object are blocking, and will not return until the service call
     * completes.
     *
     * @param clientParams
     *        Object providing client parameters.
     */
    AWSQAppsClient(AwsSyncClientParams clientParams) {
        this(clientParams, false);
    }

    /**
     * Constructs a new client to invoke service methods on QApps using the specified parameters.
     *
     * <p>
     * All service calls made using this new client object are blocking, and will not return until the service call
     * completes.
     *
     * @param clientParams
     *        Object providing client parameters.
     */
    AWSQAppsClient(AwsSyncClientParams clientParams, boolean endpointDiscoveryEnabled) {
        super(clientParams);
        this.awsCredentialsProvider = clientParams.getCredentialsProvider();
        this.advancedConfig = clientParams.getAdvancedConfig();
        init();
    }

    private void init() {
        setServiceNameIntern(DEFAULT_SIGNING_NAME);
        setEndpointPrefix(ENDPOINT_PREFIX);
        // calling this.setEndPoint(...) will also modify the signer accordingly
        setEndpoint("data.qapps.us-east-1.amazonaws.com");
        HandlerChainFactory chainFactory = new HandlerChainFactory();
        requestHandler2s.addAll(chainFactory.newRequestHandlerChain("/com/amazonaws/services/qapps/request.handlers"));
        requestHandler2s.addAll(chainFactory.newRequestHandler2Chain("/com/amazonaws/services/qapps/request.handler2s"));
        requestHandler2s.addAll(chainFactory.getGlobalHandlers());
    }

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
    @Override
    public AssociateLibraryItemReviewResult associateLibraryItemReview(AssociateLibraryItemReviewRequest request) {
        request = beforeClientExecution(request);
        return executeAssociateLibraryItemReview(request);
    }

    @SdkInternalApi
    final AssociateLibraryItemReviewResult executeAssociateLibraryItemReview(AssociateLibraryItemReviewRequest associateLibraryItemReviewRequest) {

        ExecutionContext executionContext = createExecutionContext(associateLibraryItemReviewRequest);
        AWSRequestMetrics awsRequestMetrics = executionContext.getAwsRequestMetrics();
        awsRequestMetrics.startEvent(Field.ClientExecuteTime);
        Request<AssociateLibraryItemReviewRequest> request = null;
        Response<AssociateLibraryItemReviewResult> response = null;

        try {
            awsRequestMetrics.startEvent(Field.RequestMarshallTime);
            try {
                request = new AssociateLibraryItemReviewRequestProtocolMarshaller(protocolFactory).marshall(super
                        .beforeMarshalling(associateLibraryItemReviewRequest));
                // Binds the request metrics to the current request.
                request.setAWSRequestMetrics(awsRequestMetrics);
                request.addHandlerContext(HandlerContextKey.CLIENT_ENDPOINT, endpoint);
                request.addHandlerContext(HandlerContextKey.ENDPOINT_OVERRIDDEN, isEndpointOverridden());
                request.addHandlerContext(HandlerContextKey.SIGNING_REGION, getSigningRegion());
                request.addHandlerContext(HandlerContextKey.SERVICE_ID, "QApps");
                request.addHandlerContext(HandlerContextKey.OPERATION_NAME, "AssociateLibraryItemReview");
                request.addHandlerContext(HandlerContextKey.ADVANCED_CONFIG, advancedConfig);

            } finally {
                awsRequestMetrics.endEvent(Field.RequestMarshallTime);
            }

            HttpResponseHandler<AmazonWebServiceResponse<AssociateLibraryItemReviewResult>> responseHandler = protocolFactory.createResponseHandler(
                    new JsonOperationMetadata().withPayloadJson(true).withHasStreamingSuccessResponse(false),
                    new AssociateLibraryItemReviewResultJsonUnmarshaller());
            response = invoke(request, responseHandler, executionContext);

            return response.getAwsResponse();

        } finally {

            endClientExecution(awsRequestMetrics, request, response);
        }
    }

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
    @Override
    public AssociateQAppWithUserResult associateQAppWithUser(AssociateQAppWithUserRequest request) {
        request = beforeClientExecution(request);
        return executeAssociateQAppWithUser(request);
    }

    @SdkInternalApi
    final AssociateQAppWithUserResult executeAssociateQAppWithUser(AssociateQAppWithUserRequest associateQAppWithUserRequest) {

        ExecutionContext executionContext = createExecutionContext(associateQAppWithUserRequest);
        AWSRequestMetrics awsRequestMetrics = executionContext.getAwsRequestMetrics();
        awsRequestMetrics.startEvent(Field.ClientExecuteTime);
        Request<AssociateQAppWithUserRequest> request = null;
        Response<AssociateQAppWithUserResult> response = null;

        try {
            awsRequestMetrics.startEvent(Field.RequestMarshallTime);
            try {
                request = new AssociateQAppWithUserRequestProtocolMarshaller(protocolFactory).marshall(super.beforeMarshalling(associateQAppWithUserRequest));
                // Binds the request metrics to the current request.
                request.setAWSRequestMetrics(awsRequestMetrics);
                request.addHandlerContext(HandlerContextKey.CLIENT_ENDPOINT, endpoint);
                request.addHandlerContext(HandlerContextKey.ENDPOINT_OVERRIDDEN, isEndpointOverridden());
                request.addHandlerContext(HandlerContextKey.SIGNING_REGION, getSigningRegion());
                request.addHandlerContext(HandlerContextKey.SERVICE_ID, "QApps");
                request.addHandlerContext(HandlerContextKey.OPERATION_NAME, "AssociateQAppWithUser");
                request.addHandlerContext(HandlerContextKey.ADVANCED_CONFIG, advancedConfig);

            } finally {
                awsRequestMetrics.endEvent(Field.RequestMarshallTime);
            }

            HttpResponseHandler<AmazonWebServiceResponse<AssociateQAppWithUserResult>> responseHandler = protocolFactory
                    .createResponseHandler(new JsonOperationMetadata().withPayloadJson(true).withHasStreamingSuccessResponse(false),
                            new AssociateQAppWithUserResultJsonUnmarshaller());
            response = invoke(request, responseHandler, executionContext);

            return response.getAwsResponse();

        } finally {

            endClientExecution(awsRequestMetrics, request, response);
        }
    }

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
    @Override
    public CreateLibraryItemResult createLibraryItem(CreateLibraryItemRequest request) {
        request = beforeClientExecution(request);
        return executeCreateLibraryItem(request);
    }

    @SdkInternalApi
    final CreateLibraryItemResult executeCreateLibraryItem(CreateLibraryItemRequest createLibraryItemRequest) {

        ExecutionContext executionContext = createExecutionContext(createLibraryItemRequest);
        AWSRequestMetrics awsRequestMetrics = executionContext.getAwsRequestMetrics();
        awsRequestMetrics.startEvent(Field.ClientExecuteTime);
        Request<CreateLibraryItemRequest> request = null;
        Response<CreateLibraryItemResult> response = null;

        try {
            awsRequestMetrics.startEvent(Field.RequestMarshallTime);
            try {
                request = new CreateLibraryItemRequestProtocolMarshaller(protocolFactory).marshall(super.beforeMarshalling(createLibraryItemRequest));
                // Binds the request metrics to the current request.
                request.setAWSRequestMetrics(awsRequestMetrics);
                request.addHandlerContext(HandlerContextKey.CLIENT_ENDPOINT, endpoint);
                request.addHandlerContext(HandlerContextKey.ENDPOINT_OVERRIDDEN, isEndpointOverridden());
                request.addHandlerContext(HandlerContextKey.SIGNING_REGION, getSigningRegion());
                request.addHandlerContext(HandlerContextKey.SERVICE_ID, "QApps");
                request.addHandlerContext(HandlerContextKey.OPERATION_NAME, "CreateLibraryItem");
                request.addHandlerContext(HandlerContextKey.ADVANCED_CONFIG, advancedConfig);

            } finally {
                awsRequestMetrics.endEvent(Field.RequestMarshallTime);
            }

            HttpResponseHandler<AmazonWebServiceResponse<CreateLibraryItemResult>> responseHandler = protocolFactory.createResponseHandler(
                    new JsonOperationMetadata().withPayloadJson(true).withHasStreamingSuccessResponse(false), new CreateLibraryItemResultJsonUnmarshaller());
            response = invoke(request, responseHandler, executionContext);

            return response.getAwsResponse();

        } finally {

            endClientExecution(awsRequestMetrics, request, response);
        }
    }

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
    @Override
    public CreateQAppResult createQApp(CreateQAppRequest request) {
        request = beforeClientExecution(request);
        return executeCreateQApp(request);
    }

    @SdkInternalApi
    final CreateQAppResult executeCreateQApp(CreateQAppRequest createQAppRequest) {

        ExecutionContext executionContext = createExecutionContext(createQAppRequest);
        AWSRequestMetrics awsRequestMetrics = executionContext.getAwsRequestMetrics();
        awsRequestMetrics.startEvent(Field.ClientExecuteTime);
        Request<CreateQAppRequest> request = null;
        Response<CreateQAppResult> response = null;

        try {
            awsRequestMetrics.startEvent(Field.RequestMarshallTime);
            try {
                request = new CreateQAppRequestProtocolMarshaller(protocolFactory).marshall(super.beforeMarshalling(createQAppRequest));
                // Binds the request metrics to the current request.
                request.setAWSRequestMetrics(awsRequestMetrics);
                request.addHandlerContext(HandlerContextKey.CLIENT_ENDPOINT, endpoint);
                request.addHandlerContext(HandlerContextKey.ENDPOINT_OVERRIDDEN, isEndpointOverridden());
                request.addHandlerContext(HandlerContextKey.SIGNING_REGION, getSigningRegion());
                request.addHandlerContext(HandlerContextKey.SERVICE_ID, "QApps");
                request.addHandlerContext(HandlerContextKey.OPERATION_NAME, "CreateQApp");
                request.addHandlerContext(HandlerContextKey.ADVANCED_CONFIG, advancedConfig);

            } finally {
                awsRequestMetrics.endEvent(Field.RequestMarshallTime);
            }

            HttpResponseHandler<AmazonWebServiceResponse<CreateQAppResult>> responseHandler = protocolFactory.createResponseHandler(new JsonOperationMetadata()
                    .withPayloadJson(true).withHasStreamingSuccessResponse(false), new CreateQAppResultJsonUnmarshaller());
            response = invoke(request, responseHandler, executionContext);

            return response.getAwsResponse();

        } finally {

            endClientExecution(awsRequestMetrics, request, response);
        }
    }

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
    @Override
    public DeleteLibraryItemResult deleteLibraryItem(DeleteLibraryItemRequest request) {
        request = beforeClientExecution(request);
        return executeDeleteLibraryItem(request);
    }

    @SdkInternalApi
    final DeleteLibraryItemResult executeDeleteLibraryItem(DeleteLibraryItemRequest deleteLibraryItemRequest) {

        ExecutionContext executionContext = createExecutionContext(deleteLibraryItemRequest);
        AWSRequestMetrics awsRequestMetrics = executionContext.getAwsRequestMetrics();
        awsRequestMetrics.startEvent(Field.ClientExecuteTime);
        Request<DeleteLibraryItemRequest> request = null;
        Response<DeleteLibraryItemResult> response = null;

        try {
            awsRequestMetrics.startEvent(Field.RequestMarshallTime);
            try {
                request = new DeleteLibraryItemRequestProtocolMarshaller(protocolFactory).marshall(super.beforeMarshalling(deleteLibraryItemRequest));
                // Binds the request metrics to the current request.
                request.setAWSRequestMetrics(awsRequestMetrics);
                request.addHandlerContext(HandlerContextKey.CLIENT_ENDPOINT, endpoint);
                request.addHandlerContext(HandlerContextKey.ENDPOINT_OVERRIDDEN, isEndpointOverridden());
                request.addHandlerContext(HandlerContextKey.SIGNING_REGION, getSigningRegion());
                request.addHandlerContext(HandlerContextKey.SERVICE_ID, "QApps");
                request.addHandlerContext(HandlerContextKey.OPERATION_NAME, "DeleteLibraryItem");
                request.addHandlerContext(HandlerContextKey.ADVANCED_CONFIG, advancedConfig);

            } finally {
                awsRequestMetrics.endEvent(Field.RequestMarshallTime);
            }

            HttpResponseHandler<AmazonWebServiceResponse<DeleteLibraryItemResult>> responseHandler = protocolFactory.createResponseHandler(
                    new JsonOperationMetadata().withPayloadJson(true).withHasStreamingSuccessResponse(false), new DeleteLibraryItemResultJsonUnmarshaller());
            response = invoke(request, responseHandler, executionContext);

            return response.getAwsResponse();

        } finally {

            endClientExecution(awsRequestMetrics, request, response);
        }
    }

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
    @Override
    public DeleteQAppResult deleteQApp(DeleteQAppRequest request) {
        request = beforeClientExecution(request);
        return executeDeleteQApp(request);
    }

    @SdkInternalApi
    final DeleteQAppResult executeDeleteQApp(DeleteQAppRequest deleteQAppRequest) {

        ExecutionContext executionContext = createExecutionContext(deleteQAppRequest);
        AWSRequestMetrics awsRequestMetrics = executionContext.getAwsRequestMetrics();
        awsRequestMetrics.startEvent(Field.ClientExecuteTime);
        Request<DeleteQAppRequest> request = null;
        Response<DeleteQAppResult> response = null;

        try {
            awsRequestMetrics.startEvent(Field.RequestMarshallTime);
            try {
                request = new DeleteQAppRequestProtocolMarshaller(protocolFactory).marshall(super.beforeMarshalling(deleteQAppRequest));
                // Binds the request metrics to the current request.
                request.setAWSRequestMetrics(awsRequestMetrics);
                request.addHandlerContext(HandlerContextKey.CLIENT_ENDPOINT, endpoint);
                request.addHandlerContext(HandlerContextKey.ENDPOINT_OVERRIDDEN, isEndpointOverridden());
                request.addHandlerContext(HandlerContextKey.SIGNING_REGION, getSigningRegion());
                request.addHandlerContext(HandlerContextKey.SERVICE_ID, "QApps");
                request.addHandlerContext(HandlerContextKey.OPERATION_NAME, "DeleteQApp");
                request.addHandlerContext(HandlerContextKey.ADVANCED_CONFIG, advancedConfig);

            } finally {
                awsRequestMetrics.endEvent(Field.RequestMarshallTime);
            }

            HttpResponseHandler<AmazonWebServiceResponse<DeleteQAppResult>> responseHandler = protocolFactory.createResponseHandler(new JsonOperationMetadata()
                    .withPayloadJson(true).withHasStreamingSuccessResponse(false), new DeleteQAppResultJsonUnmarshaller());
            response = invoke(request, responseHandler, executionContext);

            return response.getAwsResponse();

        } finally {

            endClientExecution(awsRequestMetrics, request, response);
        }
    }

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
    @Override
    public DisassociateLibraryItemReviewResult disassociateLibraryItemReview(DisassociateLibraryItemReviewRequest request) {
        request = beforeClientExecution(request);
        return executeDisassociateLibraryItemReview(request);
    }

    @SdkInternalApi
    final DisassociateLibraryItemReviewResult executeDisassociateLibraryItemReview(DisassociateLibraryItemReviewRequest disassociateLibraryItemReviewRequest) {

        ExecutionContext executionContext = createExecutionContext(disassociateLibraryItemReviewRequest);
        AWSRequestMetrics awsRequestMetrics = executionContext.getAwsRequestMetrics();
        awsRequestMetrics.startEvent(Field.ClientExecuteTime);
        Request<DisassociateLibraryItemReviewRequest> request = null;
        Response<DisassociateLibraryItemReviewResult> response = null;

        try {
            awsRequestMetrics.startEvent(Field.RequestMarshallTime);
            try {
                request = new DisassociateLibraryItemReviewRequestProtocolMarshaller(protocolFactory).marshall(super
                        .beforeMarshalling(disassociateLibraryItemReviewRequest));
                // Binds the request metrics to the current request.
                request.setAWSRequestMetrics(awsRequestMetrics);
                request.addHandlerContext(HandlerContextKey.CLIENT_ENDPOINT, endpoint);
                request.addHandlerContext(HandlerContextKey.ENDPOINT_OVERRIDDEN, isEndpointOverridden());
                request.addHandlerContext(HandlerContextKey.SIGNING_REGION, getSigningRegion());
                request.addHandlerContext(HandlerContextKey.SERVICE_ID, "QApps");
                request.addHandlerContext(HandlerContextKey.OPERATION_NAME, "DisassociateLibraryItemReview");
                request.addHandlerContext(HandlerContextKey.ADVANCED_CONFIG, advancedConfig);

            } finally {
                awsRequestMetrics.endEvent(Field.RequestMarshallTime);
            }

            HttpResponseHandler<AmazonWebServiceResponse<DisassociateLibraryItemReviewResult>> responseHandler = protocolFactory.createResponseHandler(
                    new JsonOperationMetadata().withPayloadJson(true).withHasStreamingSuccessResponse(false),
                    new DisassociateLibraryItemReviewResultJsonUnmarshaller());
            response = invoke(request, responseHandler, executionContext);

            return response.getAwsResponse();

        } finally {

            endClientExecution(awsRequestMetrics, request, response);
        }
    }

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
    @Override
    public DisassociateQAppFromUserResult disassociateQAppFromUser(DisassociateQAppFromUserRequest request) {
        request = beforeClientExecution(request);
        return executeDisassociateQAppFromUser(request);
    }

    @SdkInternalApi
    final DisassociateQAppFromUserResult executeDisassociateQAppFromUser(DisassociateQAppFromUserRequest disassociateQAppFromUserRequest) {

        ExecutionContext executionContext = createExecutionContext(disassociateQAppFromUserRequest);
        AWSRequestMetrics awsRequestMetrics = executionContext.getAwsRequestMetrics();
        awsRequestMetrics.startEvent(Field.ClientExecuteTime);
        Request<DisassociateQAppFromUserRequest> request = null;
        Response<DisassociateQAppFromUserResult> response = null;

        try {
            awsRequestMetrics.startEvent(Field.RequestMarshallTime);
            try {
                request = new DisassociateQAppFromUserRequestProtocolMarshaller(protocolFactory).marshall(super
                        .beforeMarshalling(disassociateQAppFromUserRequest));
                // Binds the request metrics to the current request.
                request.setAWSRequestMetrics(awsRequestMetrics);
                request.addHandlerContext(HandlerContextKey.CLIENT_ENDPOINT, endpoint);
                request.addHandlerContext(HandlerContextKey.ENDPOINT_OVERRIDDEN, isEndpointOverridden());
                request.addHandlerContext(HandlerContextKey.SIGNING_REGION, getSigningRegion());
                request.addHandlerContext(HandlerContextKey.SERVICE_ID, "QApps");
                request.addHandlerContext(HandlerContextKey.OPERATION_NAME, "DisassociateQAppFromUser");
                request.addHandlerContext(HandlerContextKey.ADVANCED_CONFIG, advancedConfig);

            } finally {
                awsRequestMetrics.endEvent(Field.RequestMarshallTime);
            }

            HttpResponseHandler<AmazonWebServiceResponse<DisassociateQAppFromUserResult>> responseHandler = protocolFactory.createResponseHandler(
                    new JsonOperationMetadata().withPayloadJson(true).withHasStreamingSuccessResponse(false),
                    new DisassociateQAppFromUserResultJsonUnmarshaller());
            response = invoke(request, responseHandler, executionContext);

            return response.getAwsResponse();

        } finally {

            endClientExecution(awsRequestMetrics, request, response);
        }
    }

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
    @Override
    public GetLibraryItemResult getLibraryItem(GetLibraryItemRequest request) {
        request = beforeClientExecution(request);
        return executeGetLibraryItem(request);
    }

    @SdkInternalApi
    final GetLibraryItemResult executeGetLibraryItem(GetLibraryItemRequest getLibraryItemRequest) {

        ExecutionContext executionContext = createExecutionContext(getLibraryItemRequest);
        AWSRequestMetrics awsRequestMetrics = executionContext.getAwsRequestMetrics();
        awsRequestMetrics.startEvent(Field.ClientExecuteTime);
        Request<GetLibraryItemRequest> request = null;
        Response<GetLibraryItemResult> response = null;

        try {
            awsRequestMetrics.startEvent(Field.RequestMarshallTime);
            try {
                request = new GetLibraryItemRequestProtocolMarshaller(protocolFactory).marshall(super.beforeMarshalling(getLibraryItemRequest));
                // Binds the request metrics to the current request.
                request.setAWSRequestMetrics(awsRequestMetrics);
                request.addHandlerContext(HandlerContextKey.CLIENT_ENDPOINT, endpoint);
                request.addHandlerContext(HandlerContextKey.ENDPOINT_OVERRIDDEN, isEndpointOverridden());
                request.addHandlerContext(HandlerContextKey.SIGNING_REGION, getSigningRegion());
                request.addHandlerContext(HandlerContextKey.SERVICE_ID, "QApps");
                request.addHandlerContext(HandlerContextKey.OPERATION_NAME, "GetLibraryItem");
                request.addHandlerContext(HandlerContextKey.ADVANCED_CONFIG, advancedConfig);

            } finally {
                awsRequestMetrics.endEvent(Field.RequestMarshallTime);
            }

            HttpResponseHandler<AmazonWebServiceResponse<GetLibraryItemResult>> responseHandler = protocolFactory.createResponseHandler(
                    new JsonOperationMetadata().withPayloadJson(true).withHasStreamingSuccessResponse(false), new GetLibraryItemResultJsonUnmarshaller());
            response = invoke(request, responseHandler, executionContext);

            return response.getAwsResponse();

        } finally {

            endClientExecution(awsRequestMetrics, request, response);
        }
    }

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
    @Override
    public GetQAppResult getQApp(GetQAppRequest request) {
        request = beforeClientExecution(request);
        return executeGetQApp(request);
    }

    @SdkInternalApi
    final GetQAppResult executeGetQApp(GetQAppRequest getQAppRequest) {

        ExecutionContext executionContext = createExecutionContext(getQAppRequest);
        AWSRequestMetrics awsRequestMetrics = executionContext.getAwsRequestMetrics();
        awsRequestMetrics.startEvent(Field.ClientExecuteTime);
        Request<GetQAppRequest> request = null;
        Response<GetQAppResult> response = null;

        try {
            awsRequestMetrics.startEvent(Field.RequestMarshallTime);
            try {
                request = new GetQAppRequestProtocolMarshaller(protocolFactory).marshall(super.beforeMarshalling(getQAppRequest));
                // Binds the request metrics to the current request.
                request.setAWSRequestMetrics(awsRequestMetrics);
                request.addHandlerContext(HandlerContextKey.CLIENT_ENDPOINT, endpoint);
                request.addHandlerContext(HandlerContextKey.ENDPOINT_OVERRIDDEN, isEndpointOverridden());
                request.addHandlerContext(HandlerContextKey.SIGNING_REGION, getSigningRegion());
                request.addHandlerContext(HandlerContextKey.SERVICE_ID, "QApps");
                request.addHandlerContext(HandlerContextKey.OPERATION_NAME, "GetQApp");
                request.addHandlerContext(HandlerContextKey.ADVANCED_CONFIG, advancedConfig);

            } finally {
                awsRequestMetrics.endEvent(Field.RequestMarshallTime);
            }

            HttpResponseHandler<AmazonWebServiceResponse<GetQAppResult>> responseHandler = protocolFactory.createResponseHandler(new JsonOperationMetadata()
                    .withPayloadJson(true).withHasStreamingSuccessResponse(false), new GetQAppResultJsonUnmarshaller());
            response = invoke(request, responseHandler, executionContext);

            return response.getAwsResponse();

        } finally {

            endClientExecution(awsRequestMetrics, request, response);
        }
    }

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
    @Override
    public GetQAppSessionResult getQAppSession(GetQAppSessionRequest request) {
        request = beforeClientExecution(request);
        return executeGetQAppSession(request);
    }

    @SdkInternalApi
    final GetQAppSessionResult executeGetQAppSession(GetQAppSessionRequest getQAppSessionRequest) {

        ExecutionContext executionContext = createExecutionContext(getQAppSessionRequest);
        AWSRequestMetrics awsRequestMetrics = executionContext.getAwsRequestMetrics();
        awsRequestMetrics.startEvent(Field.ClientExecuteTime);
        Request<GetQAppSessionRequest> request = null;
        Response<GetQAppSessionResult> response = null;

        try {
            awsRequestMetrics.startEvent(Field.RequestMarshallTime);
            try {
                request = new GetQAppSessionRequestProtocolMarshaller(protocolFactory).marshall(super.beforeMarshalling(getQAppSessionRequest));
                // Binds the request metrics to the current request.
                request.setAWSRequestMetrics(awsRequestMetrics);
                request.addHandlerContext(HandlerContextKey.CLIENT_ENDPOINT, endpoint);
                request.addHandlerContext(HandlerContextKey.ENDPOINT_OVERRIDDEN, isEndpointOverridden());
                request.addHandlerContext(HandlerContextKey.SIGNING_REGION, getSigningRegion());
                request.addHandlerContext(HandlerContextKey.SERVICE_ID, "QApps");
                request.addHandlerContext(HandlerContextKey.OPERATION_NAME, "GetQAppSession");
                request.addHandlerContext(HandlerContextKey.ADVANCED_CONFIG, advancedConfig);

            } finally {
                awsRequestMetrics.endEvent(Field.RequestMarshallTime);
            }

            HttpResponseHandler<AmazonWebServiceResponse<GetQAppSessionResult>> responseHandler = protocolFactory.createResponseHandler(
                    new JsonOperationMetadata().withPayloadJson(true).withHasStreamingSuccessResponse(false), new GetQAppSessionResultJsonUnmarshaller());
            response = invoke(request, responseHandler, executionContext);

            return response.getAwsResponse();

        } finally {

            endClientExecution(awsRequestMetrics, request, response);
        }
    }

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
    @Override
    public ImportDocumentResult importDocument(ImportDocumentRequest request) {
        request = beforeClientExecution(request);
        return executeImportDocument(request);
    }

    @SdkInternalApi
    final ImportDocumentResult executeImportDocument(ImportDocumentRequest importDocumentRequest) {

        ExecutionContext executionContext = createExecutionContext(importDocumentRequest);
        AWSRequestMetrics awsRequestMetrics = executionContext.getAwsRequestMetrics();
        awsRequestMetrics.startEvent(Field.ClientExecuteTime);
        Request<ImportDocumentRequest> request = null;
        Response<ImportDocumentResult> response = null;

        try {
            awsRequestMetrics.startEvent(Field.RequestMarshallTime);
            try {
                request = new ImportDocumentRequestProtocolMarshaller(protocolFactory).marshall(super.beforeMarshalling(importDocumentRequest));
                // Binds the request metrics to the current request.
                request.setAWSRequestMetrics(awsRequestMetrics);
                request.addHandlerContext(HandlerContextKey.CLIENT_ENDPOINT, endpoint);
                request.addHandlerContext(HandlerContextKey.ENDPOINT_OVERRIDDEN, isEndpointOverridden());
                request.addHandlerContext(HandlerContextKey.SIGNING_REGION, getSigningRegion());
                request.addHandlerContext(HandlerContextKey.SERVICE_ID, "QApps");
                request.addHandlerContext(HandlerContextKey.OPERATION_NAME, "ImportDocument");
                request.addHandlerContext(HandlerContextKey.ADVANCED_CONFIG, advancedConfig);

            } finally {
                awsRequestMetrics.endEvent(Field.RequestMarshallTime);
            }

            HttpResponseHandler<AmazonWebServiceResponse<ImportDocumentResult>> responseHandler = protocolFactory.createResponseHandler(
                    new JsonOperationMetadata().withPayloadJson(true).withHasStreamingSuccessResponse(false), new ImportDocumentResultJsonUnmarshaller());
            response = invoke(request, responseHandler, executionContext);

            return response.getAwsResponse();

        } finally {

            endClientExecution(awsRequestMetrics, request, response);
        }
    }

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
    @Override
    public ListLibraryItemsResult listLibraryItems(ListLibraryItemsRequest request) {
        request = beforeClientExecution(request);
        return executeListLibraryItems(request);
    }

    @SdkInternalApi
    final ListLibraryItemsResult executeListLibraryItems(ListLibraryItemsRequest listLibraryItemsRequest) {

        ExecutionContext executionContext = createExecutionContext(listLibraryItemsRequest);
        AWSRequestMetrics awsRequestMetrics = executionContext.getAwsRequestMetrics();
        awsRequestMetrics.startEvent(Field.ClientExecuteTime);
        Request<ListLibraryItemsRequest> request = null;
        Response<ListLibraryItemsResult> response = null;

        try {
            awsRequestMetrics.startEvent(Field.RequestMarshallTime);
            try {
                request = new ListLibraryItemsRequestProtocolMarshaller(protocolFactory).marshall(super.beforeMarshalling(listLibraryItemsRequest));
                // Binds the request metrics to the current request.
                request.setAWSRequestMetrics(awsRequestMetrics);
                request.addHandlerContext(HandlerContextKey.CLIENT_ENDPOINT, endpoint);
                request.addHandlerContext(HandlerContextKey.ENDPOINT_OVERRIDDEN, isEndpointOverridden());
                request.addHandlerContext(HandlerContextKey.SIGNING_REGION, getSigningRegion());
                request.addHandlerContext(HandlerContextKey.SERVICE_ID, "QApps");
                request.addHandlerContext(HandlerContextKey.OPERATION_NAME, "ListLibraryItems");
                request.addHandlerContext(HandlerContextKey.ADVANCED_CONFIG, advancedConfig);

            } finally {
                awsRequestMetrics.endEvent(Field.RequestMarshallTime);
            }

            HttpResponseHandler<AmazonWebServiceResponse<ListLibraryItemsResult>> responseHandler = protocolFactory.createResponseHandler(
                    new JsonOperationMetadata().withPayloadJson(true).withHasStreamingSuccessResponse(false), new ListLibraryItemsResultJsonUnmarshaller());
            response = invoke(request, responseHandler, executionContext);

            return response.getAwsResponse();

        } finally {

            endClientExecution(awsRequestMetrics, request, response);
        }
    }

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
    @Override
    public ListQAppsResult listQApps(ListQAppsRequest request) {
        request = beforeClientExecution(request);
        return executeListQApps(request);
    }

    @SdkInternalApi
    final ListQAppsResult executeListQApps(ListQAppsRequest listQAppsRequest) {

        ExecutionContext executionContext = createExecutionContext(listQAppsRequest);
        AWSRequestMetrics awsRequestMetrics = executionContext.getAwsRequestMetrics();
        awsRequestMetrics.startEvent(Field.ClientExecuteTime);
        Request<ListQAppsRequest> request = null;
        Response<ListQAppsResult> response = null;

        try {
            awsRequestMetrics.startEvent(Field.RequestMarshallTime);
            try {
                request = new ListQAppsRequestProtocolMarshaller(protocolFactory).marshall(super.beforeMarshalling(listQAppsRequest));
                // Binds the request metrics to the current request.
                request.setAWSRequestMetrics(awsRequestMetrics);
                request.addHandlerContext(HandlerContextKey.CLIENT_ENDPOINT, endpoint);
                request.addHandlerContext(HandlerContextKey.ENDPOINT_OVERRIDDEN, isEndpointOverridden());
                request.addHandlerContext(HandlerContextKey.SIGNING_REGION, getSigningRegion());
                request.addHandlerContext(HandlerContextKey.SERVICE_ID, "QApps");
                request.addHandlerContext(HandlerContextKey.OPERATION_NAME, "ListQApps");
                request.addHandlerContext(HandlerContextKey.ADVANCED_CONFIG, advancedConfig);

            } finally {
                awsRequestMetrics.endEvent(Field.RequestMarshallTime);
            }

            HttpResponseHandler<AmazonWebServiceResponse<ListQAppsResult>> responseHandler = protocolFactory.createResponseHandler(new JsonOperationMetadata()
                    .withPayloadJson(true).withHasStreamingSuccessResponse(false), new ListQAppsResultJsonUnmarshaller());
            response = invoke(request, responseHandler, executionContext);

            return response.getAwsResponse();

        } finally {

            endClientExecution(awsRequestMetrics, request, response);
        }
    }

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
    @Override
    public ListTagsForResourceResult listTagsForResource(ListTagsForResourceRequest request) {
        request = beforeClientExecution(request);
        return executeListTagsForResource(request);
    }

    @SdkInternalApi
    final ListTagsForResourceResult executeListTagsForResource(ListTagsForResourceRequest listTagsForResourceRequest) {

        ExecutionContext executionContext = createExecutionContext(listTagsForResourceRequest);
        AWSRequestMetrics awsRequestMetrics = executionContext.getAwsRequestMetrics();
        awsRequestMetrics.startEvent(Field.ClientExecuteTime);
        Request<ListTagsForResourceRequest> request = null;
        Response<ListTagsForResourceResult> response = null;

        try {
            awsRequestMetrics.startEvent(Field.RequestMarshallTime);
            try {
                request = new ListTagsForResourceRequestProtocolMarshaller(protocolFactory).marshall(super.beforeMarshalling(listTagsForResourceRequest));
                // Binds the request metrics to the current request.
                request.setAWSRequestMetrics(awsRequestMetrics);
                request.addHandlerContext(HandlerContextKey.CLIENT_ENDPOINT, endpoint);
                request.addHandlerContext(HandlerContextKey.ENDPOINT_OVERRIDDEN, isEndpointOverridden());
                request.addHandlerContext(HandlerContextKey.SIGNING_REGION, getSigningRegion());
                request.addHandlerContext(HandlerContextKey.SERVICE_ID, "QApps");
                request.addHandlerContext(HandlerContextKey.OPERATION_NAME, "ListTagsForResource");
                request.addHandlerContext(HandlerContextKey.ADVANCED_CONFIG, advancedConfig);

            } finally {
                awsRequestMetrics.endEvent(Field.RequestMarshallTime);
            }

            HttpResponseHandler<AmazonWebServiceResponse<ListTagsForResourceResult>> responseHandler = protocolFactory.createResponseHandler(
                    new JsonOperationMetadata().withPayloadJson(true).withHasStreamingSuccessResponse(false), new ListTagsForResourceResultJsonUnmarshaller());
            response = invoke(request, responseHandler, executionContext);

            return response.getAwsResponse();

        } finally {

            endClientExecution(awsRequestMetrics, request, response);
        }
    }

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
    @Override
    public PredictQAppResult predictQApp(PredictQAppRequest request) {
        request = beforeClientExecution(request);
        return executePredictQApp(request);
    }

    @SdkInternalApi
    final PredictQAppResult executePredictQApp(PredictQAppRequest predictQAppRequest) {

        ExecutionContext executionContext = createExecutionContext(predictQAppRequest);
        AWSRequestMetrics awsRequestMetrics = executionContext.getAwsRequestMetrics();
        awsRequestMetrics.startEvent(Field.ClientExecuteTime);
        Request<PredictQAppRequest> request = null;
        Response<PredictQAppResult> response = null;

        try {
            awsRequestMetrics.startEvent(Field.RequestMarshallTime);
            try {
                request = new PredictQAppRequestProtocolMarshaller(protocolFactory).marshall(super.beforeMarshalling(predictQAppRequest));
                // Binds the request metrics to the current request.
                request.setAWSRequestMetrics(awsRequestMetrics);
                request.addHandlerContext(HandlerContextKey.CLIENT_ENDPOINT, endpoint);
                request.addHandlerContext(HandlerContextKey.ENDPOINT_OVERRIDDEN, isEndpointOverridden());
                request.addHandlerContext(HandlerContextKey.SIGNING_REGION, getSigningRegion());
                request.addHandlerContext(HandlerContextKey.SERVICE_ID, "QApps");
                request.addHandlerContext(HandlerContextKey.OPERATION_NAME, "PredictQApp");
                request.addHandlerContext(HandlerContextKey.ADVANCED_CONFIG, advancedConfig);

            } finally {
                awsRequestMetrics.endEvent(Field.RequestMarshallTime);
            }

            HttpResponseHandler<AmazonWebServiceResponse<PredictQAppResult>> responseHandler = protocolFactory.createResponseHandler(
                    new JsonOperationMetadata().withPayloadJson(true).withHasStreamingSuccessResponse(false), new PredictQAppResultJsonUnmarshaller());
            response = invoke(request, responseHandler, executionContext);

            return response.getAwsResponse();

        } finally {

            endClientExecution(awsRequestMetrics, request, response);
        }
    }

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
    @Override
    public StartQAppSessionResult startQAppSession(StartQAppSessionRequest request) {
        request = beforeClientExecution(request);
        return executeStartQAppSession(request);
    }

    @SdkInternalApi
    final StartQAppSessionResult executeStartQAppSession(StartQAppSessionRequest startQAppSessionRequest) {

        ExecutionContext executionContext = createExecutionContext(startQAppSessionRequest);
        AWSRequestMetrics awsRequestMetrics = executionContext.getAwsRequestMetrics();
        awsRequestMetrics.startEvent(Field.ClientExecuteTime);
        Request<StartQAppSessionRequest> request = null;
        Response<StartQAppSessionResult> response = null;

        try {
            awsRequestMetrics.startEvent(Field.RequestMarshallTime);
            try {
                request = new StartQAppSessionRequestProtocolMarshaller(protocolFactory).marshall(super.beforeMarshalling(startQAppSessionRequest));
                // Binds the request metrics to the current request.
                request.setAWSRequestMetrics(awsRequestMetrics);
                request.addHandlerContext(HandlerContextKey.CLIENT_ENDPOINT, endpoint);
                request.addHandlerContext(HandlerContextKey.ENDPOINT_OVERRIDDEN, isEndpointOverridden());
                request.addHandlerContext(HandlerContextKey.SIGNING_REGION, getSigningRegion());
                request.addHandlerContext(HandlerContextKey.SERVICE_ID, "QApps");
                request.addHandlerContext(HandlerContextKey.OPERATION_NAME, "StartQAppSession");
                request.addHandlerContext(HandlerContextKey.ADVANCED_CONFIG, advancedConfig);

            } finally {
                awsRequestMetrics.endEvent(Field.RequestMarshallTime);
            }

            HttpResponseHandler<AmazonWebServiceResponse<StartQAppSessionResult>> responseHandler = protocolFactory.createResponseHandler(
                    new JsonOperationMetadata().withPayloadJson(true).withHasStreamingSuccessResponse(false), new StartQAppSessionResultJsonUnmarshaller());
            response = invoke(request, responseHandler, executionContext);

            return response.getAwsResponse();

        } finally {

            endClientExecution(awsRequestMetrics, request, response);
        }
    }

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
    @Override
    public StopQAppSessionResult stopQAppSession(StopQAppSessionRequest request) {
        request = beforeClientExecution(request);
        return executeStopQAppSession(request);
    }

    @SdkInternalApi
    final StopQAppSessionResult executeStopQAppSession(StopQAppSessionRequest stopQAppSessionRequest) {

        ExecutionContext executionContext = createExecutionContext(stopQAppSessionRequest);
        AWSRequestMetrics awsRequestMetrics = executionContext.getAwsRequestMetrics();
        awsRequestMetrics.startEvent(Field.ClientExecuteTime);
        Request<StopQAppSessionRequest> request = null;
        Response<StopQAppSessionResult> response = null;

        try {
            awsRequestMetrics.startEvent(Field.RequestMarshallTime);
            try {
                request = new StopQAppSessionRequestProtocolMarshaller(protocolFactory).marshall(super.beforeMarshalling(stopQAppSessionRequest));
                // Binds the request metrics to the current request.
                request.setAWSRequestMetrics(awsRequestMetrics);
                request.addHandlerContext(HandlerContextKey.CLIENT_ENDPOINT, endpoint);
                request.addHandlerContext(HandlerContextKey.ENDPOINT_OVERRIDDEN, isEndpointOverridden());
                request.addHandlerContext(HandlerContextKey.SIGNING_REGION, getSigningRegion());
                request.addHandlerContext(HandlerContextKey.SERVICE_ID, "QApps");
                request.addHandlerContext(HandlerContextKey.OPERATION_NAME, "StopQAppSession");
                request.addHandlerContext(HandlerContextKey.ADVANCED_CONFIG, advancedConfig);

            } finally {
                awsRequestMetrics.endEvent(Field.RequestMarshallTime);
            }

            HttpResponseHandler<AmazonWebServiceResponse<StopQAppSessionResult>> responseHandler = protocolFactory.createResponseHandler(
                    new JsonOperationMetadata().withPayloadJson(true).withHasStreamingSuccessResponse(false), new StopQAppSessionResultJsonUnmarshaller());
            response = invoke(request, responseHandler, executionContext);

            return response.getAwsResponse();

        } finally {

            endClientExecution(awsRequestMetrics, request, response);
        }
    }

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
    @Override
    public TagResourceResult tagResource(TagResourceRequest request) {
        request = beforeClientExecution(request);
        return executeTagResource(request);
    }

    @SdkInternalApi
    final TagResourceResult executeTagResource(TagResourceRequest tagResourceRequest) {

        ExecutionContext executionContext = createExecutionContext(tagResourceRequest);
        AWSRequestMetrics awsRequestMetrics = executionContext.getAwsRequestMetrics();
        awsRequestMetrics.startEvent(Field.ClientExecuteTime);
        Request<TagResourceRequest> request = null;
        Response<TagResourceResult> response = null;

        try {
            awsRequestMetrics.startEvent(Field.RequestMarshallTime);
            try {
                request = new TagResourceRequestProtocolMarshaller(protocolFactory).marshall(super.beforeMarshalling(tagResourceRequest));
                // Binds the request metrics to the current request.
                request.setAWSRequestMetrics(awsRequestMetrics);
                request.addHandlerContext(HandlerContextKey.CLIENT_ENDPOINT, endpoint);
                request.addHandlerContext(HandlerContextKey.ENDPOINT_OVERRIDDEN, isEndpointOverridden());
                request.addHandlerContext(HandlerContextKey.SIGNING_REGION, getSigningRegion());
                request.addHandlerContext(HandlerContextKey.SERVICE_ID, "QApps");
                request.addHandlerContext(HandlerContextKey.OPERATION_NAME, "TagResource");
                request.addHandlerContext(HandlerContextKey.ADVANCED_CONFIG, advancedConfig);

            } finally {
                awsRequestMetrics.endEvent(Field.RequestMarshallTime);
            }

            HttpResponseHandler<AmazonWebServiceResponse<TagResourceResult>> responseHandler = protocolFactory.createResponseHandler(
                    new JsonOperationMetadata().withPayloadJson(true).withHasStreamingSuccessResponse(false), new TagResourceResultJsonUnmarshaller());
            response = invoke(request, responseHandler, executionContext);

            return response.getAwsResponse();

        } finally {

            endClientExecution(awsRequestMetrics, request, response);
        }
    }

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
    @Override
    public UntagResourceResult untagResource(UntagResourceRequest request) {
        request = beforeClientExecution(request);
        return executeUntagResource(request);
    }

    @SdkInternalApi
    final UntagResourceResult executeUntagResource(UntagResourceRequest untagResourceRequest) {

        ExecutionContext executionContext = createExecutionContext(untagResourceRequest);
        AWSRequestMetrics awsRequestMetrics = executionContext.getAwsRequestMetrics();
        awsRequestMetrics.startEvent(Field.ClientExecuteTime);
        Request<UntagResourceRequest> request = null;
        Response<UntagResourceResult> response = null;

        try {
            awsRequestMetrics.startEvent(Field.RequestMarshallTime);
            try {
                request = new UntagResourceRequestProtocolMarshaller(protocolFactory).marshall(super.beforeMarshalling(untagResourceRequest));
                // Binds the request metrics to the current request.
                request.setAWSRequestMetrics(awsRequestMetrics);
                request.addHandlerContext(HandlerContextKey.CLIENT_ENDPOINT, endpoint);
                request.addHandlerContext(HandlerContextKey.ENDPOINT_OVERRIDDEN, isEndpointOverridden());
                request.addHandlerContext(HandlerContextKey.SIGNING_REGION, getSigningRegion());
                request.addHandlerContext(HandlerContextKey.SERVICE_ID, "QApps");
                request.addHandlerContext(HandlerContextKey.OPERATION_NAME, "UntagResource");
                request.addHandlerContext(HandlerContextKey.ADVANCED_CONFIG, advancedConfig);

            } finally {
                awsRequestMetrics.endEvent(Field.RequestMarshallTime);
            }

            HttpResponseHandler<AmazonWebServiceResponse<UntagResourceResult>> responseHandler = protocolFactory.createResponseHandler(
                    new JsonOperationMetadata().withPayloadJson(true).withHasStreamingSuccessResponse(false), new UntagResourceResultJsonUnmarshaller());
            response = invoke(request, responseHandler, executionContext);

            return response.getAwsResponse();

        } finally {

            endClientExecution(awsRequestMetrics, request, response);
        }
    }

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
    @Override
    public UpdateLibraryItemResult updateLibraryItem(UpdateLibraryItemRequest request) {
        request = beforeClientExecution(request);
        return executeUpdateLibraryItem(request);
    }

    @SdkInternalApi
    final UpdateLibraryItemResult executeUpdateLibraryItem(UpdateLibraryItemRequest updateLibraryItemRequest) {

        ExecutionContext executionContext = createExecutionContext(updateLibraryItemRequest);
        AWSRequestMetrics awsRequestMetrics = executionContext.getAwsRequestMetrics();
        awsRequestMetrics.startEvent(Field.ClientExecuteTime);
        Request<UpdateLibraryItemRequest> request = null;
        Response<UpdateLibraryItemResult> response = null;

        try {
            awsRequestMetrics.startEvent(Field.RequestMarshallTime);
            try {
                request = new UpdateLibraryItemRequestProtocolMarshaller(protocolFactory).marshall(super.beforeMarshalling(updateLibraryItemRequest));
                // Binds the request metrics to the current request.
                request.setAWSRequestMetrics(awsRequestMetrics);
                request.addHandlerContext(HandlerContextKey.CLIENT_ENDPOINT, endpoint);
                request.addHandlerContext(HandlerContextKey.ENDPOINT_OVERRIDDEN, isEndpointOverridden());
                request.addHandlerContext(HandlerContextKey.SIGNING_REGION, getSigningRegion());
                request.addHandlerContext(HandlerContextKey.SERVICE_ID, "QApps");
                request.addHandlerContext(HandlerContextKey.OPERATION_NAME, "UpdateLibraryItem");
                request.addHandlerContext(HandlerContextKey.ADVANCED_CONFIG, advancedConfig);

            } finally {
                awsRequestMetrics.endEvent(Field.RequestMarshallTime);
            }

            HttpResponseHandler<AmazonWebServiceResponse<UpdateLibraryItemResult>> responseHandler = protocolFactory.createResponseHandler(
                    new JsonOperationMetadata().withPayloadJson(true).withHasStreamingSuccessResponse(false), new UpdateLibraryItemResultJsonUnmarshaller());
            response = invoke(request, responseHandler, executionContext);

            return response.getAwsResponse();

        } finally {

            endClientExecution(awsRequestMetrics, request, response);
        }
    }

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
    @Override
    public UpdateQAppResult updateQApp(UpdateQAppRequest request) {
        request = beforeClientExecution(request);
        return executeUpdateQApp(request);
    }

    @SdkInternalApi
    final UpdateQAppResult executeUpdateQApp(UpdateQAppRequest updateQAppRequest) {

        ExecutionContext executionContext = createExecutionContext(updateQAppRequest);
        AWSRequestMetrics awsRequestMetrics = executionContext.getAwsRequestMetrics();
        awsRequestMetrics.startEvent(Field.ClientExecuteTime);
        Request<UpdateQAppRequest> request = null;
        Response<UpdateQAppResult> response = null;

        try {
            awsRequestMetrics.startEvent(Field.RequestMarshallTime);
            try {
                request = new UpdateQAppRequestProtocolMarshaller(protocolFactory).marshall(super.beforeMarshalling(updateQAppRequest));
                // Binds the request metrics to the current request.
                request.setAWSRequestMetrics(awsRequestMetrics);
                request.addHandlerContext(HandlerContextKey.CLIENT_ENDPOINT, endpoint);
                request.addHandlerContext(HandlerContextKey.ENDPOINT_OVERRIDDEN, isEndpointOverridden());
                request.addHandlerContext(HandlerContextKey.SIGNING_REGION, getSigningRegion());
                request.addHandlerContext(HandlerContextKey.SERVICE_ID, "QApps");
                request.addHandlerContext(HandlerContextKey.OPERATION_NAME, "UpdateQApp");
                request.addHandlerContext(HandlerContextKey.ADVANCED_CONFIG, advancedConfig);

            } finally {
                awsRequestMetrics.endEvent(Field.RequestMarshallTime);
            }

            HttpResponseHandler<AmazonWebServiceResponse<UpdateQAppResult>> responseHandler = protocolFactory.createResponseHandler(new JsonOperationMetadata()
                    .withPayloadJson(true).withHasStreamingSuccessResponse(false), new UpdateQAppResultJsonUnmarshaller());
            response = invoke(request, responseHandler, executionContext);

            return response.getAwsResponse();

        } finally {

            endClientExecution(awsRequestMetrics, request, response);
        }
    }

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
    @Override
    public UpdateQAppSessionResult updateQAppSession(UpdateQAppSessionRequest request) {
        request = beforeClientExecution(request);
        return executeUpdateQAppSession(request);
    }

    @SdkInternalApi
    final UpdateQAppSessionResult executeUpdateQAppSession(UpdateQAppSessionRequest updateQAppSessionRequest) {

        ExecutionContext executionContext = createExecutionContext(updateQAppSessionRequest);
        AWSRequestMetrics awsRequestMetrics = executionContext.getAwsRequestMetrics();
        awsRequestMetrics.startEvent(Field.ClientExecuteTime);
        Request<UpdateQAppSessionRequest> request = null;
        Response<UpdateQAppSessionResult> response = null;

        try {
            awsRequestMetrics.startEvent(Field.RequestMarshallTime);
            try {
                request = new UpdateQAppSessionRequestProtocolMarshaller(protocolFactory).marshall(super.beforeMarshalling(updateQAppSessionRequest));
                // Binds the request metrics to the current request.
                request.setAWSRequestMetrics(awsRequestMetrics);
                request.addHandlerContext(HandlerContextKey.CLIENT_ENDPOINT, endpoint);
                request.addHandlerContext(HandlerContextKey.ENDPOINT_OVERRIDDEN, isEndpointOverridden());
                request.addHandlerContext(HandlerContextKey.SIGNING_REGION, getSigningRegion());
                request.addHandlerContext(HandlerContextKey.SERVICE_ID, "QApps");
                request.addHandlerContext(HandlerContextKey.OPERATION_NAME, "UpdateQAppSession");
                request.addHandlerContext(HandlerContextKey.ADVANCED_CONFIG, advancedConfig);

            } finally {
                awsRequestMetrics.endEvent(Field.RequestMarshallTime);
            }

            HttpResponseHandler<AmazonWebServiceResponse<UpdateQAppSessionResult>> responseHandler = protocolFactory.createResponseHandler(
                    new JsonOperationMetadata().withPayloadJson(true).withHasStreamingSuccessResponse(false), new UpdateQAppSessionResultJsonUnmarshaller());
            response = invoke(request, responseHandler, executionContext);

            return response.getAwsResponse();

        } finally {

            endClientExecution(awsRequestMetrics, request, response);
        }
    }

    /**
     * Returns additional metadata for a previously executed successful, request, typically used for debugging issues
     * where a service isn't acting as expected. This data isn't considered part of the result data returned by an
     * operation, so it's available through this separate, diagnostic interface.
     * <p>
     * Response metadata is only cached for a limited period of time, so if you need to access this extra diagnostic
     * information for an executed request, you should use this method to retrieve it as soon as possible after
     * executing the request.
     *
     * @param request
     *        The originally executed request
     *
     * @return The response metadata for the specified request, or null if none is available.
     */
    public ResponseMetadata getCachedResponseMetadata(AmazonWebServiceRequest request) {
        return client.getResponseMetadataForRequest(request);
    }

    /**
     * Normal invoke with authentication. Credentials are required and may be overriden at the request level.
     **/
    private <X, Y extends AmazonWebServiceRequest> Response<X> invoke(Request<Y> request, HttpResponseHandler<AmazonWebServiceResponse<X>> responseHandler,
            ExecutionContext executionContext) {

        return invoke(request, responseHandler, executionContext, null, null);
    }

    /**
     * Normal invoke with authentication. Credentials are required and may be overriden at the request level.
     **/
    private <X, Y extends AmazonWebServiceRequest> Response<X> invoke(Request<Y> request, HttpResponseHandler<AmazonWebServiceResponse<X>> responseHandler,
            ExecutionContext executionContext, URI cachedEndpoint, URI uriFromEndpointTrait) {

        executionContext.setCredentialsProvider(CredentialUtils.getCredentialsProvider(request.getOriginalRequest(), awsCredentialsProvider));

        return doInvoke(request, responseHandler, executionContext, cachedEndpoint, uriFromEndpointTrait);
    }

    /**
     * Invoke with no authentication. Credentials are not required and any credentials set on the client or request will
     * be ignored for this operation.
     **/
    private <X, Y extends AmazonWebServiceRequest> Response<X> anonymousInvoke(Request<Y> request,
            HttpResponseHandler<AmazonWebServiceResponse<X>> responseHandler, ExecutionContext executionContext) {

        return doInvoke(request, responseHandler, executionContext, null, null);
    }

    /**
     * Invoke the request using the http client. Assumes credentials (or lack thereof) have been configured in the
     * ExecutionContext beforehand.
     **/
    private <X, Y extends AmazonWebServiceRequest> Response<X> doInvoke(Request<Y> request, HttpResponseHandler<AmazonWebServiceResponse<X>> responseHandler,
            ExecutionContext executionContext, URI discoveredEndpoint, URI uriFromEndpointTrait) {

        if (discoveredEndpoint != null) {
            request.setEndpoint(discoveredEndpoint);
            request.getOriginalRequest().getRequestClientOptions().appendUserAgent("endpoint-discovery");
        } else if (uriFromEndpointTrait != null) {
            request.setEndpoint(uriFromEndpointTrait);
        } else {
            request.setEndpoint(endpoint);
        }

        request.setTimeOffset(timeOffset);

        HttpResponseHandler<AmazonServiceException> errorResponseHandler = protocolFactory.createErrorResponseHandler(new JsonErrorResponseMetadata());

        return client.execute(request, responseHandler, errorResponseHandler, executionContext);
    }

    @com.amazonaws.annotation.SdkInternalApi
    static com.amazonaws.protocol.json.SdkJsonProtocolFactory getProtocolFactory() {
        return protocolFactory;
    }

    @Override
    public void shutdown() {
        super.shutdown();
    }

}
