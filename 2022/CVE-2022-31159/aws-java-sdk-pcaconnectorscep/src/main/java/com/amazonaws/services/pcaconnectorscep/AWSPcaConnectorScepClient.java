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

import com.amazonaws.services.pcaconnectorscep.AWSPcaConnectorScepClientBuilder;

import com.amazonaws.AmazonServiceException;

import com.amazonaws.services.pcaconnectorscep.model.*;

import com.amazonaws.services.pcaconnectorscep.model.transform.*;

/**
 * Client for accessing Private CA Connector for SCEP. All service calls made using this client are blocking, and will
 * not return until the service call completes.
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
public class AWSPcaConnectorScepClient extends AmazonWebServiceClient implements AWSPcaConnectorScep {

    /** Provider for AWS credentials. */
    private final AWSCredentialsProvider awsCredentialsProvider;

    private static final Log log = LogFactory.getLog(AWSPcaConnectorScep.class);

    /** Default signing name for the service. */
    private static final String DEFAULT_SIGNING_NAME = "pca-connector-scep";

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
                                    com.amazonaws.services.pcaconnectorscep.model.transform.AccessDeniedExceptionUnmarshaller.getInstance()))
                    .addErrorMetadata(
                            new JsonErrorShapeMetadata().withErrorCode("ValidationException").withExceptionUnmarshaller(
                                    com.amazonaws.services.pcaconnectorscep.model.transform.ValidationExceptionUnmarshaller.getInstance()))
                    .addErrorMetadata(
                            new JsonErrorShapeMetadata().withErrorCode("ConflictException").withExceptionUnmarshaller(
                                    com.amazonaws.services.pcaconnectorscep.model.transform.ConflictExceptionUnmarshaller.getInstance()))
                    .addErrorMetadata(
                            new JsonErrorShapeMetadata().withErrorCode("ResourceNotFoundException").withExceptionUnmarshaller(
                                    com.amazonaws.services.pcaconnectorscep.model.transform.ResourceNotFoundExceptionUnmarshaller.getInstance()))
                    .addErrorMetadata(
                            new JsonErrorShapeMetadata().withErrorCode("ServiceQuotaExceededException").withExceptionUnmarshaller(
                                    com.amazonaws.services.pcaconnectorscep.model.transform.ServiceQuotaExceededExceptionUnmarshaller.getInstance()))
                    .addErrorMetadata(
                            new JsonErrorShapeMetadata().withErrorCode("InternalServerException").withExceptionUnmarshaller(
                                    com.amazonaws.services.pcaconnectorscep.model.transform.InternalServerExceptionUnmarshaller.getInstance()))
                    .addErrorMetadata(
                            new JsonErrorShapeMetadata().withErrorCode("BadRequestException").withExceptionUnmarshaller(
                                    com.amazonaws.services.pcaconnectorscep.model.transform.BadRequestExceptionUnmarshaller.getInstance()))
                    .addErrorMetadata(
                            new JsonErrorShapeMetadata().withErrorCode("ThrottlingException").withExceptionUnmarshaller(
                                    com.amazonaws.services.pcaconnectorscep.model.transform.ThrottlingExceptionUnmarshaller.getInstance()))
                    .withBaseServiceExceptionClass(com.amazonaws.services.pcaconnectorscep.model.AWSPcaConnectorScepException.class));

    public static AWSPcaConnectorScepClientBuilder builder() {
        return AWSPcaConnectorScepClientBuilder.standard();
    }

    /**
     * Constructs a new client to invoke service methods on Private CA Connector for SCEP using the specified
     * parameters.
     *
     * <p>
     * All service calls made using this new client object are blocking, and will not return until the service call
     * completes.
     *
     * @param clientParams
     *        Object providing client parameters.
     */
    AWSPcaConnectorScepClient(AwsSyncClientParams clientParams) {
        this(clientParams, false);
    }

    /**
     * Constructs a new client to invoke service methods on Private CA Connector for SCEP using the specified
     * parameters.
     *
     * <p>
     * All service calls made using this new client object are blocking, and will not return until the service call
     * completes.
     *
     * @param clientParams
     *        Object providing client parameters.
     */
    AWSPcaConnectorScepClient(AwsSyncClientParams clientParams, boolean endpointDiscoveryEnabled) {
        super(clientParams);
        this.awsCredentialsProvider = clientParams.getCredentialsProvider();
        this.advancedConfig = clientParams.getAdvancedConfig();
        init();
    }

    private void init() {
        setServiceNameIntern(DEFAULT_SIGNING_NAME);
        setEndpointPrefix(ENDPOINT_PREFIX);
        // calling this.setEndPoint(...) will also modify the signer accordingly
        setEndpoint("pca-connector-scep.us-east-1.amazonaws.com");
        HandlerChainFactory chainFactory = new HandlerChainFactory();
        requestHandler2s.addAll(chainFactory.newRequestHandlerChain("/com/amazonaws/services/pcaconnectorscep/request.handlers"));
        requestHandler2s.addAll(chainFactory.newRequestHandler2Chain("/com/amazonaws/services/pcaconnectorscep/request.handler2s"));
        requestHandler2s.addAll(chainFactory.getGlobalHandlers());
    }

    /**
     * <p>
     * For general-purpose connectors. Creates a <i>challenge password</i> for the specified connector. The SCEP
     * protocol uses a challenge password to authenticate a request before issuing a certificate from a certificate
     * authority (CA). Your SCEP clients include the challenge password as part of their certificate request to
     * Connector for SCEP. To retrieve the connector Amazon Resource Names (ARNs) for the connectors in your account,
     * call <a
     * href="https://docs.aws.amazon.com/C4SCEP_API/pca-connector-scep/latest/APIReference/API_ListConnectors.html"
     * >ListConnectors</a>.
     * </p>
     * <p>
     * To create additional challenge passwords for the connector, call <code>CreateChallenge</code> again. We recommend
     * frequently rotating your challenge passwords.
     * </p>
     * 
     * @param createChallengeRequest
     * @return Result of the CreateChallenge operation returned by the service.
     * @throws ResourceNotFoundException
     *         The operation tried to access a nonexistent resource. The resource might be incorrectly specified, or it
     *         might have a status other than <code>ACTIVE</code>.
     * @throws BadRequestException
     *         The request is malformed or contains an error such as an invalid parameter value or a missing required
     *         parameter.
     * @throws InternalServerException
     *         The request processing has failed because of an unknown error, exception or failure with an internal
     *         server.
     * @throws ValidationException
     *         An input validation error occurred. For example, invalid characters in a name tag, or an invalid
     *         pagination token.
     * @throws ThrottlingException
     *         The limit on the number of requests per second was exceeded.
     * @throws AccessDeniedException
     *         You can receive this error if you attempt to perform an operation and you don't have the required
     *         permissions. This can be caused by insufficient permissions in policies attached to your Amazon Web
     *         Services Identity and Access Management (IAM) principal. It can also happen because of restrictions in
     *         place from an Amazon Web Services Organizations service control policy (SCP) that affects your Amazon Web
     *         Services account.
     * @throws ConflictException
     *         This request can't be completed for one of the following reasons because the requested resource was being
     *         concurrently modified by another request.
     * @throws ServiceQuotaExceededException
     *         The request would cause a service quota to be exceeded.
     * @sample AWSPcaConnectorScep.CreateChallenge
     * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/pca-connector-scep-2018-05-10/CreateChallenge"
     *      target="_top">AWS API Documentation</a>
     */
    @Override
    public CreateChallengeResult createChallenge(CreateChallengeRequest request) {
        request = beforeClientExecution(request);
        return executeCreateChallenge(request);
    }

    @SdkInternalApi
    final CreateChallengeResult executeCreateChallenge(CreateChallengeRequest createChallengeRequest) {

        ExecutionContext executionContext = createExecutionContext(createChallengeRequest);
        AWSRequestMetrics awsRequestMetrics = executionContext.getAwsRequestMetrics();
        awsRequestMetrics.startEvent(Field.ClientExecuteTime);
        Request<CreateChallengeRequest> request = null;
        Response<CreateChallengeResult> response = null;

        try {
            awsRequestMetrics.startEvent(Field.RequestMarshallTime);
            try {
                request = new CreateChallengeRequestProtocolMarshaller(protocolFactory).marshall(super.beforeMarshalling(createChallengeRequest));
                // Binds the request metrics to the current request.
                request.setAWSRequestMetrics(awsRequestMetrics);
                request.addHandlerContext(HandlerContextKey.CLIENT_ENDPOINT, endpoint);
                request.addHandlerContext(HandlerContextKey.ENDPOINT_OVERRIDDEN, isEndpointOverridden());
                request.addHandlerContext(HandlerContextKey.SIGNING_REGION, getSigningRegion());
                request.addHandlerContext(HandlerContextKey.SERVICE_ID, "Pca Connector Scep");
                request.addHandlerContext(HandlerContextKey.OPERATION_NAME, "CreateChallenge");
                request.addHandlerContext(HandlerContextKey.ADVANCED_CONFIG, advancedConfig);

            } finally {
                awsRequestMetrics.endEvent(Field.RequestMarshallTime);
            }

            HttpResponseHandler<AmazonWebServiceResponse<CreateChallengeResult>> responseHandler = protocolFactory.createResponseHandler(
                    new JsonOperationMetadata().withPayloadJson(true).withHasStreamingSuccessResponse(false), new CreateChallengeResultJsonUnmarshaller());
            response = invoke(request, responseHandler, executionContext);

            return response.getAwsResponse();

        } finally {

            endClientExecution(awsRequestMetrics, request, response);
        }
    }

    /**
     * <p>
     * Creates a SCEP connector. A SCEP connector links Amazon Web Services Private Certificate Authority to your
     * SCEP-compatible devices and mobile device management (MDM) systems. Before you create a connector, you must
     * complete a set of prerequisites, including creation of a private certificate authority (CA) to use with this
     * connector. For more information, see <a href=
     * "https://docs.aws.amazon.com/privateca/latest/userguide/scep-connector.htmlconnector-for-scep-prerequisites.html"
     * >Connector for SCEP prerequisites</a>.
     * </p>
     * 
     * @param createConnectorRequest
     * @return Result of the CreateConnector operation returned by the service.
     * @throws ResourceNotFoundException
     *         The operation tried to access a nonexistent resource. The resource might be incorrectly specified, or it
     *         might have a status other than <code>ACTIVE</code>.
     * @throws InternalServerException
     *         The request processing has failed because of an unknown error, exception or failure with an internal
     *         server.
     * @throws ValidationException
     *         An input validation error occurred. For example, invalid characters in a name tag, or an invalid
     *         pagination token.
     * @throws ThrottlingException
     *         The limit on the number of requests per second was exceeded.
     * @throws AccessDeniedException
     *         You can receive this error if you attempt to perform an operation and you don't have the required
     *         permissions. This can be caused by insufficient permissions in policies attached to your Amazon Web
     *         Services Identity and Access Management (IAM) principal. It can also happen because of restrictions in
     *         place from an Amazon Web Services Organizations service control policy (SCP) that affects your Amazon Web
     *         Services account.
     * @throws ConflictException
     *         This request can't be completed for one of the following reasons because the requested resource was being
     *         concurrently modified by another request.
     * @throws ServiceQuotaExceededException
     *         The request would cause a service quota to be exceeded.
     * @sample AWSPcaConnectorScep.CreateConnector
     * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/pca-connector-scep-2018-05-10/CreateConnector"
     *      target="_top">AWS API Documentation</a>
     */
    @Override
    public CreateConnectorResult createConnector(CreateConnectorRequest request) {
        request = beforeClientExecution(request);
        return executeCreateConnector(request);
    }

    @SdkInternalApi
    final CreateConnectorResult executeCreateConnector(CreateConnectorRequest createConnectorRequest) {

        ExecutionContext executionContext = createExecutionContext(createConnectorRequest);
        AWSRequestMetrics awsRequestMetrics = executionContext.getAwsRequestMetrics();
        awsRequestMetrics.startEvent(Field.ClientExecuteTime);
        Request<CreateConnectorRequest> request = null;
        Response<CreateConnectorResult> response = null;

        try {
            awsRequestMetrics.startEvent(Field.RequestMarshallTime);
            try {
                request = new CreateConnectorRequestProtocolMarshaller(protocolFactory).marshall(super.beforeMarshalling(createConnectorRequest));
                // Binds the request metrics to the current request.
                request.setAWSRequestMetrics(awsRequestMetrics);
                request.addHandlerContext(HandlerContextKey.CLIENT_ENDPOINT, endpoint);
                request.addHandlerContext(HandlerContextKey.ENDPOINT_OVERRIDDEN, isEndpointOverridden());
                request.addHandlerContext(HandlerContextKey.SIGNING_REGION, getSigningRegion());
                request.addHandlerContext(HandlerContextKey.SERVICE_ID, "Pca Connector Scep");
                request.addHandlerContext(HandlerContextKey.OPERATION_NAME, "CreateConnector");
                request.addHandlerContext(HandlerContextKey.ADVANCED_CONFIG, advancedConfig);

            } finally {
                awsRequestMetrics.endEvent(Field.RequestMarshallTime);
            }

            HttpResponseHandler<AmazonWebServiceResponse<CreateConnectorResult>> responseHandler = protocolFactory.createResponseHandler(
                    new JsonOperationMetadata().withPayloadJson(true).withHasStreamingSuccessResponse(false), new CreateConnectorResultJsonUnmarshaller());
            response = invoke(request, responseHandler, executionContext);

            return response.getAwsResponse();

        } finally {

            endClientExecution(awsRequestMetrics, request, response);
        }
    }

    /**
     * <p>
     * Deletes the specified <a
     * href="https://docs.aws.amazon.com/C4SCEP_API/pca-connector-scep/latest/APIReference/API_Challenge.html"
     * >Challenge</a>.
     * </p>
     * 
     * @param deleteChallengeRequest
     * @return Result of the DeleteChallenge operation returned by the service.
     * @throws ResourceNotFoundException
     *         The operation tried to access a nonexistent resource. The resource might be incorrectly specified, or it
     *         might have a status other than <code>ACTIVE</code>.
     * @throws InternalServerException
     *         The request processing has failed because of an unknown error, exception or failure with an internal
     *         server.
     * @throws ValidationException
     *         An input validation error occurred. For example, invalid characters in a name tag, or an invalid
     *         pagination token.
     * @throws ThrottlingException
     *         The limit on the number of requests per second was exceeded.
     * @throws AccessDeniedException
     *         You can receive this error if you attempt to perform an operation and you don't have the required
     *         permissions. This can be caused by insufficient permissions in policies attached to your Amazon Web
     *         Services Identity and Access Management (IAM) principal. It can also happen because of restrictions in
     *         place from an Amazon Web Services Organizations service control policy (SCP) that affects your Amazon Web
     *         Services account.
     * @throws ConflictException
     *         This request can't be completed for one of the following reasons because the requested resource was being
     *         concurrently modified by another request.
     * @sample AWSPcaConnectorScep.DeleteChallenge
     * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/pca-connector-scep-2018-05-10/DeleteChallenge"
     *      target="_top">AWS API Documentation</a>
     */
    @Override
    public DeleteChallengeResult deleteChallenge(DeleteChallengeRequest request) {
        request = beforeClientExecution(request);
        return executeDeleteChallenge(request);
    }

    @SdkInternalApi
    final DeleteChallengeResult executeDeleteChallenge(DeleteChallengeRequest deleteChallengeRequest) {

        ExecutionContext executionContext = createExecutionContext(deleteChallengeRequest);
        AWSRequestMetrics awsRequestMetrics = executionContext.getAwsRequestMetrics();
        awsRequestMetrics.startEvent(Field.ClientExecuteTime);
        Request<DeleteChallengeRequest> request = null;
        Response<DeleteChallengeResult> response = null;

        try {
            awsRequestMetrics.startEvent(Field.RequestMarshallTime);
            try {
                request = new DeleteChallengeRequestProtocolMarshaller(protocolFactory).marshall(super.beforeMarshalling(deleteChallengeRequest));
                // Binds the request metrics to the current request.
                request.setAWSRequestMetrics(awsRequestMetrics);
                request.addHandlerContext(HandlerContextKey.CLIENT_ENDPOINT, endpoint);
                request.addHandlerContext(HandlerContextKey.ENDPOINT_OVERRIDDEN, isEndpointOverridden());
                request.addHandlerContext(HandlerContextKey.SIGNING_REGION, getSigningRegion());
                request.addHandlerContext(HandlerContextKey.SERVICE_ID, "Pca Connector Scep");
                request.addHandlerContext(HandlerContextKey.OPERATION_NAME, "DeleteChallenge");
                request.addHandlerContext(HandlerContextKey.ADVANCED_CONFIG, advancedConfig);

            } finally {
                awsRequestMetrics.endEvent(Field.RequestMarshallTime);
            }

            HttpResponseHandler<AmazonWebServiceResponse<DeleteChallengeResult>> responseHandler = protocolFactory.createResponseHandler(
                    new JsonOperationMetadata().withPayloadJson(true).withHasStreamingSuccessResponse(false), new DeleteChallengeResultJsonUnmarshaller());
            response = invoke(request, responseHandler, executionContext);

            return response.getAwsResponse();

        } finally {

            endClientExecution(awsRequestMetrics, request, response);
        }
    }

    /**
     * <p>
     * Deletes the specified <a
     * href="https://docs.aws.amazon.com/C4SCEP_API/pca-connector-scep/latest/APIReference/API_Connector.html"
     * >Connector</a>. This operation also deletes any challenges associated with the connector.
     * </p>
     * 
     * @param deleteConnectorRequest
     * @return Result of the DeleteConnector operation returned by the service.
     * @throws ResourceNotFoundException
     *         The operation tried to access a nonexistent resource. The resource might be incorrectly specified, or it
     *         might have a status other than <code>ACTIVE</code>.
     * @throws InternalServerException
     *         The request processing has failed because of an unknown error, exception or failure with an internal
     *         server.
     * @throws ValidationException
     *         An input validation error occurred. For example, invalid characters in a name tag, or an invalid
     *         pagination token.
     * @throws ThrottlingException
     *         The limit on the number of requests per second was exceeded.
     * @throws AccessDeniedException
     *         You can receive this error if you attempt to perform an operation and you don't have the required
     *         permissions. This can be caused by insufficient permissions in policies attached to your Amazon Web
     *         Services Identity and Access Management (IAM) principal. It can also happen because of restrictions in
     *         place from an Amazon Web Services Organizations service control policy (SCP) that affects your Amazon Web
     *         Services account.
     * @throws ConflictException
     *         This request can't be completed for one of the following reasons because the requested resource was being
     *         concurrently modified by another request.
     * @sample AWSPcaConnectorScep.DeleteConnector
     * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/pca-connector-scep-2018-05-10/DeleteConnector"
     *      target="_top">AWS API Documentation</a>
     */
    @Override
    public DeleteConnectorResult deleteConnector(DeleteConnectorRequest request) {
        request = beforeClientExecution(request);
        return executeDeleteConnector(request);
    }

    @SdkInternalApi
    final DeleteConnectorResult executeDeleteConnector(DeleteConnectorRequest deleteConnectorRequest) {

        ExecutionContext executionContext = createExecutionContext(deleteConnectorRequest);
        AWSRequestMetrics awsRequestMetrics = executionContext.getAwsRequestMetrics();
        awsRequestMetrics.startEvent(Field.ClientExecuteTime);
        Request<DeleteConnectorRequest> request = null;
        Response<DeleteConnectorResult> response = null;

        try {
            awsRequestMetrics.startEvent(Field.RequestMarshallTime);
            try {
                request = new DeleteConnectorRequestProtocolMarshaller(protocolFactory).marshall(super.beforeMarshalling(deleteConnectorRequest));
                // Binds the request metrics to the current request.
                request.setAWSRequestMetrics(awsRequestMetrics);
                request.addHandlerContext(HandlerContextKey.CLIENT_ENDPOINT, endpoint);
                request.addHandlerContext(HandlerContextKey.ENDPOINT_OVERRIDDEN, isEndpointOverridden());
                request.addHandlerContext(HandlerContextKey.SIGNING_REGION, getSigningRegion());
                request.addHandlerContext(HandlerContextKey.SERVICE_ID, "Pca Connector Scep");
                request.addHandlerContext(HandlerContextKey.OPERATION_NAME, "DeleteConnector");
                request.addHandlerContext(HandlerContextKey.ADVANCED_CONFIG, advancedConfig);

            } finally {
                awsRequestMetrics.endEvent(Field.RequestMarshallTime);
            }

            HttpResponseHandler<AmazonWebServiceResponse<DeleteConnectorResult>> responseHandler = protocolFactory.createResponseHandler(
                    new JsonOperationMetadata().withPayloadJson(true).withHasStreamingSuccessResponse(false), new DeleteConnectorResultJsonUnmarshaller());
            response = invoke(request, responseHandler, executionContext);

            return response.getAwsResponse();

        } finally {

            endClientExecution(awsRequestMetrics, request, response);
        }
    }

    /**
     * <p>
     * Retrieves the metadata for the specified <a
     * href="https://docs.aws.amazon.com/C4SCEP_API/pca-connector-scep/latest/APIReference/API_Challenge.html"
     * >Challenge</a>.
     * </p>
     * 
     * @param getChallengeMetadataRequest
     * @return Result of the GetChallengeMetadata operation returned by the service.
     * @throws ResourceNotFoundException
     *         The operation tried to access a nonexistent resource. The resource might be incorrectly specified, or it
     *         might have a status other than <code>ACTIVE</code>.
     * @throws InternalServerException
     *         The request processing has failed because of an unknown error, exception or failure with an internal
     *         server.
     * @throws ValidationException
     *         An input validation error occurred. For example, invalid characters in a name tag, or an invalid
     *         pagination token.
     * @throws ThrottlingException
     *         The limit on the number of requests per second was exceeded.
     * @throws AccessDeniedException
     *         You can receive this error if you attempt to perform an operation and you don't have the required
     *         permissions. This can be caused by insufficient permissions in policies attached to your Amazon Web
     *         Services Identity and Access Management (IAM) principal. It can also happen because of restrictions in
     *         place from an Amazon Web Services Organizations service control policy (SCP) that affects your Amazon Web
     *         Services account.
     * @sample AWSPcaConnectorScep.GetChallengeMetadata
     * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/pca-connector-scep-2018-05-10/GetChallengeMetadata"
     *      target="_top">AWS API Documentation</a>
     */
    @Override
    public GetChallengeMetadataResult getChallengeMetadata(GetChallengeMetadataRequest request) {
        request = beforeClientExecution(request);
        return executeGetChallengeMetadata(request);
    }

    @SdkInternalApi
    final GetChallengeMetadataResult executeGetChallengeMetadata(GetChallengeMetadataRequest getChallengeMetadataRequest) {

        ExecutionContext executionContext = createExecutionContext(getChallengeMetadataRequest);
        AWSRequestMetrics awsRequestMetrics = executionContext.getAwsRequestMetrics();
        awsRequestMetrics.startEvent(Field.ClientExecuteTime);
        Request<GetChallengeMetadataRequest> request = null;
        Response<GetChallengeMetadataResult> response = null;

        try {
            awsRequestMetrics.startEvent(Field.RequestMarshallTime);
            try {
                request = new GetChallengeMetadataRequestProtocolMarshaller(protocolFactory).marshall(super.beforeMarshalling(getChallengeMetadataRequest));
                // Binds the request metrics to the current request.
                request.setAWSRequestMetrics(awsRequestMetrics);
                request.addHandlerContext(HandlerContextKey.CLIENT_ENDPOINT, endpoint);
                request.addHandlerContext(HandlerContextKey.ENDPOINT_OVERRIDDEN, isEndpointOverridden());
                request.addHandlerContext(HandlerContextKey.SIGNING_REGION, getSigningRegion());
                request.addHandlerContext(HandlerContextKey.SERVICE_ID, "Pca Connector Scep");
                request.addHandlerContext(HandlerContextKey.OPERATION_NAME, "GetChallengeMetadata");
                request.addHandlerContext(HandlerContextKey.ADVANCED_CONFIG, advancedConfig);

            } finally {
                awsRequestMetrics.endEvent(Field.RequestMarshallTime);
            }

            HttpResponseHandler<AmazonWebServiceResponse<GetChallengeMetadataResult>> responseHandler = protocolFactory.createResponseHandler(
                    new JsonOperationMetadata().withPayloadJson(true).withHasStreamingSuccessResponse(false), new GetChallengeMetadataResultJsonUnmarshaller());
            response = invoke(request, responseHandler, executionContext);

            return response.getAwsResponse();

        } finally {

            endClientExecution(awsRequestMetrics, request, response);
        }
    }

    /**
     * <p>
     * Retrieves the challenge password for the specified <a
     * href="https://docs.aws.amazon.com/C4SCEP_API/pca-connector-scep/latest/APIReference/API_Challenge.html"
     * >Challenge</a>.
     * </p>
     * 
     * @param getChallengePasswordRequest
     * @return Result of the GetChallengePassword operation returned by the service.
     * @throws ResourceNotFoundException
     *         The operation tried to access a nonexistent resource. The resource might be incorrectly specified, or it
     *         might have a status other than <code>ACTIVE</code>.
     * @throws InternalServerException
     *         The request processing has failed because of an unknown error, exception or failure with an internal
     *         server.
     * @throws ValidationException
     *         An input validation error occurred. For example, invalid characters in a name tag, or an invalid
     *         pagination token.
     * @throws ThrottlingException
     *         The limit on the number of requests per second was exceeded.
     * @throws AccessDeniedException
     *         You can receive this error if you attempt to perform an operation and you don't have the required
     *         permissions. This can be caused by insufficient permissions in policies attached to your Amazon Web
     *         Services Identity and Access Management (IAM) principal. It can also happen because of restrictions in
     *         place from an Amazon Web Services Organizations service control policy (SCP) that affects your Amazon Web
     *         Services account.
     * @sample AWSPcaConnectorScep.GetChallengePassword
     * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/pca-connector-scep-2018-05-10/GetChallengePassword"
     *      target="_top">AWS API Documentation</a>
     */
    @Override
    public GetChallengePasswordResult getChallengePassword(GetChallengePasswordRequest request) {
        request = beforeClientExecution(request);
        return executeGetChallengePassword(request);
    }

    @SdkInternalApi
    final GetChallengePasswordResult executeGetChallengePassword(GetChallengePasswordRequest getChallengePasswordRequest) {

        ExecutionContext executionContext = createExecutionContext(getChallengePasswordRequest);
        AWSRequestMetrics awsRequestMetrics = executionContext.getAwsRequestMetrics();
        awsRequestMetrics.startEvent(Field.ClientExecuteTime);
        Request<GetChallengePasswordRequest> request = null;
        Response<GetChallengePasswordResult> response = null;

        try {
            awsRequestMetrics.startEvent(Field.RequestMarshallTime);
            try {
                request = new GetChallengePasswordRequestProtocolMarshaller(protocolFactory).marshall(super.beforeMarshalling(getChallengePasswordRequest));
                // Binds the request metrics to the current request.
                request.setAWSRequestMetrics(awsRequestMetrics);
                request.addHandlerContext(HandlerContextKey.CLIENT_ENDPOINT, endpoint);
                request.addHandlerContext(HandlerContextKey.ENDPOINT_OVERRIDDEN, isEndpointOverridden());
                request.addHandlerContext(HandlerContextKey.SIGNING_REGION, getSigningRegion());
                request.addHandlerContext(HandlerContextKey.SERVICE_ID, "Pca Connector Scep");
                request.addHandlerContext(HandlerContextKey.OPERATION_NAME, "GetChallengePassword");
                request.addHandlerContext(HandlerContextKey.ADVANCED_CONFIG, advancedConfig);

            } finally {
                awsRequestMetrics.endEvent(Field.RequestMarshallTime);
            }

            HttpResponseHandler<AmazonWebServiceResponse<GetChallengePasswordResult>> responseHandler = protocolFactory.createResponseHandler(
                    new JsonOperationMetadata().withPayloadJson(true).withHasStreamingSuccessResponse(false), new GetChallengePasswordResultJsonUnmarshaller());
            response = invoke(request, responseHandler, executionContext);

            return response.getAwsResponse();

        } finally {

            endClientExecution(awsRequestMetrics, request, response);
        }
    }

    /**
     * <p>
     * Retrieves details about the specified <a
     * href="https://docs.aws.amazon.com/C4SCEP_API/pca-connector-scep/latest/APIReference/API_Connector.html"
     * >Connector</a>. Calling this action returns important details about the connector, such as the public SCEP URL
     * where your clients can request certificates.
     * </p>
     * 
     * @param getConnectorRequest
     * @return Result of the GetConnector operation returned by the service.
     * @throws ResourceNotFoundException
     *         The operation tried to access a nonexistent resource. The resource might be incorrectly specified, or it
     *         might have a status other than <code>ACTIVE</code>.
     * @throws InternalServerException
     *         The request processing has failed because of an unknown error, exception or failure with an internal
     *         server.
     * @throws ValidationException
     *         An input validation error occurred. For example, invalid characters in a name tag, or an invalid
     *         pagination token.
     * @throws ThrottlingException
     *         The limit on the number of requests per second was exceeded.
     * @throws AccessDeniedException
     *         You can receive this error if you attempt to perform an operation and you don't have the required
     *         permissions. This can be caused by insufficient permissions in policies attached to your Amazon Web
     *         Services Identity and Access Management (IAM) principal. It can also happen because of restrictions in
     *         place from an Amazon Web Services Organizations service control policy (SCP) that affects your Amazon Web
     *         Services account.
     * @sample AWSPcaConnectorScep.GetConnector
     * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/pca-connector-scep-2018-05-10/GetConnector"
     *      target="_top">AWS API Documentation</a>
     */
    @Override
    public GetConnectorResult getConnector(GetConnectorRequest request) {
        request = beforeClientExecution(request);
        return executeGetConnector(request);
    }

    @SdkInternalApi
    final GetConnectorResult executeGetConnector(GetConnectorRequest getConnectorRequest) {

        ExecutionContext executionContext = createExecutionContext(getConnectorRequest);
        AWSRequestMetrics awsRequestMetrics = executionContext.getAwsRequestMetrics();
        awsRequestMetrics.startEvent(Field.ClientExecuteTime);
        Request<GetConnectorRequest> request = null;
        Response<GetConnectorResult> response = null;

        try {
            awsRequestMetrics.startEvent(Field.RequestMarshallTime);
            try {
                request = new GetConnectorRequestProtocolMarshaller(protocolFactory).marshall(super.beforeMarshalling(getConnectorRequest));
                // Binds the request metrics to the current request.
                request.setAWSRequestMetrics(awsRequestMetrics);
                request.addHandlerContext(HandlerContextKey.CLIENT_ENDPOINT, endpoint);
                request.addHandlerContext(HandlerContextKey.ENDPOINT_OVERRIDDEN, isEndpointOverridden());
                request.addHandlerContext(HandlerContextKey.SIGNING_REGION, getSigningRegion());
                request.addHandlerContext(HandlerContextKey.SERVICE_ID, "Pca Connector Scep");
                request.addHandlerContext(HandlerContextKey.OPERATION_NAME, "GetConnector");
                request.addHandlerContext(HandlerContextKey.ADVANCED_CONFIG, advancedConfig);

            } finally {
                awsRequestMetrics.endEvent(Field.RequestMarshallTime);
            }

            HttpResponseHandler<AmazonWebServiceResponse<GetConnectorResult>> responseHandler = protocolFactory.createResponseHandler(
                    new JsonOperationMetadata().withPayloadJson(true).withHasStreamingSuccessResponse(false), new GetConnectorResultJsonUnmarshaller());
            response = invoke(request, responseHandler, executionContext);

            return response.getAwsResponse();

        } finally {

            endClientExecution(awsRequestMetrics, request, response);
        }
    }

    /**
     * <p>
     * Retrieves the challenge metadata for the specified ARN.
     * </p>
     * 
     * @param listChallengeMetadataRequest
     * @return Result of the ListChallengeMetadata operation returned by the service.
     * @throws ResourceNotFoundException
     *         The operation tried to access a nonexistent resource. The resource might be incorrectly specified, or it
     *         might have a status other than <code>ACTIVE</code>.
     * @throws InternalServerException
     *         The request processing has failed because of an unknown error, exception or failure with an internal
     *         server.
     * @throws ValidationException
     *         An input validation error occurred. For example, invalid characters in a name tag, or an invalid
     *         pagination token.
     * @throws ThrottlingException
     *         The limit on the number of requests per second was exceeded.
     * @throws AccessDeniedException
     *         You can receive this error if you attempt to perform an operation and you don't have the required
     *         permissions. This can be caused by insufficient permissions in policies attached to your Amazon Web
     *         Services Identity and Access Management (IAM) principal. It can also happen because of restrictions in
     *         place from an Amazon Web Services Organizations service control policy (SCP) that affects your Amazon Web
     *         Services account.
     * @sample AWSPcaConnectorScep.ListChallengeMetadata
     * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/pca-connector-scep-2018-05-10/ListChallengeMetadata"
     *      target="_top">AWS API Documentation</a>
     */
    @Override
    public ListChallengeMetadataResult listChallengeMetadata(ListChallengeMetadataRequest request) {
        request = beforeClientExecution(request);
        return executeListChallengeMetadata(request);
    }

    @SdkInternalApi
    final ListChallengeMetadataResult executeListChallengeMetadata(ListChallengeMetadataRequest listChallengeMetadataRequest) {

        ExecutionContext executionContext = createExecutionContext(listChallengeMetadataRequest);
        AWSRequestMetrics awsRequestMetrics = executionContext.getAwsRequestMetrics();
        awsRequestMetrics.startEvent(Field.ClientExecuteTime);
        Request<ListChallengeMetadataRequest> request = null;
        Response<ListChallengeMetadataResult> response = null;

        try {
            awsRequestMetrics.startEvent(Field.RequestMarshallTime);
            try {
                request = new ListChallengeMetadataRequestProtocolMarshaller(protocolFactory).marshall(super.beforeMarshalling(listChallengeMetadataRequest));
                // Binds the request metrics to the current request.
                request.setAWSRequestMetrics(awsRequestMetrics);
                request.addHandlerContext(HandlerContextKey.CLIENT_ENDPOINT, endpoint);
                request.addHandlerContext(HandlerContextKey.ENDPOINT_OVERRIDDEN, isEndpointOverridden());
                request.addHandlerContext(HandlerContextKey.SIGNING_REGION, getSigningRegion());
                request.addHandlerContext(HandlerContextKey.SERVICE_ID, "Pca Connector Scep");
                request.addHandlerContext(HandlerContextKey.OPERATION_NAME, "ListChallengeMetadata");
                request.addHandlerContext(HandlerContextKey.ADVANCED_CONFIG, advancedConfig);

            } finally {
                awsRequestMetrics.endEvent(Field.RequestMarshallTime);
            }

            HttpResponseHandler<AmazonWebServiceResponse<ListChallengeMetadataResult>> responseHandler = protocolFactory
                    .createResponseHandler(new JsonOperationMetadata().withPayloadJson(true).withHasStreamingSuccessResponse(false),
                            new ListChallengeMetadataResultJsonUnmarshaller());
            response = invoke(request, responseHandler, executionContext);

            return response.getAwsResponse();

        } finally {

            endClientExecution(awsRequestMetrics, request, response);
        }
    }

    /**
     * <p>
     * Lists the connectors belonging to your Amazon Web Services account.
     * </p>
     * 
     * @param listConnectorsRequest
     * @return Result of the ListConnectors operation returned by the service.
     * @throws InternalServerException
     *         The request processing has failed because of an unknown error, exception or failure with an internal
     *         server.
     * @throws ValidationException
     *         An input validation error occurred. For example, invalid characters in a name tag, or an invalid
     *         pagination token.
     * @throws ThrottlingException
     *         The limit on the number of requests per second was exceeded.
     * @throws AccessDeniedException
     *         You can receive this error if you attempt to perform an operation and you don't have the required
     *         permissions. This can be caused by insufficient permissions in policies attached to your Amazon Web
     *         Services Identity and Access Management (IAM) principal. It can also happen because of restrictions in
     *         place from an Amazon Web Services Organizations service control policy (SCP) that affects your Amazon Web
     *         Services account.
     * @sample AWSPcaConnectorScep.ListConnectors
     * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/pca-connector-scep-2018-05-10/ListConnectors"
     *      target="_top">AWS API Documentation</a>
     */
    @Override
    public ListConnectorsResult listConnectors(ListConnectorsRequest request) {
        request = beforeClientExecution(request);
        return executeListConnectors(request);
    }

    @SdkInternalApi
    final ListConnectorsResult executeListConnectors(ListConnectorsRequest listConnectorsRequest) {

        ExecutionContext executionContext = createExecutionContext(listConnectorsRequest);
        AWSRequestMetrics awsRequestMetrics = executionContext.getAwsRequestMetrics();
        awsRequestMetrics.startEvent(Field.ClientExecuteTime);
        Request<ListConnectorsRequest> request = null;
        Response<ListConnectorsResult> response = null;

        try {
            awsRequestMetrics.startEvent(Field.RequestMarshallTime);
            try {
                request = new ListConnectorsRequestProtocolMarshaller(protocolFactory).marshall(super.beforeMarshalling(listConnectorsRequest));
                // Binds the request metrics to the current request.
                request.setAWSRequestMetrics(awsRequestMetrics);
                request.addHandlerContext(HandlerContextKey.CLIENT_ENDPOINT, endpoint);
                request.addHandlerContext(HandlerContextKey.ENDPOINT_OVERRIDDEN, isEndpointOverridden());
                request.addHandlerContext(HandlerContextKey.SIGNING_REGION, getSigningRegion());
                request.addHandlerContext(HandlerContextKey.SERVICE_ID, "Pca Connector Scep");
                request.addHandlerContext(HandlerContextKey.OPERATION_NAME, "ListConnectors");
                request.addHandlerContext(HandlerContextKey.ADVANCED_CONFIG, advancedConfig);

            } finally {
                awsRequestMetrics.endEvent(Field.RequestMarshallTime);
            }

            HttpResponseHandler<AmazonWebServiceResponse<ListConnectorsResult>> responseHandler = protocolFactory.createResponseHandler(
                    new JsonOperationMetadata().withPayloadJson(true).withHasStreamingSuccessResponse(false), new ListConnectorsResultJsonUnmarshaller());
            response = invoke(request, responseHandler, executionContext);

            return response.getAwsResponse();

        } finally {

            endClientExecution(awsRequestMetrics, request, response);
        }
    }

    /**
     * <p>
     * Retrieves the tags associated with the specified resource. Tags are key-value pairs that you can use to
     * categorize and manage your resources, for purposes like billing. For example, you might set the tag key to
     * "customer" and the value to the customer name or ID. You can specify one or more tags to add to each Amazon Web
     * Services resource, up to 50 tags for a resource.
     * </p>
     * 
     * @param listTagsForResourceRequest
     * @return Result of the ListTagsForResource operation returned by the service.
     * @throws ResourceNotFoundException
     *         The operation tried to access a nonexistent resource. The resource might be incorrectly specified, or it
     *         might have a status other than <code>ACTIVE</code>.
     * @throws InternalServerException
     *         The request processing has failed because of an unknown error, exception or failure with an internal
     *         server.
     * @throws ValidationException
     *         An input validation error occurred. For example, invalid characters in a name tag, or an invalid
     *         pagination token.
     * @throws ThrottlingException
     *         The limit on the number of requests per second was exceeded.
     * @throws AccessDeniedException
     *         You can receive this error if you attempt to perform an operation and you don't have the required
     *         permissions. This can be caused by insufficient permissions in policies attached to your Amazon Web
     *         Services Identity and Access Management (IAM) principal. It can also happen because of restrictions in
     *         place from an Amazon Web Services Organizations service control policy (SCP) that affects your Amazon Web
     *         Services account.
     * @sample AWSPcaConnectorScep.ListTagsForResource
     * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/pca-connector-scep-2018-05-10/ListTagsForResource"
     *      target="_top">AWS API Documentation</a>
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
                request.addHandlerContext(HandlerContextKey.SERVICE_ID, "Pca Connector Scep");
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
     * Adds one or more tags to your resource.
     * </p>
     * 
     * @param tagResourceRequest
     * @return Result of the TagResource operation returned by the service.
     * @throws ResourceNotFoundException
     *         The operation tried to access a nonexistent resource. The resource might be incorrectly specified, or it
     *         might have a status other than <code>ACTIVE</code>.
     * @throws InternalServerException
     *         The request processing has failed because of an unknown error, exception or failure with an internal
     *         server.
     * @throws ValidationException
     *         An input validation error occurred. For example, invalid characters in a name tag, or an invalid
     *         pagination token.
     * @throws ThrottlingException
     *         The limit on the number of requests per second was exceeded.
     * @throws AccessDeniedException
     *         You can receive this error if you attempt to perform an operation and you don't have the required
     *         permissions. This can be caused by insufficient permissions in policies attached to your Amazon Web
     *         Services Identity and Access Management (IAM) principal. It can also happen because of restrictions in
     *         place from an Amazon Web Services Organizations service control policy (SCP) that affects your Amazon Web
     *         Services account.
     * @sample AWSPcaConnectorScep.TagResource
     * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/pca-connector-scep-2018-05-10/TagResource" target="_top">AWS
     *      API Documentation</a>
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
                request.addHandlerContext(HandlerContextKey.SERVICE_ID, "Pca Connector Scep");
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
     * Removes one or more tags from your resource.
     * </p>
     * 
     * @param untagResourceRequest
     * @return Result of the UntagResource operation returned by the service.
     * @throws ResourceNotFoundException
     *         The operation tried to access a nonexistent resource. The resource might be incorrectly specified, or it
     *         might have a status other than <code>ACTIVE</code>.
     * @throws InternalServerException
     *         The request processing has failed because of an unknown error, exception or failure with an internal
     *         server.
     * @throws ValidationException
     *         An input validation error occurred. For example, invalid characters in a name tag, or an invalid
     *         pagination token.
     * @throws ThrottlingException
     *         The limit on the number of requests per second was exceeded.
     * @throws AccessDeniedException
     *         You can receive this error if you attempt to perform an operation and you don't have the required
     *         permissions. This can be caused by insufficient permissions in policies attached to your Amazon Web
     *         Services Identity and Access Management (IAM) principal. It can also happen because of restrictions in
     *         place from an Amazon Web Services Organizations service control policy (SCP) that affects your Amazon Web
     *         Services account.
     * @sample AWSPcaConnectorScep.UntagResource
     * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/pca-connector-scep-2018-05-10/UntagResource"
     *      target="_top">AWS API Documentation</a>
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
                request.addHandlerContext(HandlerContextKey.SERVICE_ID, "Pca Connector Scep");
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
