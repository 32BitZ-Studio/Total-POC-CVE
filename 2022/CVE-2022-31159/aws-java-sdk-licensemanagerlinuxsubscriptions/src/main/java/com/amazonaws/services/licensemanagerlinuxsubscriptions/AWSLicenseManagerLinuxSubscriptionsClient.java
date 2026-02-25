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
package com.amazonaws.services.licensemanagerlinuxsubscriptions;

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

import com.amazonaws.services.licensemanagerlinuxsubscriptions.AWSLicenseManagerLinuxSubscriptionsClientBuilder;

import com.amazonaws.AmazonServiceException;

import com.amazonaws.services.licensemanagerlinuxsubscriptions.model.*;

import com.amazonaws.services.licensemanagerlinuxsubscriptions.model.transform.*;

/**
 * Client for accessing AWS License Manager Linux Subscriptions. All service calls made using this client are blocking,
 * and will not return until the service call completes.
 * <p>
 * <p>
 * With License Manager, you can discover and track your commercial Linux subscriptions on running Amazon EC2 instances.
 * </p>
 */
@ThreadSafe
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class AWSLicenseManagerLinuxSubscriptionsClient extends AmazonWebServiceClient implements AWSLicenseManagerLinuxSubscriptions {

    /** Provider for AWS credentials. */
    private final AWSCredentialsProvider awsCredentialsProvider;

    private static final Log log = LogFactory.getLog(AWSLicenseManagerLinuxSubscriptions.class);

    /** Default signing name for the service. */
    private static final String DEFAULT_SIGNING_NAME = "license-manager-linux-subscriptions";

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
                            new JsonErrorShapeMetadata().withErrorCode("ValidationException").withExceptionUnmarshaller(
                                    com.amazonaws.services.licensemanagerlinuxsubscriptions.model.transform.ValidationExceptionUnmarshaller.getInstance()))
                    .addErrorMetadata(
                            new JsonErrorShapeMetadata().withErrorCode("ResourceNotFoundException")
                                    .withExceptionUnmarshaller(
                                            com.amazonaws.services.licensemanagerlinuxsubscriptions.model.transform.ResourceNotFoundExceptionUnmarshaller
                                                    .getInstance()))
                    .addErrorMetadata(
                            new JsonErrorShapeMetadata().withErrorCode("InternalServerException").withExceptionUnmarshaller(
                                    com.amazonaws.services.licensemanagerlinuxsubscriptions.model.transform.InternalServerExceptionUnmarshaller.getInstance()))
                    .addErrorMetadata(
                            new JsonErrorShapeMetadata().withErrorCode("ThrottlingException").withExceptionUnmarshaller(
                                    com.amazonaws.services.licensemanagerlinuxsubscriptions.model.transform.ThrottlingExceptionUnmarshaller.getInstance()))
                    .withBaseServiceExceptionClass(
                            com.amazonaws.services.licensemanagerlinuxsubscriptions.model.AWSLicenseManagerLinuxSubscriptionsException.class));

    public static AWSLicenseManagerLinuxSubscriptionsClientBuilder builder() {
        return AWSLicenseManagerLinuxSubscriptionsClientBuilder.standard();
    }

    /**
     * Constructs a new client to invoke service methods on AWS License Manager Linux Subscriptions using the specified
     * parameters.
     *
     * <p>
     * All service calls made using this new client object are blocking, and will not return until the service call
     * completes.
     *
     * @param clientParams
     *        Object providing client parameters.
     */
    AWSLicenseManagerLinuxSubscriptionsClient(AwsSyncClientParams clientParams) {
        this(clientParams, false);
    }

    /**
     * Constructs a new client to invoke service methods on AWS License Manager Linux Subscriptions using the specified
     * parameters.
     *
     * <p>
     * All service calls made using this new client object are blocking, and will not return until the service call
     * completes.
     *
     * @param clientParams
     *        Object providing client parameters.
     */
    AWSLicenseManagerLinuxSubscriptionsClient(AwsSyncClientParams clientParams, boolean endpointDiscoveryEnabled) {
        super(clientParams);
        this.awsCredentialsProvider = clientParams.getCredentialsProvider();
        this.advancedConfig = clientParams.getAdvancedConfig();
        init();
    }

    private void init() {
        setServiceNameIntern(DEFAULT_SIGNING_NAME);
        setEndpointPrefix(ENDPOINT_PREFIX);
        // calling this.setEndPoint(...) will also modify the signer accordingly
        setEndpoint("license-manager-linux-subscriptions.us-east-1.amazonaws.com");
        HandlerChainFactory chainFactory = new HandlerChainFactory();
        requestHandler2s.addAll(chainFactory.newRequestHandlerChain("/com/amazonaws/services/licensemanagerlinuxsubscriptions/request.handlers"));
        requestHandler2s.addAll(chainFactory.newRequestHandler2Chain("/com/amazonaws/services/licensemanagerlinuxsubscriptions/request.handler2s"));
        requestHandler2s.addAll(chainFactory.getGlobalHandlers());
    }

    /**
     * <p>
     * Remove a third-party subscription provider from the Bring Your Own License (BYOL) subscriptions registered to
     * your account.
     * </p>
     * 
     * @param deregisterSubscriptionProviderRequest
     * @return Result of the DeregisterSubscriptionProvider operation returned by the service.
     * @throws InternalServerException
     *         An exception occurred with the service.
     * @throws ResourceNotFoundException
     *         Unable to find the requested Amazon Web Services resource.
     * @throws ThrottlingException
     *         The request was denied due to request throttling.
     * @throws ValidationException
     *         The provided input is not valid. Try your request again.
     * @sample AWSLicenseManagerLinuxSubscriptions.DeregisterSubscriptionProvider
     * @see <a
     *      href="http://docs.aws.amazon.com/goto/WebAPI/license-manager-linux-subscriptions-2018-05-10/DeregisterSubscriptionProvider"
     *      target="_top">AWS API Documentation</a>
     */
    @Override
    public DeregisterSubscriptionProviderResult deregisterSubscriptionProvider(DeregisterSubscriptionProviderRequest request) {
        request = beforeClientExecution(request);
        return executeDeregisterSubscriptionProvider(request);
    }

    @SdkInternalApi
    final DeregisterSubscriptionProviderResult executeDeregisterSubscriptionProvider(DeregisterSubscriptionProviderRequest deregisterSubscriptionProviderRequest) {

        ExecutionContext executionContext = createExecutionContext(deregisterSubscriptionProviderRequest);
        AWSRequestMetrics awsRequestMetrics = executionContext.getAwsRequestMetrics();
        awsRequestMetrics.startEvent(Field.ClientExecuteTime);
        Request<DeregisterSubscriptionProviderRequest> request = null;
        Response<DeregisterSubscriptionProviderResult> response = null;

        try {
            awsRequestMetrics.startEvent(Field.RequestMarshallTime);
            try {
                request = new DeregisterSubscriptionProviderRequestProtocolMarshaller(protocolFactory).marshall(super
                        .beforeMarshalling(deregisterSubscriptionProviderRequest));
                // Binds the request metrics to the current request.
                request.setAWSRequestMetrics(awsRequestMetrics);
                request.addHandlerContext(HandlerContextKey.CLIENT_ENDPOINT, endpoint);
                request.addHandlerContext(HandlerContextKey.ENDPOINT_OVERRIDDEN, isEndpointOverridden());
                request.addHandlerContext(HandlerContextKey.SIGNING_REGION, getSigningRegion());
                request.addHandlerContext(HandlerContextKey.SERVICE_ID, "License Manager Linux Subscriptions");
                request.addHandlerContext(HandlerContextKey.OPERATION_NAME, "DeregisterSubscriptionProvider");
                request.addHandlerContext(HandlerContextKey.ADVANCED_CONFIG, advancedConfig);

            } finally {
                awsRequestMetrics.endEvent(Field.RequestMarshallTime);
            }

            HttpResponseHandler<AmazonWebServiceResponse<DeregisterSubscriptionProviderResult>> responseHandler = protocolFactory.createResponseHandler(
                    new JsonOperationMetadata().withPayloadJson(true).withHasStreamingSuccessResponse(false),
                    new DeregisterSubscriptionProviderResultJsonUnmarshaller());
            response = invoke(request, responseHandler, executionContext);

            return response.getAwsResponse();

        } finally {

            endClientExecution(awsRequestMetrics, request, response);
        }
    }

    /**
     * <p>
     * Get details for a Bring Your Own License (BYOL) subscription that's registered to your account.
     * </p>
     * 
     * @param getRegisteredSubscriptionProviderRequest
     * @return Result of the GetRegisteredSubscriptionProvider operation returned by the service.
     * @throws InternalServerException
     *         An exception occurred with the service.
     * @throws ResourceNotFoundException
     *         Unable to find the requested Amazon Web Services resource.
     * @throws ThrottlingException
     *         The request was denied due to request throttling.
     * @throws ValidationException
     *         The provided input is not valid. Try your request again.
     * @sample AWSLicenseManagerLinuxSubscriptions.GetRegisteredSubscriptionProvider
     * @see <a
     *      href="http://docs.aws.amazon.com/goto/WebAPI/license-manager-linux-subscriptions-2018-05-10/GetRegisteredSubscriptionProvider"
     *      target="_top">AWS API Documentation</a>
     */
    @Override
    public GetRegisteredSubscriptionProviderResult getRegisteredSubscriptionProvider(GetRegisteredSubscriptionProviderRequest request) {
        request = beforeClientExecution(request);
        return executeGetRegisteredSubscriptionProvider(request);
    }

    @SdkInternalApi
    final GetRegisteredSubscriptionProviderResult executeGetRegisteredSubscriptionProvider(
            GetRegisteredSubscriptionProviderRequest getRegisteredSubscriptionProviderRequest) {

        ExecutionContext executionContext = createExecutionContext(getRegisteredSubscriptionProviderRequest);
        AWSRequestMetrics awsRequestMetrics = executionContext.getAwsRequestMetrics();
        awsRequestMetrics.startEvent(Field.ClientExecuteTime);
        Request<GetRegisteredSubscriptionProviderRequest> request = null;
        Response<GetRegisteredSubscriptionProviderResult> response = null;

        try {
            awsRequestMetrics.startEvent(Field.RequestMarshallTime);
            try {
                request = new GetRegisteredSubscriptionProviderRequestProtocolMarshaller(protocolFactory).marshall(super
                        .beforeMarshalling(getRegisteredSubscriptionProviderRequest));
                // Binds the request metrics to the current request.
                request.setAWSRequestMetrics(awsRequestMetrics);
                request.addHandlerContext(HandlerContextKey.CLIENT_ENDPOINT, endpoint);
                request.addHandlerContext(HandlerContextKey.ENDPOINT_OVERRIDDEN, isEndpointOverridden());
                request.addHandlerContext(HandlerContextKey.SIGNING_REGION, getSigningRegion());
                request.addHandlerContext(HandlerContextKey.SERVICE_ID, "License Manager Linux Subscriptions");
                request.addHandlerContext(HandlerContextKey.OPERATION_NAME, "GetRegisteredSubscriptionProvider");
                request.addHandlerContext(HandlerContextKey.ADVANCED_CONFIG, advancedConfig);

            } finally {
                awsRequestMetrics.endEvent(Field.RequestMarshallTime);
            }

            HttpResponseHandler<AmazonWebServiceResponse<GetRegisteredSubscriptionProviderResult>> responseHandler = protocolFactory.createResponseHandler(
                    new JsonOperationMetadata().withPayloadJson(true).withHasStreamingSuccessResponse(false),
                    new GetRegisteredSubscriptionProviderResultJsonUnmarshaller());
            response = invoke(request, responseHandler, executionContext);

            return response.getAwsResponse();

        } finally {

            endClientExecution(awsRequestMetrics, request, response);
        }
    }

    /**
     * <p>
     * Lists the Linux subscriptions service settings for your account.
     * </p>
     * 
     * @param getServiceSettingsRequest
     * @return Result of the GetServiceSettings operation returned by the service.
     * @throws InternalServerException
     *         An exception occurred with the service.
     * @throws ThrottlingException
     *         The request was denied due to request throttling.
     * @throws ValidationException
     *         The provided input is not valid. Try your request again.
     * @sample AWSLicenseManagerLinuxSubscriptions.GetServiceSettings
     * @see <a
     *      href="http://docs.aws.amazon.com/goto/WebAPI/license-manager-linux-subscriptions-2018-05-10/GetServiceSettings"
     *      target="_top">AWS API Documentation</a>
     */
    @Override
    public GetServiceSettingsResult getServiceSettings(GetServiceSettingsRequest request) {
        request = beforeClientExecution(request);
        return executeGetServiceSettings(request);
    }

    @SdkInternalApi
    final GetServiceSettingsResult executeGetServiceSettings(GetServiceSettingsRequest getServiceSettingsRequest) {

        ExecutionContext executionContext = createExecutionContext(getServiceSettingsRequest);
        AWSRequestMetrics awsRequestMetrics = executionContext.getAwsRequestMetrics();
        awsRequestMetrics.startEvent(Field.ClientExecuteTime);
        Request<GetServiceSettingsRequest> request = null;
        Response<GetServiceSettingsResult> response = null;

        try {
            awsRequestMetrics.startEvent(Field.RequestMarshallTime);
            try {
                request = new GetServiceSettingsRequestProtocolMarshaller(protocolFactory).marshall(super.beforeMarshalling(getServiceSettingsRequest));
                // Binds the request metrics to the current request.
                request.setAWSRequestMetrics(awsRequestMetrics);
                request.addHandlerContext(HandlerContextKey.CLIENT_ENDPOINT, endpoint);
                request.addHandlerContext(HandlerContextKey.ENDPOINT_OVERRIDDEN, isEndpointOverridden());
                request.addHandlerContext(HandlerContextKey.SIGNING_REGION, getSigningRegion());
                request.addHandlerContext(HandlerContextKey.SERVICE_ID, "License Manager Linux Subscriptions");
                request.addHandlerContext(HandlerContextKey.OPERATION_NAME, "GetServiceSettings");
                request.addHandlerContext(HandlerContextKey.ADVANCED_CONFIG, advancedConfig);

            } finally {
                awsRequestMetrics.endEvent(Field.RequestMarshallTime);
            }

            HttpResponseHandler<AmazonWebServiceResponse<GetServiceSettingsResult>> responseHandler = protocolFactory.createResponseHandler(
                    new JsonOperationMetadata().withPayloadJson(true).withHasStreamingSuccessResponse(false), new GetServiceSettingsResultJsonUnmarshaller());
            response = invoke(request, responseHandler, executionContext);

            return response.getAwsResponse();

        } finally {

            endClientExecution(awsRequestMetrics, request, response);
        }
    }

    /**
     * <p>
     * Lists the running Amazon EC2 instances that were discovered with commercial Linux subscriptions.
     * </p>
     * 
     * @param listLinuxSubscriptionInstancesRequest
     *        NextToken length limit is half of ddb accepted limit. Increase this limit if parameters in request
     *        increases.
     * @return Result of the ListLinuxSubscriptionInstances operation returned by the service.
     * @throws InternalServerException
     *         An exception occurred with the service.
     * @throws ThrottlingException
     *         The request was denied due to request throttling.
     * @throws ValidationException
     *         The provided input is not valid. Try your request again.
     * @sample AWSLicenseManagerLinuxSubscriptions.ListLinuxSubscriptionInstances
     * @see <a
     *      href="http://docs.aws.amazon.com/goto/WebAPI/license-manager-linux-subscriptions-2018-05-10/ListLinuxSubscriptionInstances"
     *      target="_top">AWS API Documentation</a>
     */
    @Override
    public ListLinuxSubscriptionInstancesResult listLinuxSubscriptionInstances(ListLinuxSubscriptionInstancesRequest request) {
        request = beforeClientExecution(request);
        return executeListLinuxSubscriptionInstances(request);
    }

    @SdkInternalApi
    final ListLinuxSubscriptionInstancesResult executeListLinuxSubscriptionInstances(ListLinuxSubscriptionInstancesRequest listLinuxSubscriptionInstancesRequest) {

        ExecutionContext executionContext = createExecutionContext(listLinuxSubscriptionInstancesRequest);
        AWSRequestMetrics awsRequestMetrics = executionContext.getAwsRequestMetrics();
        awsRequestMetrics.startEvent(Field.ClientExecuteTime);
        Request<ListLinuxSubscriptionInstancesRequest> request = null;
        Response<ListLinuxSubscriptionInstancesResult> response = null;

        try {
            awsRequestMetrics.startEvent(Field.RequestMarshallTime);
            try {
                request = new ListLinuxSubscriptionInstancesRequestProtocolMarshaller(protocolFactory).marshall(super
                        .beforeMarshalling(listLinuxSubscriptionInstancesRequest));
                // Binds the request metrics to the current request.
                request.setAWSRequestMetrics(awsRequestMetrics);
                request.addHandlerContext(HandlerContextKey.CLIENT_ENDPOINT, endpoint);
                request.addHandlerContext(HandlerContextKey.ENDPOINT_OVERRIDDEN, isEndpointOverridden());
                request.addHandlerContext(HandlerContextKey.SIGNING_REGION, getSigningRegion());
                request.addHandlerContext(HandlerContextKey.SERVICE_ID, "License Manager Linux Subscriptions");
                request.addHandlerContext(HandlerContextKey.OPERATION_NAME, "ListLinuxSubscriptionInstances");
                request.addHandlerContext(HandlerContextKey.ADVANCED_CONFIG, advancedConfig);

            } finally {
                awsRequestMetrics.endEvent(Field.RequestMarshallTime);
            }

            HttpResponseHandler<AmazonWebServiceResponse<ListLinuxSubscriptionInstancesResult>> responseHandler = protocolFactory.createResponseHandler(
                    new JsonOperationMetadata().withPayloadJson(true).withHasStreamingSuccessResponse(false),
                    new ListLinuxSubscriptionInstancesResultJsonUnmarshaller());
            response = invoke(request, responseHandler, executionContext);

            return response.getAwsResponse();

        } finally {

            endClientExecution(awsRequestMetrics, request, response);
        }
    }

    /**
     * <p>
     * Lists the Linux subscriptions that have been discovered. If you have linked your organization, the returned
     * results will include data aggregated across your accounts in Organizations.
     * </p>
     * 
     * @param listLinuxSubscriptionsRequest
     *        NextToken length limit is half of ddb accepted limit. Increase this limit if parameters in request
     *        increases.
     * @return Result of the ListLinuxSubscriptions operation returned by the service.
     * @throws InternalServerException
     *         An exception occurred with the service.
     * @throws ThrottlingException
     *         The request was denied due to request throttling.
     * @throws ValidationException
     *         The provided input is not valid. Try your request again.
     * @sample AWSLicenseManagerLinuxSubscriptions.ListLinuxSubscriptions
     * @see <a
     *      href="http://docs.aws.amazon.com/goto/WebAPI/license-manager-linux-subscriptions-2018-05-10/ListLinuxSubscriptions"
     *      target="_top">AWS API Documentation</a>
     */
    @Override
    public ListLinuxSubscriptionsResult listLinuxSubscriptions(ListLinuxSubscriptionsRequest request) {
        request = beforeClientExecution(request);
        return executeListLinuxSubscriptions(request);
    }

    @SdkInternalApi
    final ListLinuxSubscriptionsResult executeListLinuxSubscriptions(ListLinuxSubscriptionsRequest listLinuxSubscriptionsRequest) {

        ExecutionContext executionContext = createExecutionContext(listLinuxSubscriptionsRequest);
        AWSRequestMetrics awsRequestMetrics = executionContext.getAwsRequestMetrics();
        awsRequestMetrics.startEvent(Field.ClientExecuteTime);
        Request<ListLinuxSubscriptionsRequest> request = null;
        Response<ListLinuxSubscriptionsResult> response = null;

        try {
            awsRequestMetrics.startEvent(Field.RequestMarshallTime);
            try {
                request = new ListLinuxSubscriptionsRequestProtocolMarshaller(protocolFactory).marshall(super.beforeMarshalling(listLinuxSubscriptionsRequest));
                // Binds the request metrics to the current request.
                request.setAWSRequestMetrics(awsRequestMetrics);
                request.addHandlerContext(HandlerContextKey.CLIENT_ENDPOINT, endpoint);
                request.addHandlerContext(HandlerContextKey.ENDPOINT_OVERRIDDEN, isEndpointOverridden());
                request.addHandlerContext(HandlerContextKey.SIGNING_REGION, getSigningRegion());
                request.addHandlerContext(HandlerContextKey.SERVICE_ID, "License Manager Linux Subscriptions");
                request.addHandlerContext(HandlerContextKey.OPERATION_NAME, "ListLinuxSubscriptions");
                request.addHandlerContext(HandlerContextKey.ADVANCED_CONFIG, advancedConfig);

            } finally {
                awsRequestMetrics.endEvent(Field.RequestMarshallTime);
            }

            HttpResponseHandler<AmazonWebServiceResponse<ListLinuxSubscriptionsResult>> responseHandler = protocolFactory.createResponseHandler(
                    new JsonOperationMetadata().withPayloadJson(true).withHasStreamingSuccessResponse(false),
                    new ListLinuxSubscriptionsResultJsonUnmarshaller());
            response = invoke(request, responseHandler, executionContext);

            return response.getAwsResponse();

        } finally {

            endClientExecution(awsRequestMetrics, request, response);
        }
    }

    /**
     * <p>
     * List Bring Your Own License (BYOL) subscription registration resources for your account.
     * </p>
     * 
     * @param listRegisteredSubscriptionProvidersRequest
     * @return Result of the ListRegisteredSubscriptionProviders operation returned by the service.
     * @throws InternalServerException
     *         An exception occurred with the service.
     * @throws ThrottlingException
     *         The request was denied due to request throttling.
     * @throws ValidationException
     *         The provided input is not valid. Try your request again.
     * @sample AWSLicenseManagerLinuxSubscriptions.ListRegisteredSubscriptionProviders
     * @see <a
     *      href="http://docs.aws.amazon.com/goto/WebAPI/license-manager-linux-subscriptions-2018-05-10/ListRegisteredSubscriptionProviders"
     *      target="_top">AWS API Documentation</a>
     */
    @Override
    public ListRegisteredSubscriptionProvidersResult listRegisteredSubscriptionProviders(ListRegisteredSubscriptionProvidersRequest request) {
        request = beforeClientExecution(request);
        return executeListRegisteredSubscriptionProviders(request);
    }

    @SdkInternalApi
    final ListRegisteredSubscriptionProvidersResult executeListRegisteredSubscriptionProviders(
            ListRegisteredSubscriptionProvidersRequest listRegisteredSubscriptionProvidersRequest) {

        ExecutionContext executionContext = createExecutionContext(listRegisteredSubscriptionProvidersRequest);
        AWSRequestMetrics awsRequestMetrics = executionContext.getAwsRequestMetrics();
        awsRequestMetrics.startEvent(Field.ClientExecuteTime);
        Request<ListRegisteredSubscriptionProvidersRequest> request = null;
        Response<ListRegisteredSubscriptionProvidersResult> response = null;

        try {
            awsRequestMetrics.startEvent(Field.RequestMarshallTime);
            try {
                request = new ListRegisteredSubscriptionProvidersRequestProtocolMarshaller(protocolFactory).marshall(super
                        .beforeMarshalling(listRegisteredSubscriptionProvidersRequest));
                // Binds the request metrics to the current request.
                request.setAWSRequestMetrics(awsRequestMetrics);
                request.addHandlerContext(HandlerContextKey.CLIENT_ENDPOINT, endpoint);
                request.addHandlerContext(HandlerContextKey.ENDPOINT_OVERRIDDEN, isEndpointOverridden());
                request.addHandlerContext(HandlerContextKey.SIGNING_REGION, getSigningRegion());
                request.addHandlerContext(HandlerContextKey.SERVICE_ID, "License Manager Linux Subscriptions");
                request.addHandlerContext(HandlerContextKey.OPERATION_NAME, "ListRegisteredSubscriptionProviders");
                request.addHandlerContext(HandlerContextKey.ADVANCED_CONFIG, advancedConfig);

            } finally {
                awsRequestMetrics.endEvent(Field.RequestMarshallTime);
            }

            HttpResponseHandler<AmazonWebServiceResponse<ListRegisteredSubscriptionProvidersResult>> responseHandler = protocolFactory.createResponseHandler(
                    new JsonOperationMetadata().withPayloadJson(true).withHasStreamingSuccessResponse(false),
                    new ListRegisteredSubscriptionProvidersResultJsonUnmarshaller());
            response = invoke(request, responseHandler, executionContext);

            return response.getAwsResponse();

        } finally {

            endClientExecution(awsRequestMetrics, request, response);
        }
    }

    /**
     * <p>
     * List the metadata tags that are assigned to the specified Amazon Web Services resource.
     * </p>
     * 
     * @param listTagsForResourceRequest
     * @return Result of the ListTagsForResource operation returned by the service.
     * @throws InternalServerException
     *         An exception occurred with the service.
     * @throws ResourceNotFoundException
     *         Unable to find the requested Amazon Web Services resource.
     * @throws ValidationException
     *         The provided input is not valid. Try your request again.
     * @sample AWSLicenseManagerLinuxSubscriptions.ListTagsForResource
     * @see <a
     *      href="http://docs.aws.amazon.com/goto/WebAPI/license-manager-linux-subscriptions-2018-05-10/ListTagsForResource"
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
                request.addHandlerContext(HandlerContextKey.SERVICE_ID, "License Manager Linux Subscriptions");
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
     * Register the supported third-party subscription provider for your Bring Your Own License (BYOL) subscription.
     * </p>
     * 
     * @param registerSubscriptionProviderRequest
     * @return Result of the RegisterSubscriptionProvider operation returned by the service.
     * @throws InternalServerException
     *         An exception occurred with the service.
     * @throws ThrottlingException
     *         The request was denied due to request throttling.
     * @throws ValidationException
     *         The provided input is not valid. Try your request again.
     * @sample AWSLicenseManagerLinuxSubscriptions.RegisterSubscriptionProvider
     * @see <a
     *      href="http://docs.aws.amazon.com/goto/WebAPI/license-manager-linux-subscriptions-2018-05-10/RegisterSubscriptionProvider"
     *      target="_top">AWS API Documentation</a>
     */
    @Override
    public RegisterSubscriptionProviderResult registerSubscriptionProvider(RegisterSubscriptionProviderRequest request) {
        request = beforeClientExecution(request);
        return executeRegisterSubscriptionProvider(request);
    }

    @SdkInternalApi
    final RegisterSubscriptionProviderResult executeRegisterSubscriptionProvider(RegisterSubscriptionProviderRequest registerSubscriptionProviderRequest) {

        ExecutionContext executionContext = createExecutionContext(registerSubscriptionProviderRequest);
        AWSRequestMetrics awsRequestMetrics = executionContext.getAwsRequestMetrics();
        awsRequestMetrics.startEvent(Field.ClientExecuteTime);
        Request<RegisterSubscriptionProviderRequest> request = null;
        Response<RegisterSubscriptionProviderResult> response = null;

        try {
            awsRequestMetrics.startEvent(Field.RequestMarshallTime);
            try {
                request = new RegisterSubscriptionProviderRequestProtocolMarshaller(protocolFactory).marshall(super
                        .beforeMarshalling(registerSubscriptionProviderRequest));
                // Binds the request metrics to the current request.
                request.setAWSRequestMetrics(awsRequestMetrics);
                request.addHandlerContext(HandlerContextKey.CLIENT_ENDPOINT, endpoint);
                request.addHandlerContext(HandlerContextKey.ENDPOINT_OVERRIDDEN, isEndpointOverridden());
                request.addHandlerContext(HandlerContextKey.SIGNING_REGION, getSigningRegion());
                request.addHandlerContext(HandlerContextKey.SERVICE_ID, "License Manager Linux Subscriptions");
                request.addHandlerContext(HandlerContextKey.OPERATION_NAME, "RegisterSubscriptionProvider");
                request.addHandlerContext(HandlerContextKey.ADVANCED_CONFIG, advancedConfig);

            } finally {
                awsRequestMetrics.endEvent(Field.RequestMarshallTime);
            }

            HttpResponseHandler<AmazonWebServiceResponse<RegisterSubscriptionProviderResult>> responseHandler = protocolFactory.createResponseHandler(
                    new JsonOperationMetadata().withPayloadJson(true).withHasStreamingSuccessResponse(false),
                    new RegisterSubscriptionProviderResultJsonUnmarshaller());
            response = invoke(request, responseHandler, executionContext);

            return response.getAwsResponse();

        } finally {

            endClientExecution(awsRequestMetrics, request, response);
        }
    }

    /**
     * <p>
     * Add metadata tags to the specified Amazon Web Services resource.
     * </p>
     * 
     * @param tagResourceRequest
     * @return Result of the TagResource operation returned by the service.
     * @throws InternalServerException
     *         An exception occurred with the service.
     * @throws ResourceNotFoundException
     *         Unable to find the requested Amazon Web Services resource.
     * @throws ValidationException
     *         The provided input is not valid. Try your request again.
     * @sample AWSLicenseManagerLinuxSubscriptions.TagResource
     * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/license-manager-linux-subscriptions-2018-05-10/TagResource"
     *      target="_top">AWS API Documentation</a>
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
                request.addHandlerContext(HandlerContextKey.SERVICE_ID, "License Manager Linux Subscriptions");
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
     * Remove one or more metadata tag from the specified Amazon Web Services resource.
     * </p>
     * 
     * @param untagResourceRequest
     * @return Result of the UntagResource operation returned by the service.
     * @throws InternalServerException
     *         An exception occurred with the service.
     * @throws ResourceNotFoundException
     *         Unable to find the requested Amazon Web Services resource.
     * @sample AWSLicenseManagerLinuxSubscriptions.UntagResource
     * @see <a
     *      href="http://docs.aws.amazon.com/goto/WebAPI/license-manager-linux-subscriptions-2018-05-10/UntagResource"
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
                request.addHandlerContext(HandlerContextKey.SERVICE_ID, "License Manager Linux Subscriptions");
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
     * Updates the service settings for Linux subscriptions.
     * </p>
     * 
     * @param updateServiceSettingsRequest
     * @return Result of the UpdateServiceSettings operation returned by the service.
     * @throws InternalServerException
     *         An exception occurred with the service.
     * @throws ThrottlingException
     *         The request was denied due to request throttling.
     * @throws ValidationException
     *         The provided input is not valid. Try your request again.
     * @sample AWSLicenseManagerLinuxSubscriptions.UpdateServiceSettings
     * @see <a
     *      href="http://docs.aws.amazon.com/goto/WebAPI/license-manager-linux-subscriptions-2018-05-10/UpdateServiceSettings"
     *      target="_top">AWS API Documentation</a>
     */
    @Override
    public UpdateServiceSettingsResult updateServiceSettings(UpdateServiceSettingsRequest request) {
        request = beforeClientExecution(request);
        return executeUpdateServiceSettings(request);
    }

    @SdkInternalApi
    final UpdateServiceSettingsResult executeUpdateServiceSettings(UpdateServiceSettingsRequest updateServiceSettingsRequest) {

        ExecutionContext executionContext = createExecutionContext(updateServiceSettingsRequest);
        AWSRequestMetrics awsRequestMetrics = executionContext.getAwsRequestMetrics();
        awsRequestMetrics.startEvent(Field.ClientExecuteTime);
        Request<UpdateServiceSettingsRequest> request = null;
        Response<UpdateServiceSettingsResult> response = null;

        try {
            awsRequestMetrics.startEvent(Field.RequestMarshallTime);
            try {
                request = new UpdateServiceSettingsRequestProtocolMarshaller(protocolFactory).marshall(super.beforeMarshalling(updateServiceSettingsRequest));
                // Binds the request metrics to the current request.
                request.setAWSRequestMetrics(awsRequestMetrics);
                request.addHandlerContext(HandlerContextKey.CLIENT_ENDPOINT, endpoint);
                request.addHandlerContext(HandlerContextKey.ENDPOINT_OVERRIDDEN, isEndpointOverridden());
                request.addHandlerContext(HandlerContextKey.SIGNING_REGION, getSigningRegion());
                request.addHandlerContext(HandlerContextKey.SERVICE_ID, "License Manager Linux Subscriptions");
                request.addHandlerContext(HandlerContextKey.OPERATION_NAME, "UpdateServiceSettings");
                request.addHandlerContext(HandlerContextKey.ADVANCED_CONFIG, advancedConfig);

            } finally {
                awsRequestMetrics.endEvent(Field.RequestMarshallTime);
            }

            HttpResponseHandler<AmazonWebServiceResponse<UpdateServiceSettingsResult>> responseHandler = protocolFactory
                    .createResponseHandler(new JsonOperationMetadata().withPayloadJson(true).withHasStreamingSuccessResponse(false),
                            new UpdateServiceSettingsResultJsonUnmarshaller());
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
