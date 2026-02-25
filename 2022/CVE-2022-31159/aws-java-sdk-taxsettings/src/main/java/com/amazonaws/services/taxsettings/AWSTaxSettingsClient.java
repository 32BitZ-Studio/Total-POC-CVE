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

import com.amazonaws.services.taxsettings.AWSTaxSettingsClientBuilder;

import com.amazonaws.AmazonServiceException;

import com.amazonaws.services.taxsettings.model.*;

import com.amazonaws.services.taxsettings.model.transform.*;

/**
 * Client for accessing Tax Settings. All service calls made using this client are blocking, and will not return until
 * the service call completes.
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
public class AWSTaxSettingsClient extends AmazonWebServiceClient implements AWSTaxSettings {

    /** Provider for AWS credentials. */
    private final AWSCredentialsProvider awsCredentialsProvider;

    private static final Log log = LogFactory.getLog(AWSTaxSettings.class);

    /** Default signing name for the service. */
    private static final String DEFAULT_SIGNING_NAME = "tax";

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
                            new JsonErrorShapeMetadata().withErrorCode("ConflictException").withExceptionUnmarshaller(
                                    com.amazonaws.services.taxsettings.model.transform.ConflictExceptionUnmarshaller.getInstance()))
                    .addErrorMetadata(
                            new JsonErrorShapeMetadata().withErrorCode("ResourceNotFoundException").withExceptionUnmarshaller(
                                    com.amazonaws.services.taxsettings.model.transform.ResourceNotFoundExceptionUnmarshaller.getInstance()))
                    .addErrorMetadata(
                            new JsonErrorShapeMetadata().withErrorCode("ValidationException").withExceptionUnmarshaller(
                                    com.amazonaws.services.taxsettings.model.transform.ValidationExceptionUnmarshaller.getInstance()))
                    .addErrorMetadata(
                            new JsonErrorShapeMetadata().withErrorCode("InternalServerException").withExceptionUnmarshaller(
                                    com.amazonaws.services.taxsettings.model.transform.InternalServerExceptionUnmarshaller.getInstance()))
                    .withBaseServiceExceptionClass(com.amazonaws.services.taxsettings.model.AWSTaxSettingsException.class));

    public static AWSTaxSettingsClientBuilder builder() {
        return AWSTaxSettingsClientBuilder.standard();
    }

    /**
     * Constructs a new client to invoke service methods on Tax Settings using the specified parameters.
     *
     * <p>
     * All service calls made using this new client object are blocking, and will not return until the service call
     * completes.
     *
     * @param clientParams
     *        Object providing client parameters.
     */
    AWSTaxSettingsClient(AwsSyncClientParams clientParams) {
        this(clientParams, false);
    }

    /**
     * Constructs a new client to invoke service methods on Tax Settings using the specified parameters.
     *
     * <p>
     * All service calls made using this new client object are blocking, and will not return until the service call
     * completes.
     *
     * @param clientParams
     *        Object providing client parameters.
     */
    AWSTaxSettingsClient(AwsSyncClientParams clientParams, boolean endpointDiscoveryEnabled) {
        super(clientParams);
        this.awsCredentialsProvider = clientParams.getCredentialsProvider();
        this.advancedConfig = clientParams.getAdvancedConfig();
        init();
    }

    private void init() {
        setServiceNameIntern(DEFAULT_SIGNING_NAME);
        setEndpointPrefix(ENDPOINT_PREFIX);
        // calling this.setEndPoint(...) will also modify the signer accordingly
        setEndpoint("tax.us-east-1.amazonaws.com");
        HandlerChainFactory chainFactory = new HandlerChainFactory();
        requestHandler2s.addAll(chainFactory.newRequestHandlerChain("/com/amazonaws/services/taxsettings/request.handlers"));
        requestHandler2s.addAll(chainFactory.newRequestHandler2Chain("/com/amazonaws/services/taxsettings/request.handler2s"));
        requestHandler2s.addAll(chainFactory.getGlobalHandlers());
    }

    /**
     * <p>
     * Deletes tax registration for multiple accounts in batch. This can be used to delete tax registrations for up to
     * five accounts in one batch.
     * </p>
     * <note>
     * <p>
     * This API operation can't be used to delete your tax registration in Brazil. Use the <a
     * href="https://console.aws.amazon.com/billing/home#/paymentpreferences/paymentmethods">Payment preferences</a>
     * page in the Billing and Cost Management console instead.
     * </p>
     * </note>
     * 
     * @param batchDeleteTaxRegistrationRequest
     * @return Result of the BatchDeleteTaxRegistration operation returned by the service.
     * @throws ValidationException
     *         The exception when the input doesn't pass validation for at least one of the input parameters.
     * @throws ConflictException
     *         The exception when the input is creating conflict with the given state.
     * @throws InternalServerException
     *         The exception thrown when an unexpected error occurs when processing a request.
     * @sample AWSTaxSettings.BatchDeleteTaxRegistration
     * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/taxsettings-2018-05-10/BatchDeleteTaxRegistration"
     *      target="_top">AWS API Documentation</a>
     */
    @Override
    public BatchDeleteTaxRegistrationResult batchDeleteTaxRegistration(BatchDeleteTaxRegistrationRequest request) {
        request = beforeClientExecution(request);
        return executeBatchDeleteTaxRegistration(request);
    }

    @SdkInternalApi
    final BatchDeleteTaxRegistrationResult executeBatchDeleteTaxRegistration(BatchDeleteTaxRegistrationRequest batchDeleteTaxRegistrationRequest) {

        ExecutionContext executionContext = createExecutionContext(batchDeleteTaxRegistrationRequest);
        AWSRequestMetrics awsRequestMetrics = executionContext.getAwsRequestMetrics();
        awsRequestMetrics.startEvent(Field.ClientExecuteTime);
        Request<BatchDeleteTaxRegistrationRequest> request = null;
        Response<BatchDeleteTaxRegistrationResult> response = null;

        try {
            awsRequestMetrics.startEvent(Field.RequestMarshallTime);
            try {
                request = new BatchDeleteTaxRegistrationRequestProtocolMarshaller(protocolFactory).marshall(super
                        .beforeMarshalling(batchDeleteTaxRegistrationRequest));
                // Binds the request metrics to the current request.
                request.setAWSRequestMetrics(awsRequestMetrics);
                request.addHandlerContext(HandlerContextKey.CLIENT_ENDPOINT, endpoint);
                request.addHandlerContext(HandlerContextKey.ENDPOINT_OVERRIDDEN, isEndpointOverridden());
                request.addHandlerContext(HandlerContextKey.SIGNING_REGION, getSigningRegion());
                request.addHandlerContext(HandlerContextKey.SERVICE_ID, "TaxSettings");
                request.addHandlerContext(HandlerContextKey.OPERATION_NAME, "BatchDeleteTaxRegistration");
                request.addHandlerContext(HandlerContextKey.ADVANCED_CONFIG, advancedConfig);

            } finally {
                awsRequestMetrics.endEvent(Field.RequestMarshallTime);
            }

            HttpResponseHandler<AmazonWebServiceResponse<BatchDeleteTaxRegistrationResult>> responseHandler = protocolFactory.createResponseHandler(
                    new JsonOperationMetadata().withPayloadJson(true).withHasStreamingSuccessResponse(false),
                    new BatchDeleteTaxRegistrationResultJsonUnmarshaller());
            response = invoke(request, responseHandler, executionContext);

            return response.getAwsResponse();

        } finally {

            endClientExecution(awsRequestMetrics, request, response);
        }
    }

    /**
     * <p>
     * Adds or updates tax registration for multiple accounts in batch. This can be used to add or update tax
     * registrations for up to five accounts in one batch. You can't set a TRN if there's a pending TRN. You'll need to
     * delete the pending TRN first.
     * </p>
     * <p>
     * To call this API operation for specific countries, see the following country-specific requirements.
     * </p>
     * <p>
     * <b>Bangladesh</b>
     * </p>
     * <ul>
     * <li>
     * <p>
     * You must specify the tax registration certificate document in the <code>taxRegistrationDocuments</code> field of
     * the <code>VerificationDetails</code> object.
     * </p>
     * </li>
     * </ul>
     * <p>
     * <b>Brazil</b>
     * </p>
     * <ul>
     * <li>
     * <p>
     * You must complete the tax registration process in the <a
     * href="https://console.aws.amazon.com/billing/home#/paymentpreferences/paymentmethods">Payment preferences</a>
     * page in the Billing and Cost Management console. After your TRN and billing address are verified, you can call
     * this API operation.
     * </p>
     * </li>
     * <li>
     * <p>
     * For Amazon Web Services accounts created through Organizations, you can call this API operation when you don't
     * have a billing address.
     * </p>
     * </li>
     * </ul>
     * <p>
     * <b>Georgia</b>
     * </p>
     * <ul>
     * <li>
     * <p>
     * The valid <code>personType</code> values are <code>Physical Person</code> and <code>Business</code>.
     * </p>
     * </li>
     * </ul>
     * <p>
     * <b>Kenya</b>
     * </p>
     * <ul>
     * <li>
     * <p>
     * You must specify the <code>personType</code> in the <code>kenyaAdditionalInfo</code> field of the
     * <code>additionalTaxInformation</code> object.
     * </p>
     * </li>
     * <li>
     * <p>
     * If the <code>personType</code> is <code>Physical Person</code>, you must specify the tax registration certificate
     * document in the <code>taxRegistrationDocuments</code> field of the <code>VerificationDetails</code> object.
     * </p>
     * </li>
     * </ul>
     * <p>
     * <b>Malaysia</b>
     * </p>
     * <ul>
     * <li>
     * <p>
     * If you use this operation to set a tax registration number (TRN) in Malaysia, only resellers with a valid sales
     * and service tax (SST) number are required to provide tax registration information.
     * </p>
     * </li>
     * <li>
     * <p>
     * By using this API operation to set a TRN in Malaysia, Amazon Web Services will regard you as self-declaring that
     * you're an authorized business reseller registered with the Royal Malaysia Customs Department (RMCD) and have a
     * valid SST number.
     * </p>
     * </li>
     * <li>
     * <p>
     * Amazon Web Services reserves the right to seek additional information and/or take other actions to support your
     * self-declaration as appropriate.
     * </p>
     * </li>
     * <li>
     * <p>
     * If you're not a reseller of Amazon Web Services, we don't recommend that you use this operation to set the TRN in
     * Malaysia.
     * </p>
     * </li>
     * <li>
     * <p>
     * Only use this API operation to upload the TRNs for accounts through which you're reselling Amazon Web Services.
     * </p>
     * </li>
     * <li>
     * <p>
     * Amazon Web Services is currently registered under the following service tax codes. You must include at least one
     * of the service tax codes in the service tax code strings to declare yourself as an authorized registered business
     * reseller.
     * </p>
     * <p>
     * Taxable service and service tax codes:
     * </p>
     * <p>
     * Consultancy - 9907061674
     * </p>
     * <p>
     * Training or coaching service - 9907071685
     * </p>
     * <p>
     * IT service - 9907101676
     * </p>
     * <p>
     * Digital services and electronic medium - 9907121690
     * </p>
     * </li>
     * </ul>
     * <p>
     * <b>Nepal</b>
     * </p>
     * <ul>
     * <li>
     * <p>
     * The sector valid values are <code>Business</code> and <code>Individual</code>.
     * </p>
     * </li>
     * </ul>
     * <p>
     * <b>Saudi Arabia</b>
     * </p>
     * <ul>
     * <li>
     * <p>
     * For <code>address</code>, you must specify <code>addressLine3</code>.
     * </p>
     * </li>
     * </ul>
     * <p>
     * <b>South Korea</b>
     * </p>
     * <ul>
     * <li>
     * <p>
     * You must specify the <code>certifiedEmailId</code> and <code>legalName</code> in the
     * <code>TaxRegistrationEntry</code> object. Use Korean characters for <code>legalName</code>.
     * </p>
     * </li>
     * <li>
     * <p>
     * You must specify the <code>businessRepresentativeName</code>, <code>itemOfBusiness</code>, and
     * <code>lineOfBusiness</code> in the <code>southKoreaAdditionalInfo</code> field of the
     * <code>additionalTaxInformation</code> object. Use Korean characters for these fields.
     * </p>
     * </li>
     * <li>
     * <p>
     * You must specify the tax registration certificate document in the <code>taxRegistrationDocuments</code> field of
     * the <code>VerificationDetails</code> object.
     * </p>
     * </li>
     * <li>
     * <p>
     * For the <code>address</code> object, use Korean characters for <code>addressLine1</code>,
     * <code>addressLine2</code> <code>city</code>, <code>postalCode</code>, and <code>stateOrRegion</code>.
     * </p>
     * </li>
     * </ul>
     * <p>
     * <b>Spain</b>
     * </p>
     * <ul>
     * <li>
     * <p>
     * You must specify the <code>registrationType</code> in the <code>spainAdditionalInfo</code> field of the
     * <code>additionalTaxInformation</code> object.
     * </p>
     * </li>
     * <li>
     * <p>
     * If the <code>registrationType</code> is <code>Local</code>, you must specify the tax registration certificate
     * document in the <code>taxRegistrationDocuments</code> field of the <code>VerificationDetails</code> object.
     * </p>
     * </li>
     * </ul>
     * <p>
     * <b>Turkey</b>
     * </p>
     * <ul>
     * <li>
     * <p>
     * You must specify the <code>sector</code> in the <code>taxRegistrationEntry</code> object.
     * </p>
     * </li>
     * <li>
     * <p>
     * If your <code>sector</code> is <code>Business</code>, <code>Individual</code>, or <code>Government</code>:
     * </p>
     * <ul>
     * <li>
     * <p>
     * Specify the <code>taxOffice</code>. If your <code>sector</code> is <code>Individual</code>, don't enter this
     * value.
     * </p>
     * </li>
     * <li>
     * <p>
     * (Optional) Specify the <code>kepEmailId</code>. If your <code>sector</code> is <code>Individual</code>, don't
     * enter this value.
     * </p>
     * </li>
     * <li>
     * <p>
     * <b>Note:</b> In the <b>Tax Settings</b> page of the Billing console, <code>Government</code> appears as <b>Public
     * institutions</b>
     * </p>
     * </li>
     * </ul>
     * </li>
     * <li>
     * <p>
     * If your <code>sector</code> is <code>Business</code> and you're subject to KDV tax, you must specify your
     * industry in the <code>industries</code> field.
     * </p>
     * </li>
     * <li>
     * <p>
     * For <code>address</code>, you must specify <code>districtOrCounty</code>.
     * </p>
     * </li>
     * </ul>
     * <p>
     * <b>Ukraine</b>
     * </p>
     * <ul>
     * <li>
     * <p>
     * The sector valid values are <code>Business</code> and <code>Individual</code>.
     * </p>
     * </li>
     * </ul>
     * 
     * @param batchPutTaxRegistrationRequest
     * @return Result of the BatchPutTaxRegistration operation returned by the service.
     * @throws ValidationException
     *         The exception when the input doesn't pass validation for at least one of the input parameters.
     * @throws ConflictException
     *         The exception when the input is creating conflict with the given state.
     * @throws InternalServerException
     *         The exception thrown when an unexpected error occurs when processing a request.
     * @sample AWSTaxSettings.BatchPutTaxRegistration
     * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/taxsettings-2018-05-10/BatchPutTaxRegistration"
     *      target="_top">AWS API Documentation</a>
     */
    @Override
    public BatchPutTaxRegistrationResult batchPutTaxRegistration(BatchPutTaxRegistrationRequest request) {
        request = beforeClientExecution(request);
        return executeBatchPutTaxRegistration(request);
    }

    @SdkInternalApi
    final BatchPutTaxRegistrationResult executeBatchPutTaxRegistration(BatchPutTaxRegistrationRequest batchPutTaxRegistrationRequest) {

        ExecutionContext executionContext = createExecutionContext(batchPutTaxRegistrationRequest);
        AWSRequestMetrics awsRequestMetrics = executionContext.getAwsRequestMetrics();
        awsRequestMetrics.startEvent(Field.ClientExecuteTime);
        Request<BatchPutTaxRegistrationRequest> request = null;
        Response<BatchPutTaxRegistrationResult> response = null;

        try {
            awsRequestMetrics.startEvent(Field.RequestMarshallTime);
            try {
                request = new BatchPutTaxRegistrationRequestProtocolMarshaller(protocolFactory).marshall(super
                        .beforeMarshalling(batchPutTaxRegistrationRequest));
                // Binds the request metrics to the current request.
                request.setAWSRequestMetrics(awsRequestMetrics);
                request.addHandlerContext(HandlerContextKey.CLIENT_ENDPOINT, endpoint);
                request.addHandlerContext(HandlerContextKey.ENDPOINT_OVERRIDDEN, isEndpointOverridden());
                request.addHandlerContext(HandlerContextKey.SIGNING_REGION, getSigningRegion());
                request.addHandlerContext(HandlerContextKey.SERVICE_ID, "TaxSettings");
                request.addHandlerContext(HandlerContextKey.OPERATION_NAME, "BatchPutTaxRegistration");
                request.addHandlerContext(HandlerContextKey.ADVANCED_CONFIG, advancedConfig);

            } finally {
                awsRequestMetrics.endEvent(Field.RequestMarshallTime);
            }

            HttpResponseHandler<AmazonWebServiceResponse<BatchPutTaxRegistrationResult>> responseHandler = protocolFactory.createResponseHandler(
                    new JsonOperationMetadata().withPayloadJson(true).withHasStreamingSuccessResponse(false),
                    new BatchPutTaxRegistrationResultJsonUnmarshaller());
            response = invoke(request, responseHandler, executionContext);

            return response.getAwsResponse();

        } finally {

            endClientExecution(awsRequestMetrics, request, response);
        }
    }

    /**
     * <p>
     * Deletes tax registration for a single account.
     * </p>
     * <note>
     * <p>
     * This API operation can't be used to delete your tax registration in Brazil. Use the <a
     * href="https://console.aws.amazon.com/billing/home#/paymentpreferences/paymentmethods">Payment preferences</a>
     * page in the Billing and Cost Management console instead.
     * </p>
     * </note>
     * 
     * @param deleteTaxRegistrationRequest
     * @return Result of the DeleteTaxRegistration operation returned by the service.
     * @throws ValidationException
     *         The exception when the input doesn't pass validation for at least one of the input parameters.
     * @throws ConflictException
     *         The exception when the input is creating conflict with the given state.
     * @throws ResourceNotFoundException
     *         The exception thrown when the input doesn't have a resource associated to it.
     * @throws InternalServerException
     *         The exception thrown when an unexpected error occurs when processing a request.
     * @sample AWSTaxSettings.DeleteTaxRegistration
     * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/taxsettings-2018-05-10/DeleteTaxRegistration"
     *      target="_top">AWS API Documentation</a>
     */
    @Override
    public DeleteTaxRegistrationResult deleteTaxRegistration(DeleteTaxRegistrationRequest request) {
        request = beforeClientExecution(request);
        return executeDeleteTaxRegistration(request);
    }

    @SdkInternalApi
    final DeleteTaxRegistrationResult executeDeleteTaxRegistration(DeleteTaxRegistrationRequest deleteTaxRegistrationRequest) {

        ExecutionContext executionContext = createExecutionContext(deleteTaxRegistrationRequest);
        AWSRequestMetrics awsRequestMetrics = executionContext.getAwsRequestMetrics();
        awsRequestMetrics.startEvent(Field.ClientExecuteTime);
        Request<DeleteTaxRegistrationRequest> request = null;
        Response<DeleteTaxRegistrationResult> response = null;

        try {
            awsRequestMetrics.startEvent(Field.RequestMarshallTime);
            try {
                request = new DeleteTaxRegistrationRequestProtocolMarshaller(protocolFactory).marshall(super.beforeMarshalling(deleteTaxRegistrationRequest));
                // Binds the request metrics to the current request.
                request.setAWSRequestMetrics(awsRequestMetrics);
                request.addHandlerContext(HandlerContextKey.CLIENT_ENDPOINT, endpoint);
                request.addHandlerContext(HandlerContextKey.ENDPOINT_OVERRIDDEN, isEndpointOverridden());
                request.addHandlerContext(HandlerContextKey.SIGNING_REGION, getSigningRegion());
                request.addHandlerContext(HandlerContextKey.SERVICE_ID, "TaxSettings");
                request.addHandlerContext(HandlerContextKey.OPERATION_NAME, "DeleteTaxRegistration");
                request.addHandlerContext(HandlerContextKey.ADVANCED_CONFIG, advancedConfig);

            } finally {
                awsRequestMetrics.endEvent(Field.RequestMarshallTime);
            }

            HttpResponseHandler<AmazonWebServiceResponse<DeleteTaxRegistrationResult>> responseHandler = protocolFactory
                    .createResponseHandler(new JsonOperationMetadata().withPayloadJson(true).withHasStreamingSuccessResponse(false),
                            new DeleteTaxRegistrationResultJsonUnmarshaller());
            response = invoke(request, responseHandler, executionContext);

            return response.getAwsResponse();

        } finally {

            endClientExecution(awsRequestMetrics, request, response);
        }
    }

    /**
     * <p>
     * Retrieves tax registration for a single account.
     * </p>
     * 
     * @param getTaxRegistrationRequest
     * @return Result of the GetTaxRegistration operation returned by the service.
     * @throws ValidationException
     *         The exception when the input doesn't pass validation for at least one of the input parameters.
     * @throws ResourceNotFoundException
     *         The exception thrown when the input doesn't have a resource associated to it.
     * @throws InternalServerException
     *         The exception thrown when an unexpected error occurs when processing a request.
     * @sample AWSTaxSettings.GetTaxRegistration
     * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/taxsettings-2018-05-10/GetTaxRegistration" target="_top">AWS
     *      API Documentation</a>
     */
    @Override
    public GetTaxRegistrationResult getTaxRegistration(GetTaxRegistrationRequest request) {
        request = beforeClientExecution(request);
        return executeGetTaxRegistration(request);
    }

    @SdkInternalApi
    final GetTaxRegistrationResult executeGetTaxRegistration(GetTaxRegistrationRequest getTaxRegistrationRequest) {

        ExecutionContext executionContext = createExecutionContext(getTaxRegistrationRequest);
        AWSRequestMetrics awsRequestMetrics = executionContext.getAwsRequestMetrics();
        awsRequestMetrics.startEvent(Field.ClientExecuteTime);
        Request<GetTaxRegistrationRequest> request = null;
        Response<GetTaxRegistrationResult> response = null;

        try {
            awsRequestMetrics.startEvent(Field.RequestMarshallTime);
            try {
                request = new GetTaxRegistrationRequestProtocolMarshaller(protocolFactory).marshall(super.beforeMarshalling(getTaxRegistrationRequest));
                // Binds the request metrics to the current request.
                request.setAWSRequestMetrics(awsRequestMetrics);
                request.addHandlerContext(HandlerContextKey.CLIENT_ENDPOINT, endpoint);
                request.addHandlerContext(HandlerContextKey.ENDPOINT_OVERRIDDEN, isEndpointOverridden());
                request.addHandlerContext(HandlerContextKey.SIGNING_REGION, getSigningRegion());
                request.addHandlerContext(HandlerContextKey.SERVICE_ID, "TaxSettings");
                request.addHandlerContext(HandlerContextKey.OPERATION_NAME, "GetTaxRegistration");
                request.addHandlerContext(HandlerContextKey.ADVANCED_CONFIG, advancedConfig);

            } finally {
                awsRequestMetrics.endEvent(Field.RequestMarshallTime);
            }

            HttpResponseHandler<AmazonWebServiceResponse<GetTaxRegistrationResult>> responseHandler = protocolFactory.createResponseHandler(
                    new JsonOperationMetadata().withPayloadJson(true).withHasStreamingSuccessResponse(false), new GetTaxRegistrationResultJsonUnmarshaller());
            response = invoke(request, responseHandler, executionContext);

            return response.getAwsResponse();

        } finally {

            endClientExecution(awsRequestMetrics, request, response);
        }
    }

    /**
     * <p>
     * Downloads your tax documents to the Amazon S3 bucket that you specify in your request.
     * </p>
     * 
     * @param getTaxRegistrationDocumentRequest
     * @return Result of the GetTaxRegistrationDocument operation returned by the service.
     * @throws ValidationException
     *         The exception when the input doesn't pass validation for at least one of the input parameters.
     * @throws InternalServerException
     *         The exception thrown when an unexpected error occurs when processing a request.
     * @sample AWSTaxSettings.GetTaxRegistrationDocument
     * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/taxsettings-2018-05-10/GetTaxRegistrationDocument"
     *      target="_top">AWS API Documentation</a>
     */
    @Override
    public GetTaxRegistrationDocumentResult getTaxRegistrationDocument(GetTaxRegistrationDocumentRequest request) {
        request = beforeClientExecution(request);
        return executeGetTaxRegistrationDocument(request);
    }

    @SdkInternalApi
    final GetTaxRegistrationDocumentResult executeGetTaxRegistrationDocument(GetTaxRegistrationDocumentRequest getTaxRegistrationDocumentRequest) {

        ExecutionContext executionContext = createExecutionContext(getTaxRegistrationDocumentRequest);
        AWSRequestMetrics awsRequestMetrics = executionContext.getAwsRequestMetrics();
        awsRequestMetrics.startEvent(Field.ClientExecuteTime);
        Request<GetTaxRegistrationDocumentRequest> request = null;
        Response<GetTaxRegistrationDocumentResult> response = null;

        try {
            awsRequestMetrics.startEvent(Field.RequestMarshallTime);
            try {
                request = new GetTaxRegistrationDocumentRequestProtocolMarshaller(protocolFactory).marshall(super
                        .beforeMarshalling(getTaxRegistrationDocumentRequest));
                // Binds the request metrics to the current request.
                request.setAWSRequestMetrics(awsRequestMetrics);
                request.addHandlerContext(HandlerContextKey.CLIENT_ENDPOINT, endpoint);
                request.addHandlerContext(HandlerContextKey.ENDPOINT_OVERRIDDEN, isEndpointOverridden());
                request.addHandlerContext(HandlerContextKey.SIGNING_REGION, getSigningRegion());
                request.addHandlerContext(HandlerContextKey.SERVICE_ID, "TaxSettings");
                request.addHandlerContext(HandlerContextKey.OPERATION_NAME, "GetTaxRegistrationDocument");
                request.addHandlerContext(HandlerContextKey.ADVANCED_CONFIG, advancedConfig);

            } finally {
                awsRequestMetrics.endEvent(Field.RequestMarshallTime);
            }

            HttpResponseHandler<AmazonWebServiceResponse<GetTaxRegistrationDocumentResult>> responseHandler = protocolFactory.createResponseHandler(
                    new JsonOperationMetadata().withPayloadJson(true).withHasStreamingSuccessResponse(false),
                    new GetTaxRegistrationDocumentResultJsonUnmarshaller());
            response = invoke(request, responseHandler, executionContext);

            return response.getAwsResponse();

        } finally {

            endClientExecution(awsRequestMetrics, request, response);
        }
    }

    /**
     * <p>
     * Retrieves the tax registration of accounts listed in a consolidated billing family. This can be used to retrieve
     * up to 100 accounts' tax registrations in one call (default 50).
     * </p>
     * 
     * @param listTaxRegistrationsRequest
     * @return Result of the ListTaxRegistrations operation returned by the service.
     * @throws ValidationException
     *         The exception when the input doesn't pass validation for at least one of the input parameters.
     * @throws ResourceNotFoundException
     *         The exception thrown when the input doesn't have a resource associated to it.
     * @throws InternalServerException
     *         The exception thrown when an unexpected error occurs when processing a request.
     * @sample AWSTaxSettings.ListTaxRegistrations
     * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/taxsettings-2018-05-10/ListTaxRegistrations"
     *      target="_top">AWS API Documentation</a>
     */
    @Override
    public ListTaxRegistrationsResult listTaxRegistrations(ListTaxRegistrationsRequest request) {
        request = beforeClientExecution(request);
        return executeListTaxRegistrations(request);
    }

    @SdkInternalApi
    final ListTaxRegistrationsResult executeListTaxRegistrations(ListTaxRegistrationsRequest listTaxRegistrationsRequest) {

        ExecutionContext executionContext = createExecutionContext(listTaxRegistrationsRequest);
        AWSRequestMetrics awsRequestMetrics = executionContext.getAwsRequestMetrics();
        awsRequestMetrics.startEvent(Field.ClientExecuteTime);
        Request<ListTaxRegistrationsRequest> request = null;
        Response<ListTaxRegistrationsResult> response = null;

        try {
            awsRequestMetrics.startEvent(Field.RequestMarshallTime);
            try {
                request = new ListTaxRegistrationsRequestProtocolMarshaller(protocolFactory).marshall(super.beforeMarshalling(listTaxRegistrationsRequest));
                // Binds the request metrics to the current request.
                request.setAWSRequestMetrics(awsRequestMetrics);
                request.addHandlerContext(HandlerContextKey.CLIENT_ENDPOINT, endpoint);
                request.addHandlerContext(HandlerContextKey.ENDPOINT_OVERRIDDEN, isEndpointOverridden());
                request.addHandlerContext(HandlerContextKey.SIGNING_REGION, getSigningRegion());
                request.addHandlerContext(HandlerContextKey.SERVICE_ID, "TaxSettings");
                request.addHandlerContext(HandlerContextKey.OPERATION_NAME, "ListTaxRegistrations");
                request.addHandlerContext(HandlerContextKey.ADVANCED_CONFIG, advancedConfig);

            } finally {
                awsRequestMetrics.endEvent(Field.RequestMarshallTime);
            }

            HttpResponseHandler<AmazonWebServiceResponse<ListTaxRegistrationsResult>> responseHandler = protocolFactory.createResponseHandler(
                    new JsonOperationMetadata().withPayloadJson(true).withHasStreamingSuccessResponse(false), new ListTaxRegistrationsResultJsonUnmarshaller());
            response = invoke(request, responseHandler, executionContext);

            return response.getAwsResponse();

        } finally {

            endClientExecution(awsRequestMetrics, request, response);
        }
    }

    /**
     * <p>
     * Adds or updates tax registration for a single account. You can't set a TRN if there's a pending TRN. You'll need
     * to delete the pending TRN first.
     * </p>
     * <p>
     * To call this API operation for specific countries, see the following country-specific requirements.
     * </p>
     * <p>
     * <b>Bangladesh</b>
     * </p>
     * <ul>
     * <li>
     * <p>
     * You must specify the tax registration certificate document in the <code>taxRegistrationDocuments</code> field of
     * the <code>VerificationDetails</code> object.
     * </p>
     * </li>
     * </ul>
     * <p>
     * <b>Brazil</b>
     * </p>
     * <ul>
     * <li>
     * <p>
     * You must complete the tax registration process in the <a
     * href="https://console.aws.amazon.com/billing/home#/paymentpreferences/paymentmethods">Payment preferences</a>
     * page in the Billing and Cost Management console. After your TRN and billing address are verified, you can call
     * this API operation.
     * </p>
     * </li>
     * <li>
     * <p>
     * For Amazon Web Services accounts created through Organizations, you can call this API operation when you don't
     * have a billing address.
     * </p>
     * </li>
     * </ul>
     * <p>
     * <b>Georgia</b>
     * </p>
     * <ul>
     * <li>
     * <p>
     * The valid <code>personType</code> values are <code>Physical Person</code> and <code>Business</code>.
     * </p>
     * </li>
     * </ul>
     * <p>
     * <b>Kenya</b>
     * </p>
     * <ul>
     * <li>
     * <p>
     * You must specify the <code>personType</code> in the <code>kenyaAdditionalInfo</code> field of the
     * <code>additionalTaxInformation</code> object.
     * </p>
     * </li>
     * <li>
     * <p>
     * If the <code>personType</code> is <code>Physical Person</code>, you must specify the tax registration certificate
     * document in the <code>taxRegistrationDocuments</code> field of the <code>VerificationDetails</code> object.
     * </p>
     * </li>
     * </ul>
     * <p>
     * <b>Malaysia</b>
     * </p>
     * <ul>
     * <li>
     * <p>
     * If you use this operation to set a tax registration number (TRN) in Malaysia, only resellers with a valid sales
     * and service tax (SST) number are required to provide tax registration information.
     * </p>
     * </li>
     * <li>
     * <p>
     * By using this API operation to set a TRN in Malaysia, Amazon Web Services will regard you as self-declaring that
     * you're an authorized business reseller registered with the Royal Malaysia Customs Department (RMCD) and have a
     * valid SST number.
     * </p>
     * </li>
     * <li>
     * <p>
     * Amazon Web Services reserves the right to seek additional information and/or take other actions to support your
     * self-declaration as appropriate.
     * </p>
     * </li>
     * <li>
     * <p>
     * If you're not a reseller of Amazon Web Services, we don't recommend that you use this operation to set the TRN in
     * Malaysia.
     * </p>
     * </li>
     * <li>
     * <p>
     * Only use this API operation to upload the TRNs for accounts through which you're reselling Amazon Web Services.
     * </p>
     * </li>
     * <li>
     * <p>
     * Amazon Web Services is currently registered under the following service tax codes. You must include at least one
     * of the service tax codes in the service tax code strings to declare yourself as an authorized registered business
     * reseller.
     * </p>
     * <p>
     * Taxable service and service tax codes:
     * </p>
     * <p>
     * Consultancy - 9907061674
     * </p>
     * <p>
     * Training or coaching service - 9907071685
     * </p>
     * <p>
     * IT service - 9907101676
     * </p>
     * <p>
     * Digital services and electronic medium - 9907121690
     * </p>
     * </li>
     * </ul>
     * <p>
     * <b>Nepal</b>
     * </p>
     * <ul>
     * <li>
     * <p>
     * The sector valid values are <code>Business</code> and <code>Individual</code>.
     * </p>
     * </li>
     * </ul>
     * <p>
     * <b>Saudi Arabia</b>
     * </p>
     * <ul>
     * <li>
     * <p>
     * For <code>address</code>, you must specify <code>addressLine3</code>.
     * </p>
     * </li>
     * </ul>
     * <p>
     * <b>South Korea</b>
     * </p>
     * <ul>
     * <li>
     * <p>
     * You must specify the <code>certifiedEmailId</code> and <code>legalName</code> in the
     * <code>TaxRegistrationEntry</code> object. Use Korean characters for <code>legalName</code>.
     * </p>
     * </li>
     * <li>
     * <p>
     * You must specify the <code>businessRepresentativeName</code>, <code>itemOfBusiness</code>, and
     * <code>lineOfBusiness</code> in the <code>southKoreaAdditionalInfo</code> field of the
     * <code>additionalTaxInformation</code> object. Use Korean characters for these fields.
     * </p>
     * </li>
     * <li>
     * <p>
     * You must specify the tax registration certificate document in the <code>taxRegistrationDocuments</code> field of
     * the <code>VerificationDetails</code> object.
     * </p>
     * </li>
     * <li>
     * <p>
     * For the <code>address</code> object, use Korean characters for <code>addressLine1</code>,
     * <code>addressLine2</code> <code>city</code>, <code>postalCode</code>, and <code>stateOrRegion</code>.
     * </p>
     * </li>
     * </ul>
     * <p>
     * <b>Spain</b>
     * </p>
     * <ul>
     * <li>
     * <p>
     * You must specify the <code>registrationType</code> in the <code>spainAdditionalInfo</code> field of the
     * <code>additionalTaxInformation</code> object.
     * </p>
     * </li>
     * <li>
     * <p>
     * If the <code>registrationType</code> is <code>Local</code>, you must specify the tax registration certificate
     * document in the <code>taxRegistrationDocuments</code> field of the <code>VerificationDetails</code> object.
     * </p>
     * </li>
     * </ul>
     * <p>
     * <b>Turkey</b>
     * </p>
     * <ul>
     * <li>
     * <p>
     * You must specify the <code>sector</code> in the <code>taxRegistrationEntry</code> object.
     * </p>
     * </li>
     * <li>
     * <p>
     * If your <code>sector</code> is <code>Business</code>, <code>Individual</code>, or <code>Government</code>:
     * </p>
     * <ul>
     * <li>
     * <p>
     * Specify the <code>taxOffice</code>. If your <code>sector</code> is <code>Individual</code>, don't enter this
     * value.
     * </p>
     * </li>
     * <li>
     * <p>
     * (Optional) Specify the <code>kepEmailId</code>. If your <code>sector</code> is <code>Individual</code>, don't
     * enter this value.
     * </p>
     * </li>
     * <li>
     * <p>
     * <b>Note:</b> In the <b>Tax Settings</b> page of the Billing console, <code>Government</code> appears as <b>Public
     * institutions</b>
     * </p>
     * </li>
     * </ul>
     * </li>
     * <li>
     * <p>
     * If your <code>sector</code> is <code>Business</code> and you're subject to KDV tax, you must specify your
     * industry in the <code>industries</code> field.
     * </p>
     * </li>
     * <li>
     * <p>
     * For <code>address</code>, you must specify <code>districtOrCounty</code>.
     * </p>
     * </li>
     * </ul>
     * <p>
     * <b>Ukraine</b>
     * </p>
     * <ul>
     * <li>
     * <p>
     * The sector valid values are <code>Business</code> and <code>Individual</code>.
     * </p>
     * </li>
     * </ul>
     * 
     * @param putTaxRegistrationRequest
     * @return Result of the PutTaxRegistration operation returned by the service.
     * @throws ValidationException
     *         The exception when the input doesn't pass validation for at least one of the input parameters.
     * @throws ConflictException
     *         The exception when the input is creating conflict with the given state.
     * @throws InternalServerException
     *         The exception thrown when an unexpected error occurs when processing a request.
     * @sample AWSTaxSettings.PutTaxRegistration
     * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/taxsettings-2018-05-10/PutTaxRegistration" target="_top">AWS
     *      API Documentation</a>
     */
    @Override
    public PutTaxRegistrationResult putTaxRegistration(PutTaxRegistrationRequest request) {
        request = beforeClientExecution(request);
        return executePutTaxRegistration(request);
    }

    @SdkInternalApi
    final PutTaxRegistrationResult executePutTaxRegistration(PutTaxRegistrationRequest putTaxRegistrationRequest) {

        ExecutionContext executionContext = createExecutionContext(putTaxRegistrationRequest);
        AWSRequestMetrics awsRequestMetrics = executionContext.getAwsRequestMetrics();
        awsRequestMetrics.startEvent(Field.ClientExecuteTime);
        Request<PutTaxRegistrationRequest> request = null;
        Response<PutTaxRegistrationResult> response = null;

        try {
            awsRequestMetrics.startEvent(Field.RequestMarshallTime);
            try {
                request = new PutTaxRegistrationRequestProtocolMarshaller(protocolFactory).marshall(super.beforeMarshalling(putTaxRegistrationRequest));
                // Binds the request metrics to the current request.
                request.setAWSRequestMetrics(awsRequestMetrics);
                request.addHandlerContext(HandlerContextKey.CLIENT_ENDPOINT, endpoint);
                request.addHandlerContext(HandlerContextKey.ENDPOINT_OVERRIDDEN, isEndpointOverridden());
                request.addHandlerContext(HandlerContextKey.SIGNING_REGION, getSigningRegion());
                request.addHandlerContext(HandlerContextKey.SERVICE_ID, "TaxSettings");
                request.addHandlerContext(HandlerContextKey.OPERATION_NAME, "PutTaxRegistration");
                request.addHandlerContext(HandlerContextKey.ADVANCED_CONFIG, advancedConfig);

            } finally {
                awsRequestMetrics.endEvent(Field.RequestMarshallTime);
            }

            HttpResponseHandler<AmazonWebServiceResponse<PutTaxRegistrationResult>> responseHandler = protocolFactory.createResponseHandler(
                    new JsonOperationMetadata().withPayloadJson(true).withHasStreamingSuccessResponse(false), new PutTaxRegistrationResultJsonUnmarshaller());
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
