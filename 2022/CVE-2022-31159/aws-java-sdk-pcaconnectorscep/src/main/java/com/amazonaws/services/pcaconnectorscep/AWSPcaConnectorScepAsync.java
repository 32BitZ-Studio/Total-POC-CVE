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

/**
 * Interface for accessing Private CA Connector for SCEP asynchronously. Each asynchronous method will return a Java
 * Future object representing the asynchronous operation; overloads which accept an {@code AsyncHandler} can be used to
 * receive notification when an asynchronous operation completes.
 * <p>
 * <b>Note:</b> Do not directly implement this interface, new methods are added to it regularly. Extend from
 * {@link com.amazonaws.services.pcaconnectorscep.AbstractAWSPcaConnectorScepAsync} instead.
 * </p>
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
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public interface AWSPcaConnectorScepAsync extends AWSPcaConnectorScep {

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
     * @return A Java Future containing the result of the CreateChallenge operation returned by the service.
     * @sample AWSPcaConnectorScepAsync.CreateChallenge
     * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/pca-connector-scep-2018-05-10/CreateChallenge"
     *      target="_top">AWS API Documentation</a>
     */
    java.util.concurrent.Future<CreateChallengeResult> createChallengeAsync(CreateChallengeRequest createChallengeRequest);

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
     * @param asyncHandler
     *        Asynchronous callback handler for events in the lifecycle of the request. Users can provide an
     *        implementation of the callback methods in this interface to receive notification of successful or
     *        unsuccessful completion of the operation.
     * @return A Java Future containing the result of the CreateChallenge operation returned by the service.
     * @sample AWSPcaConnectorScepAsyncHandler.CreateChallenge
     * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/pca-connector-scep-2018-05-10/CreateChallenge"
     *      target="_top">AWS API Documentation</a>
     */
    java.util.concurrent.Future<CreateChallengeResult> createChallengeAsync(CreateChallengeRequest createChallengeRequest,
            com.amazonaws.handlers.AsyncHandler<CreateChallengeRequest, CreateChallengeResult> asyncHandler);

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
     * @return A Java Future containing the result of the CreateConnector operation returned by the service.
     * @sample AWSPcaConnectorScepAsync.CreateConnector
     * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/pca-connector-scep-2018-05-10/CreateConnector"
     *      target="_top">AWS API Documentation</a>
     */
    java.util.concurrent.Future<CreateConnectorResult> createConnectorAsync(CreateConnectorRequest createConnectorRequest);

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
     * @param asyncHandler
     *        Asynchronous callback handler for events in the lifecycle of the request. Users can provide an
     *        implementation of the callback methods in this interface to receive notification of successful or
     *        unsuccessful completion of the operation.
     * @return A Java Future containing the result of the CreateConnector operation returned by the service.
     * @sample AWSPcaConnectorScepAsyncHandler.CreateConnector
     * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/pca-connector-scep-2018-05-10/CreateConnector"
     *      target="_top">AWS API Documentation</a>
     */
    java.util.concurrent.Future<CreateConnectorResult> createConnectorAsync(CreateConnectorRequest createConnectorRequest,
            com.amazonaws.handlers.AsyncHandler<CreateConnectorRequest, CreateConnectorResult> asyncHandler);

    /**
     * <p>
     * Deletes the specified <a
     * href="https://docs.aws.amazon.com/C4SCEP_API/pca-connector-scep/latest/APIReference/API_Challenge.html"
     * >Challenge</a>.
     * </p>
     * 
     * @param deleteChallengeRequest
     * @return A Java Future containing the result of the DeleteChallenge operation returned by the service.
     * @sample AWSPcaConnectorScepAsync.DeleteChallenge
     * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/pca-connector-scep-2018-05-10/DeleteChallenge"
     *      target="_top">AWS API Documentation</a>
     */
    java.util.concurrent.Future<DeleteChallengeResult> deleteChallengeAsync(DeleteChallengeRequest deleteChallengeRequest);

    /**
     * <p>
     * Deletes the specified <a
     * href="https://docs.aws.amazon.com/C4SCEP_API/pca-connector-scep/latest/APIReference/API_Challenge.html"
     * >Challenge</a>.
     * </p>
     * 
     * @param deleteChallengeRequest
     * @param asyncHandler
     *        Asynchronous callback handler for events in the lifecycle of the request. Users can provide an
     *        implementation of the callback methods in this interface to receive notification of successful or
     *        unsuccessful completion of the operation.
     * @return A Java Future containing the result of the DeleteChallenge operation returned by the service.
     * @sample AWSPcaConnectorScepAsyncHandler.DeleteChallenge
     * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/pca-connector-scep-2018-05-10/DeleteChallenge"
     *      target="_top">AWS API Documentation</a>
     */
    java.util.concurrent.Future<DeleteChallengeResult> deleteChallengeAsync(DeleteChallengeRequest deleteChallengeRequest,
            com.amazonaws.handlers.AsyncHandler<DeleteChallengeRequest, DeleteChallengeResult> asyncHandler);

    /**
     * <p>
     * Deletes the specified <a
     * href="https://docs.aws.amazon.com/C4SCEP_API/pca-connector-scep/latest/APIReference/API_Connector.html"
     * >Connector</a>. This operation also deletes any challenges associated with the connector.
     * </p>
     * 
     * @param deleteConnectorRequest
     * @return A Java Future containing the result of the DeleteConnector operation returned by the service.
     * @sample AWSPcaConnectorScepAsync.DeleteConnector
     * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/pca-connector-scep-2018-05-10/DeleteConnector"
     *      target="_top">AWS API Documentation</a>
     */
    java.util.concurrent.Future<DeleteConnectorResult> deleteConnectorAsync(DeleteConnectorRequest deleteConnectorRequest);

    /**
     * <p>
     * Deletes the specified <a
     * href="https://docs.aws.amazon.com/C4SCEP_API/pca-connector-scep/latest/APIReference/API_Connector.html"
     * >Connector</a>. This operation also deletes any challenges associated with the connector.
     * </p>
     * 
     * @param deleteConnectorRequest
     * @param asyncHandler
     *        Asynchronous callback handler for events in the lifecycle of the request. Users can provide an
     *        implementation of the callback methods in this interface to receive notification of successful or
     *        unsuccessful completion of the operation.
     * @return A Java Future containing the result of the DeleteConnector operation returned by the service.
     * @sample AWSPcaConnectorScepAsyncHandler.DeleteConnector
     * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/pca-connector-scep-2018-05-10/DeleteConnector"
     *      target="_top">AWS API Documentation</a>
     */
    java.util.concurrent.Future<DeleteConnectorResult> deleteConnectorAsync(DeleteConnectorRequest deleteConnectorRequest,
            com.amazonaws.handlers.AsyncHandler<DeleteConnectorRequest, DeleteConnectorResult> asyncHandler);

    /**
     * <p>
     * Retrieves the metadata for the specified <a
     * href="https://docs.aws.amazon.com/C4SCEP_API/pca-connector-scep/latest/APIReference/API_Challenge.html"
     * >Challenge</a>.
     * </p>
     * 
     * @param getChallengeMetadataRequest
     * @return A Java Future containing the result of the GetChallengeMetadata operation returned by the service.
     * @sample AWSPcaConnectorScepAsync.GetChallengeMetadata
     * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/pca-connector-scep-2018-05-10/GetChallengeMetadata"
     *      target="_top">AWS API Documentation</a>
     */
    java.util.concurrent.Future<GetChallengeMetadataResult> getChallengeMetadataAsync(GetChallengeMetadataRequest getChallengeMetadataRequest);

    /**
     * <p>
     * Retrieves the metadata for the specified <a
     * href="https://docs.aws.amazon.com/C4SCEP_API/pca-connector-scep/latest/APIReference/API_Challenge.html"
     * >Challenge</a>.
     * </p>
     * 
     * @param getChallengeMetadataRequest
     * @param asyncHandler
     *        Asynchronous callback handler for events in the lifecycle of the request. Users can provide an
     *        implementation of the callback methods in this interface to receive notification of successful or
     *        unsuccessful completion of the operation.
     * @return A Java Future containing the result of the GetChallengeMetadata operation returned by the service.
     * @sample AWSPcaConnectorScepAsyncHandler.GetChallengeMetadata
     * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/pca-connector-scep-2018-05-10/GetChallengeMetadata"
     *      target="_top">AWS API Documentation</a>
     */
    java.util.concurrent.Future<GetChallengeMetadataResult> getChallengeMetadataAsync(GetChallengeMetadataRequest getChallengeMetadataRequest,
            com.amazonaws.handlers.AsyncHandler<GetChallengeMetadataRequest, GetChallengeMetadataResult> asyncHandler);

    /**
     * <p>
     * Retrieves the challenge password for the specified <a
     * href="https://docs.aws.amazon.com/C4SCEP_API/pca-connector-scep/latest/APIReference/API_Challenge.html"
     * >Challenge</a>.
     * </p>
     * 
     * @param getChallengePasswordRequest
     * @return A Java Future containing the result of the GetChallengePassword operation returned by the service.
     * @sample AWSPcaConnectorScepAsync.GetChallengePassword
     * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/pca-connector-scep-2018-05-10/GetChallengePassword"
     *      target="_top">AWS API Documentation</a>
     */
    java.util.concurrent.Future<GetChallengePasswordResult> getChallengePasswordAsync(GetChallengePasswordRequest getChallengePasswordRequest);

    /**
     * <p>
     * Retrieves the challenge password for the specified <a
     * href="https://docs.aws.amazon.com/C4SCEP_API/pca-connector-scep/latest/APIReference/API_Challenge.html"
     * >Challenge</a>.
     * </p>
     * 
     * @param getChallengePasswordRequest
     * @param asyncHandler
     *        Asynchronous callback handler for events in the lifecycle of the request. Users can provide an
     *        implementation of the callback methods in this interface to receive notification of successful or
     *        unsuccessful completion of the operation.
     * @return A Java Future containing the result of the GetChallengePassword operation returned by the service.
     * @sample AWSPcaConnectorScepAsyncHandler.GetChallengePassword
     * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/pca-connector-scep-2018-05-10/GetChallengePassword"
     *      target="_top">AWS API Documentation</a>
     */
    java.util.concurrent.Future<GetChallengePasswordResult> getChallengePasswordAsync(GetChallengePasswordRequest getChallengePasswordRequest,
            com.amazonaws.handlers.AsyncHandler<GetChallengePasswordRequest, GetChallengePasswordResult> asyncHandler);

    /**
     * <p>
     * Retrieves details about the specified <a
     * href="https://docs.aws.amazon.com/C4SCEP_API/pca-connector-scep/latest/APIReference/API_Connector.html"
     * >Connector</a>. Calling this action returns important details about the connector, such as the public SCEP URL
     * where your clients can request certificates.
     * </p>
     * 
     * @param getConnectorRequest
     * @return A Java Future containing the result of the GetConnector operation returned by the service.
     * @sample AWSPcaConnectorScepAsync.GetConnector
     * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/pca-connector-scep-2018-05-10/GetConnector"
     *      target="_top">AWS API Documentation</a>
     */
    java.util.concurrent.Future<GetConnectorResult> getConnectorAsync(GetConnectorRequest getConnectorRequest);

    /**
     * <p>
     * Retrieves details about the specified <a
     * href="https://docs.aws.amazon.com/C4SCEP_API/pca-connector-scep/latest/APIReference/API_Connector.html"
     * >Connector</a>. Calling this action returns important details about the connector, such as the public SCEP URL
     * where your clients can request certificates.
     * </p>
     * 
     * @param getConnectorRequest
     * @param asyncHandler
     *        Asynchronous callback handler for events in the lifecycle of the request. Users can provide an
     *        implementation of the callback methods in this interface to receive notification of successful or
     *        unsuccessful completion of the operation.
     * @return A Java Future containing the result of the GetConnector operation returned by the service.
     * @sample AWSPcaConnectorScepAsyncHandler.GetConnector
     * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/pca-connector-scep-2018-05-10/GetConnector"
     *      target="_top">AWS API Documentation</a>
     */
    java.util.concurrent.Future<GetConnectorResult> getConnectorAsync(GetConnectorRequest getConnectorRequest,
            com.amazonaws.handlers.AsyncHandler<GetConnectorRequest, GetConnectorResult> asyncHandler);

    /**
     * <p>
     * Retrieves the challenge metadata for the specified ARN.
     * </p>
     * 
     * @param listChallengeMetadataRequest
     * @return A Java Future containing the result of the ListChallengeMetadata operation returned by the service.
     * @sample AWSPcaConnectorScepAsync.ListChallengeMetadata
     * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/pca-connector-scep-2018-05-10/ListChallengeMetadata"
     *      target="_top">AWS API Documentation</a>
     */
    java.util.concurrent.Future<ListChallengeMetadataResult> listChallengeMetadataAsync(ListChallengeMetadataRequest listChallengeMetadataRequest);

    /**
     * <p>
     * Retrieves the challenge metadata for the specified ARN.
     * </p>
     * 
     * @param listChallengeMetadataRequest
     * @param asyncHandler
     *        Asynchronous callback handler for events in the lifecycle of the request. Users can provide an
     *        implementation of the callback methods in this interface to receive notification of successful or
     *        unsuccessful completion of the operation.
     * @return A Java Future containing the result of the ListChallengeMetadata operation returned by the service.
     * @sample AWSPcaConnectorScepAsyncHandler.ListChallengeMetadata
     * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/pca-connector-scep-2018-05-10/ListChallengeMetadata"
     *      target="_top">AWS API Documentation</a>
     */
    java.util.concurrent.Future<ListChallengeMetadataResult> listChallengeMetadataAsync(ListChallengeMetadataRequest listChallengeMetadataRequest,
            com.amazonaws.handlers.AsyncHandler<ListChallengeMetadataRequest, ListChallengeMetadataResult> asyncHandler);

    /**
     * <p>
     * Lists the connectors belonging to your Amazon Web Services account.
     * </p>
     * 
     * @param listConnectorsRequest
     * @return A Java Future containing the result of the ListConnectors operation returned by the service.
     * @sample AWSPcaConnectorScepAsync.ListConnectors
     * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/pca-connector-scep-2018-05-10/ListConnectors"
     *      target="_top">AWS API Documentation</a>
     */
    java.util.concurrent.Future<ListConnectorsResult> listConnectorsAsync(ListConnectorsRequest listConnectorsRequest);

    /**
     * <p>
     * Lists the connectors belonging to your Amazon Web Services account.
     * </p>
     * 
     * @param listConnectorsRequest
     * @param asyncHandler
     *        Asynchronous callback handler for events in the lifecycle of the request. Users can provide an
     *        implementation of the callback methods in this interface to receive notification of successful or
     *        unsuccessful completion of the operation.
     * @return A Java Future containing the result of the ListConnectors operation returned by the service.
     * @sample AWSPcaConnectorScepAsyncHandler.ListConnectors
     * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/pca-connector-scep-2018-05-10/ListConnectors"
     *      target="_top">AWS API Documentation</a>
     */
    java.util.concurrent.Future<ListConnectorsResult> listConnectorsAsync(ListConnectorsRequest listConnectorsRequest,
            com.amazonaws.handlers.AsyncHandler<ListConnectorsRequest, ListConnectorsResult> asyncHandler);

    /**
     * <p>
     * Retrieves the tags associated with the specified resource. Tags are key-value pairs that you can use to
     * categorize and manage your resources, for purposes like billing. For example, you might set the tag key to
     * "customer" and the value to the customer name or ID. You can specify one or more tags to add to each Amazon Web
     * Services resource, up to 50 tags for a resource.
     * </p>
     * 
     * @param listTagsForResourceRequest
     * @return A Java Future containing the result of the ListTagsForResource operation returned by the service.
     * @sample AWSPcaConnectorScepAsync.ListTagsForResource
     * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/pca-connector-scep-2018-05-10/ListTagsForResource"
     *      target="_top">AWS API Documentation</a>
     */
    java.util.concurrent.Future<ListTagsForResourceResult> listTagsForResourceAsync(ListTagsForResourceRequest listTagsForResourceRequest);

    /**
     * <p>
     * Retrieves the tags associated with the specified resource. Tags are key-value pairs that you can use to
     * categorize and manage your resources, for purposes like billing. For example, you might set the tag key to
     * "customer" and the value to the customer name or ID. You can specify one or more tags to add to each Amazon Web
     * Services resource, up to 50 tags for a resource.
     * </p>
     * 
     * @param listTagsForResourceRequest
     * @param asyncHandler
     *        Asynchronous callback handler for events in the lifecycle of the request. Users can provide an
     *        implementation of the callback methods in this interface to receive notification of successful or
     *        unsuccessful completion of the operation.
     * @return A Java Future containing the result of the ListTagsForResource operation returned by the service.
     * @sample AWSPcaConnectorScepAsyncHandler.ListTagsForResource
     * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/pca-connector-scep-2018-05-10/ListTagsForResource"
     *      target="_top">AWS API Documentation</a>
     */
    java.util.concurrent.Future<ListTagsForResourceResult> listTagsForResourceAsync(ListTagsForResourceRequest listTagsForResourceRequest,
            com.amazonaws.handlers.AsyncHandler<ListTagsForResourceRequest, ListTagsForResourceResult> asyncHandler);

    /**
     * <p>
     * Adds one or more tags to your resource.
     * </p>
     * 
     * @param tagResourceRequest
     * @return A Java Future containing the result of the TagResource operation returned by the service.
     * @sample AWSPcaConnectorScepAsync.TagResource
     * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/pca-connector-scep-2018-05-10/TagResource" target="_top">AWS
     *      API Documentation</a>
     */
    java.util.concurrent.Future<TagResourceResult> tagResourceAsync(TagResourceRequest tagResourceRequest);

    /**
     * <p>
     * Adds one or more tags to your resource.
     * </p>
     * 
     * @param tagResourceRequest
     * @param asyncHandler
     *        Asynchronous callback handler for events in the lifecycle of the request. Users can provide an
     *        implementation of the callback methods in this interface to receive notification of successful or
     *        unsuccessful completion of the operation.
     * @return A Java Future containing the result of the TagResource operation returned by the service.
     * @sample AWSPcaConnectorScepAsyncHandler.TagResource
     * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/pca-connector-scep-2018-05-10/TagResource" target="_top">AWS
     *      API Documentation</a>
     */
    java.util.concurrent.Future<TagResourceResult> tagResourceAsync(TagResourceRequest tagResourceRequest,
            com.amazonaws.handlers.AsyncHandler<TagResourceRequest, TagResourceResult> asyncHandler);

    /**
     * <p>
     * Removes one or more tags from your resource.
     * </p>
     * 
     * @param untagResourceRequest
     * @return A Java Future containing the result of the UntagResource operation returned by the service.
     * @sample AWSPcaConnectorScepAsync.UntagResource
     * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/pca-connector-scep-2018-05-10/UntagResource"
     *      target="_top">AWS API Documentation</a>
     */
    java.util.concurrent.Future<UntagResourceResult> untagResourceAsync(UntagResourceRequest untagResourceRequest);

    /**
     * <p>
     * Removes one or more tags from your resource.
     * </p>
     * 
     * @param untagResourceRequest
     * @param asyncHandler
     *        Asynchronous callback handler for events in the lifecycle of the request. Users can provide an
     *        implementation of the callback methods in this interface to receive notification of successful or
     *        unsuccessful completion of the operation.
     * @return A Java Future containing the result of the UntagResource operation returned by the service.
     * @sample AWSPcaConnectorScepAsyncHandler.UntagResource
     * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/pca-connector-scep-2018-05-10/UntagResource"
     *      target="_top">AWS API Documentation</a>
     */
    java.util.concurrent.Future<UntagResourceResult> untagResourceAsync(UntagResourceRequest untagResourceRequest,
            com.amazonaws.handlers.AsyncHandler<UntagResourceRequest, UntagResourceResult> asyncHandler);

}
