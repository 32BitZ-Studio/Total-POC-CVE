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

import com.amazonaws.*;
import com.amazonaws.regions.*;

import com.amazonaws.services.pcaconnectorscep.model.*;

/**
 * Interface for accessing Private CA Connector for SCEP.
 * <p>
 * <b>Note:</b> Do not directly implement this interface, new methods are added to it regularly. Extend from
 * {@link com.amazonaws.services.pcaconnectorscep.AbstractAWSPcaConnectorScep} instead.
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
public interface AWSPcaConnectorScep {

    /**
     * The region metadata service name for computing region endpoints. You can use this value to retrieve metadata
     * (such as supported regions) of the service.
     *
     * @see RegionUtils#getRegionsForService(String)
     */
    String ENDPOINT_PREFIX = "pca-connector-scep";

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
    CreateChallengeResult createChallenge(CreateChallengeRequest createChallengeRequest);

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
    CreateConnectorResult createConnector(CreateConnectorRequest createConnectorRequest);

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
    DeleteChallengeResult deleteChallenge(DeleteChallengeRequest deleteChallengeRequest);

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
    DeleteConnectorResult deleteConnector(DeleteConnectorRequest deleteConnectorRequest);

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
    GetChallengeMetadataResult getChallengeMetadata(GetChallengeMetadataRequest getChallengeMetadataRequest);

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
    GetChallengePasswordResult getChallengePassword(GetChallengePasswordRequest getChallengePasswordRequest);

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
    GetConnectorResult getConnector(GetConnectorRequest getConnectorRequest);

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
    ListChallengeMetadataResult listChallengeMetadata(ListChallengeMetadataRequest listChallengeMetadataRequest);

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
    ListConnectorsResult listConnectors(ListConnectorsRequest listConnectorsRequest);

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
    ListTagsForResourceResult listTagsForResource(ListTagsForResourceRequest listTagsForResourceRequest);

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
    TagResourceResult tagResource(TagResourceRequest tagResourceRequest);

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
    UntagResourceResult untagResource(UntagResourceRequest untagResourceRequest);

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
