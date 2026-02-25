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

import javax.annotation.Generated;

import com.amazonaws.*;
import com.amazonaws.regions.*;

import com.amazonaws.services.licensemanagerlinuxsubscriptions.model.*;

/**
 * Interface for accessing AWS License Manager Linux Subscriptions.
 * <p>
 * <b>Note:</b> Do not directly implement this interface, new methods are added to it regularly. Extend from
 * {@link com.amazonaws.services.licensemanagerlinuxsubscriptions.AbstractAWSLicenseManagerLinuxSubscriptions} instead.
 * </p>
 * <p>
 * <p>
 * With License Manager, you can discover and track your commercial Linux subscriptions on running Amazon EC2 instances.
 * </p>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public interface AWSLicenseManagerLinuxSubscriptions {

    /**
     * The region metadata service name for computing region endpoints. You can use this value to retrieve metadata
     * (such as supported regions) of the service.
     *
     * @see RegionUtils#getRegionsForService(String)
     */
    String ENDPOINT_PREFIX = "license-manager-linux-subscriptions";

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
    DeregisterSubscriptionProviderResult deregisterSubscriptionProvider(DeregisterSubscriptionProviderRequest deregisterSubscriptionProviderRequest);

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
    GetRegisteredSubscriptionProviderResult getRegisteredSubscriptionProvider(GetRegisteredSubscriptionProviderRequest getRegisteredSubscriptionProviderRequest);

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
    GetServiceSettingsResult getServiceSettings(GetServiceSettingsRequest getServiceSettingsRequest);

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
    ListLinuxSubscriptionInstancesResult listLinuxSubscriptionInstances(ListLinuxSubscriptionInstancesRequest listLinuxSubscriptionInstancesRequest);

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
    ListLinuxSubscriptionsResult listLinuxSubscriptions(ListLinuxSubscriptionsRequest listLinuxSubscriptionsRequest);

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
    ListRegisteredSubscriptionProvidersResult listRegisteredSubscriptionProviders(
            ListRegisteredSubscriptionProvidersRequest listRegisteredSubscriptionProvidersRequest);

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
    ListTagsForResourceResult listTagsForResource(ListTagsForResourceRequest listTagsForResourceRequest);

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
    RegisterSubscriptionProviderResult registerSubscriptionProvider(RegisterSubscriptionProviderRequest registerSubscriptionProviderRequest);

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
    TagResourceResult tagResource(TagResourceRequest tagResourceRequest);

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
    UntagResourceResult untagResource(UntagResourceRequest untagResourceRequest);

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
    UpdateServiceSettingsResult updateServiceSettings(UpdateServiceSettingsRequest updateServiceSettingsRequest);

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
