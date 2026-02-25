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

import com.amazonaws.services.licensemanagerlinuxsubscriptions.model.*;

/**
 * Interface for accessing AWS License Manager Linux Subscriptions asynchronously. Each asynchronous method will return
 * a Java Future object representing the asynchronous operation; overloads which accept an {@code AsyncHandler} can be
 * used to receive notification when an asynchronous operation completes.
 * <p>
 * <b>Note:</b> Do not directly implement this interface, new methods are added to it regularly. Extend from
 * {@link com.amazonaws.services.licensemanagerlinuxsubscriptions.AbstractAWSLicenseManagerLinuxSubscriptionsAsync}
 * instead.
 * </p>
 * <p>
 * <p>
 * With License Manager, you can discover and track your commercial Linux subscriptions on running Amazon EC2 instances.
 * </p>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public interface AWSLicenseManagerLinuxSubscriptionsAsync extends AWSLicenseManagerLinuxSubscriptions {

    /**
     * <p>
     * Remove a third-party subscription provider from the Bring Your Own License (BYOL) subscriptions registered to
     * your account.
     * </p>
     * 
     * @param deregisterSubscriptionProviderRequest
     * @return A Java Future containing the result of the DeregisterSubscriptionProvider operation returned by the
     *         service.
     * @sample AWSLicenseManagerLinuxSubscriptionsAsync.DeregisterSubscriptionProvider
     * @see <a
     *      href="http://docs.aws.amazon.com/goto/WebAPI/license-manager-linux-subscriptions-2018-05-10/DeregisterSubscriptionProvider"
     *      target="_top">AWS API Documentation</a>
     */
    java.util.concurrent.Future<DeregisterSubscriptionProviderResult> deregisterSubscriptionProviderAsync(
            DeregisterSubscriptionProviderRequest deregisterSubscriptionProviderRequest);

    /**
     * <p>
     * Remove a third-party subscription provider from the Bring Your Own License (BYOL) subscriptions registered to
     * your account.
     * </p>
     * 
     * @param deregisterSubscriptionProviderRequest
     * @param asyncHandler
     *        Asynchronous callback handler for events in the lifecycle of the request. Users can provide an
     *        implementation of the callback methods in this interface to receive notification of successful or
     *        unsuccessful completion of the operation.
     * @return A Java Future containing the result of the DeregisterSubscriptionProvider operation returned by the
     *         service.
     * @sample AWSLicenseManagerLinuxSubscriptionsAsyncHandler.DeregisterSubscriptionProvider
     * @see <a
     *      href="http://docs.aws.amazon.com/goto/WebAPI/license-manager-linux-subscriptions-2018-05-10/DeregisterSubscriptionProvider"
     *      target="_top">AWS API Documentation</a>
     */
    java.util.concurrent.Future<DeregisterSubscriptionProviderResult> deregisterSubscriptionProviderAsync(
            DeregisterSubscriptionProviderRequest deregisterSubscriptionProviderRequest,
            com.amazonaws.handlers.AsyncHandler<DeregisterSubscriptionProviderRequest, DeregisterSubscriptionProviderResult> asyncHandler);

    /**
     * <p>
     * Get details for a Bring Your Own License (BYOL) subscription that's registered to your account.
     * </p>
     * 
     * @param getRegisteredSubscriptionProviderRequest
     * @return A Java Future containing the result of the GetRegisteredSubscriptionProvider operation returned by the
     *         service.
     * @sample AWSLicenseManagerLinuxSubscriptionsAsync.GetRegisteredSubscriptionProvider
     * @see <a
     *      href="http://docs.aws.amazon.com/goto/WebAPI/license-manager-linux-subscriptions-2018-05-10/GetRegisteredSubscriptionProvider"
     *      target="_top">AWS API Documentation</a>
     */
    java.util.concurrent.Future<GetRegisteredSubscriptionProviderResult> getRegisteredSubscriptionProviderAsync(
            GetRegisteredSubscriptionProviderRequest getRegisteredSubscriptionProviderRequest);

    /**
     * <p>
     * Get details for a Bring Your Own License (BYOL) subscription that's registered to your account.
     * </p>
     * 
     * @param getRegisteredSubscriptionProviderRequest
     * @param asyncHandler
     *        Asynchronous callback handler for events in the lifecycle of the request. Users can provide an
     *        implementation of the callback methods in this interface to receive notification of successful or
     *        unsuccessful completion of the operation.
     * @return A Java Future containing the result of the GetRegisteredSubscriptionProvider operation returned by the
     *         service.
     * @sample AWSLicenseManagerLinuxSubscriptionsAsyncHandler.GetRegisteredSubscriptionProvider
     * @see <a
     *      href="http://docs.aws.amazon.com/goto/WebAPI/license-manager-linux-subscriptions-2018-05-10/GetRegisteredSubscriptionProvider"
     *      target="_top">AWS API Documentation</a>
     */
    java.util.concurrent.Future<GetRegisteredSubscriptionProviderResult> getRegisteredSubscriptionProviderAsync(
            GetRegisteredSubscriptionProviderRequest getRegisteredSubscriptionProviderRequest,
            com.amazonaws.handlers.AsyncHandler<GetRegisteredSubscriptionProviderRequest, GetRegisteredSubscriptionProviderResult> asyncHandler);

    /**
     * <p>
     * Lists the Linux subscriptions service settings for your account.
     * </p>
     * 
     * @param getServiceSettingsRequest
     * @return A Java Future containing the result of the GetServiceSettings operation returned by the service.
     * @sample AWSLicenseManagerLinuxSubscriptionsAsync.GetServiceSettings
     * @see <a
     *      href="http://docs.aws.amazon.com/goto/WebAPI/license-manager-linux-subscriptions-2018-05-10/GetServiceSettings"
     *      target="_top">AWS API Documentation</a>
     */
    java.util.concurrent.Future<GetServiceSettingsResult> getServiceSettingsAsync(GetServiceSettingsRequest getServiceSettingsRequest);

    /**
     * <p>
     * Lists the Linux subscriptions service settings for your account.
     * </p>
     * 
     * @param getServiceSettingsRequest
     * @param asyncHandler
     *        Asynchronous callback handler for events in the lifecycle of the request. Users can provide an
     *        implementation of the callback methods in this interface to receive notification of successful or
     *        unsuccessful completion of the operation.
     * @return A Java Future containing the result of the GetServiceSettings operation returned by the service.
     * @sample AWSLicenseManagerLinuxSubscriptionsAsyncHandler.GetServiceSettings
     * @see <a
     *      href="http://docs.aws.amazon.com/goto/WebAPI/license-manager-linux-subscriptions-2018-05-10/GetServiceSettings"
     *      target="_top">AWS API Documentation</a>
     */
    java.util.concurrent.Future<GetServiceSettingsResult> getServiceSettingsAsync(GetServiceSettingsRequest getServiceSettingsRequest,
            com.amazonaws.handlers.AsyncHandler<GetServiceSettingsRequest, GetServiceSettingsResult> asyncHandler);

    /**
     * <p>
     * Lists the running Amazon EC2 instances that were discovered with commercial Linux subscriptions.
     * </p>
     * 
     * @param listLinuxSubscriptionInstancesRequest
     *        NextToken length limit is half of ddb accepted limit. Increase this limit if parameters in request
     *        increases.
     * @return A Java Future containing the result of the ListLinuxSubscriptionInstances operation returned by the
     *         service.
     * @sample AWSLicenseManagerLinuxSubscriptionsAsync.ListLinuxSubscriptionInstances
     * @see <a
     *      href="http://docs.aws.amazon.com/goto/WebAPI/license-manager-linux-subscriptions-2018-05-10/ListLinuxSubscriptionInstances"
     *      target="_top">AWS API Documentation</a>
     */
    java.util.concurrent.Future<ListLinuxSubscriptionInstancesResult> listLinuxSubscriptionInstancesAsync(
            ListLinuxSubscriptionInstancesRequest listLinuxSubscriptionInstancesRequest);

    /**
     * <p>
     * Lists the running Amazon EC2 instances that were discovered with commercial Linux subscriptions.
     * </p>
     * 
     * @param listLinuxSubscriptionInstancesRequest
     *        NextToken length limit is half of ddb accepted limit. Increase this limit if parameters in request
     *        increases.
     * @param asyncHandler
     *        Asynchronous callback handler for events in the lifecycle of the request. Users can provide an
     *        implementation of the callback methods in this interface to receive notification of successful or
     *        unsuccessful completion of the operation.
     * @return A Java Future containing the result of the ListLinuxSubscriptionInstances operation returned by the
     *         service.
     * @sample AWSLicenseManagerLinuxSubscriptionsAsyncHandler.ListLinuxSubscriptionInstances
     * @see <a
     *      href="http://docs.aws.amazon.com/goto/WebAPI/license-manager-linux-subscriptions-2018-05-10/ListLinuxSubscriptionInstances"
     *      target="_top">AWS API Documentation</a>
     */
    java.util.concurrent.Future<ListLinuxSubscriptionInstancesResult> listLinuxSubscriptionInstancesAsync(
            ListLinuxSubscriptionInstancesRequest listLinuxSubscriptionInstancesRequest,
            com.amazonaws.handlers.AsyncHandler<ListLinuxSubscriptionInstancesRequest, ListLinuxSubscriptionInstancesResult> asyncHandler);

    /**
     * <p>
     * Lists the Linux subscriptions that have been discovered. If you have linked your organization, the returned
     * results will include data aggregated across your accounts in Organizations.
     * </p>
     * 
     * @param listLinuxSubscriptionsRequest
     *        NextToken length limit is half of ddb accepted limit. Increase this limit if parameters in request
     *        increases.
     * @return A Java Future containing the result of the ListLinuxSubscriptions operation returned by the service.
     * @sample AWSLicenseManagerLinuxSubscriptionsAsync.ListLinuxSubscriptions
     * @see <a
     *      href="http://docs.aws.amazon.com/goto/WebAPI/license-manager-linux-subscriptions-2018-05-10/ListLinuxSubscriptions"
     *      target="_top">AWS API Documentation</a>
     */
    java.util.concurrent.Future<ListLinuxSubscriptionsResult> listLinuxSubscriptionsAsync(ListLinuxSubscriptionsRequest listLinuxSubscriptionsRequest);

    /**
     * <p>
     * Lists the Linux subscriptions that have been discovered. If you have linked your organization, the returned
     * results will include data aggregated across your accounts in Organizations.
     * </p>
     * 
     * @param listLinuxSubscriptionsRequest
     *        NextToken length limit is half of ddb accepted limit. Increase this limit if parameters in request
     *        increases.
     * @param asyncHandler
     *        Asynchronous callback handler for events in the lifecycle of the request. Users can provide an
     *        implementation of the callback methods in this interface to receive notification of successful or
     *        unsuccessful completion of the operation.
     * @return A Java Future containing the result of the ListLinuxSubscriptions operation returned by the service.
     * @sample AWSLicenseManagerLinuxSubscriptionsAsyncHandler.ListLinuxSubscriptions
     * @see <a
     *      href="http://docs.aws.amazon.com/goto/WebAPI/license-manager-linux-subscriptions-2018-05-10/ListLinuxSubscriptions"
     *      target="_top">AWS API Documentation</a>
     */
    java.util.concurrent.Future<ListLinuxSubscriptionsResult> listLinuxSubscriptionsAsync(ListLinuxSubscriptionsRequest listLinuxSubscriptionsRequest,
            com.amazonaws.handlers.AsyncHandler<ListLinuxSubscriptionsRequest, ListLinuxSubscriptionsResult> asyncHandler);

    /**
     * <p>
     * List Bring Your Own License (BYOL) subscription registration resources for your account.
     * </p>
     * 
     * @param listRegisteredSubscriptionProvidersRequest
     * @return A Java Future containing the result of the ListRegisteredSubscriptionProviders operation returned by the
     *         service.
     * @sample AWSLicenseManagerLinuxSubscriptionsAsync.ListRegisteredSubscriptionProviders
     * @see <a
     *      href="http://docs.aws.amazon.com/goto/WebAPI/license-manager-linux-subscriptions-2018-05-10/ListRegisteredSubscriptionProviders"
     *      target="_top">AWS API Documentation</a>
     */
    java.util.concurrent.Future<ListRegisteredSubscriptionProvidersResult> listRegisteredSubscriptionProvidersAsync(
            ListRegisteredSubscriptionProvidersRequest listRegisteredSubscriptionProvidersRequest);

    /**
     * <p>
     * List Bring Your Own License (BYOL) subscription registration resources for your account.
     * </p>
     * 
     * @param listRegisteredSubscriptionProvidersRequest
     * @param asyncHandler
     *        Asynchronous callback handler for events in the lifecycle of the request. Users can provide an
     *        implementation of the callback methods in this interface to receive notification of successful or
     *        unsuccessful completion of the operation.
     * @return A Java Future containing the result of the ListRegisteredSubscriptionProviders operation returned by the
     *         service.
     * @sample AWSLicenseManagerLinuxSubscriptionsAsyncHandler.ListRegisteredSubscriptionProviders
     * @see <a
     *      href="http://docs.aws.amazon.com/goto/WebAPI/license-manager-linux-subscriptions-2018-05-10/ListRegisteredSubscriptionProviders"
     *      target="_top">AWS API Documentation</a>
     */
    java.util.concurrent.Future<ListRegisteredSubscriptionProvidersResult> listRegisteredSubscriptionProvidersAsync(
            ListRegisteredSubscriptionProvidersRequest listRegisteredSubscriptionProvidersRequest,
            com.amazonaws.handlers.AsyncHandler<ListRegisteredSubscriptionProvidersRequest, ListRegisteredSubscriptionProvidersResult> asyncHandler);

    /**
     * <p>
     * List the metadata tags that are assigned to the specified Amazon Web Services resource.
     * </p>
     * 
     * @param listTagsForResourceRequest
     * @return A Java Future containing the result of the ListTagsForResource operation returned by the service.
     * @sample AWSLicenseManagerLinuxSubscriptionsAsync.ListTagsForResource
     * @see <a
     *      href="http://docs.aws.amazon.com/goto/WebAPI/license-manager-linux-subscriptions-2018-05-10/ListTagsForResource"
     *      target="_top">AWS API Documentation</a>
     */
    java.util.concurrent.Future<ListTagsForResourceResult> listTagsForResourceAsync(ListTagsForResourceRequest listTagsForResourceRequest);

    /**
     * <p>
     * List the metadata tags that are assigned to the specified Amazon Web Services resource.
     * </p>
     * 
     * @param listTagsForResourceRequest
     * @param asyncHandler
     *        Asynchronous callback handler for events in the lifecycle of the request. Users can provide an
     *        implementation of the callback methods in this interface to receive notification of successful or
     *        unsuccessful completion of the operation.
     * @return A Java Future containing the result of the ListTagsForResource operation returned by the service.
     * @sample AWSLicenseManagerLinuxSubscriptionsAsyncHandler.ListTagsForResource
     * @see <a
     *      href="http://docs.aws.amazon.com/goto/WebAPI/license-manager-linux-subscriptions-2018-05-10/ListTagsForResource"
     *      target="_top">AWS API Documentation</a>
     */
    java.util.concurrent.Future<ListTagsForResourceResult> listTagsForResourceAsync(ListTagsForResourceRequest listTagsForResourceRequest,
            com.amazonaws.handlers.AsyncHandler<ListTagsForResourceRequest, ListTagsForResourceResult> asyncHandler);

    /**
     * <p>
     * Register the supported third-party subscription provider for your Bring Your Own License (BYOL) subscription.
     * </p>
     * 
     * @param registerSubscriptionProviderRequest
     * @return A Java Future containing the result of the RegisterSubscriptionProvider operation returned by the
     *         service.
     * @sample AWSLicenseManagerLinuxSubscriptionsAsync.RegisterSubscriptionProvider
     * @see <a
     *      href="http://docs.aws.amazon.com/goto/WebAPI/license-manager-linux-subscriptions-2018-05-10/RegisterSubscriptionProvider"
     *      target="_top">AWS API Documentation</a>
     */
    java.util.concurrent.Future<RegisterSubscriptionProviderResult> registerSubscriptionProviderAsync(
            RegisterSubscriptionProviderRequest registerSubscriptionProviderRequest);

    /**
     * <p>
     * Register the supported third-party subscription provider for your Bring Your Own License (BYOL) subscription.
     * </p>
     * 
     * @param registerSubscriptionProviderRequest
     * @param asyncHandler
     *        Asynchronous callback handler for events in the lifecycle of the request. Users can provide an
     *        implementation of the callback methods in this interface to receive notification of successful or
     *        unsuccessful completion of the operation.
     * @return A Java Future containing the result of the RegisterSubscriptionProvider operation returned by the
     *         service.
     * @sample AWSLicenseManagerLinuxSubscriptionsAsyncHandler.RegisterSubscriptionProvider
     * @see <a
     *      href="http://docs.aws.amazon.com/goto/WebAPI/license-manager-linux-subscriptions-2018-05-10/RegisterSubscriptionProvider"
     *      target="_top">AWS API Documentation</a>
     */
    java.util.concurrent.Future<RegisterSubscriptionProviderResult> registerSubscriptionProviderAsync(
            RegisterSubscriptionProviderRequest registerSubscriptionProviderRequest,
            com.amazonaws.handlers.AsyncHandler<RegisterSubscriptionProviderRequest, RegisterSubscriptionProviderResult> asyncHandler);

    /**
     * <p>
     * Add metadata tags to the specified Amazon Web Services resource.
     * </p>
     * 
     * @param tagResourceRequest
     * @return A Java Future containing the result of the TagResource operation returned by the service.
     * @sample AWSLicenseManagerLinuxSubscriptionsAsync.TagResource
     * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/license-manager-linux-subscriptions-2018-05-10/TagResource"
     *      target="_top">AWS API Documentation</a>
     */
    java.util.concurrent.Future<TagResourceResult> tagResourceAsync(TagResourceRequest tagResourceRequest);

    /**
     * <p>
     * Add metadata tags to the specified Amazon Web Services resource.
     * </p>
     * 
     * @param tagResourceRequest
     * @param asyncHandler
     *        Asynchronous callback handler for events in the lifecycle of the request. Users can provide an
     *        implementation of the callback methods in this interface to receive notification of successful or
     *        unsuccessful completion of the operation.
     * @return A Java Future containing the result of the TagResource operation returned by the service.
     * @sample AWSLicenseManagerLinuxSubscriptionsAsyncHandler.TagResource
     * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/license-manager-linux-subscriptions-2018-05-10/TagResource"
     *      target="_top">AWS API Documentation</a>
     */
    java.util.concurrent.Future<TagResourceResult> tagResourceAsync(TagResourceRequest tagResourceRequest,
            com.amazonaws.handlers.AsyncHandler<TagResourceRequest, TagResourceResult> asyncHandler);

    /**
     * <p>
     * Remove one or more metadata tag from the specified Amazon Web Services resource.
     * </p>
     * 
     * @param untagResourceRequest
     * @return A Java Future containing the result of the UntagResource operation returned by the service.
     * @sample AWSLicenseManagerLinuxSubscriptionsAsync.UntagResource
     * @see <a
     *      href="http://docs.aws.amazon.com/goto/WebAPI/license-manager-linux-subscriptions-2018-05-10/UntagResource"
     *      target="_top">AWS API Documentation</a>
     */
    java.util.concurrent.Future<UntagResourceResult> untagResourceAsync(UntagResourceRequest untagResourceRequest);

    /**
     * <p>
     * Remove one or more metadata tag from the specified Amazon Web Services resource.
     * </p>
     * 
     * @param untagResourceRequest
     * @param asyncHandler
     *        Asynchronous callback handler for events in the lifecycle of the request. Users can provide an
     *        implementation of the callback methods in this interface to receive notification of successful or
     *        unsuccessful completion of the operation.
     * @return A Java Future containing the result of the UntagResource operation returned by the service.
     * @sample AWSLicenseManagerLinuxSubscriptionsAsyncHandler.UntagResource
     * @see <a
     *      href="http://docs.aws.amazon.com/goto/WebAPI/license-manager-linux-subscriptions-2018-05-10/UntagResource"
     *      target="_top">AWS API Documentation</a>
     */
    java.util.concurrent.Future<UntagResourceResult> untagResourceAsync(UntagResourceRequest untagResourceRequest,
            com.amazonaws.handlers.AsyncHandler<UntagResourceRequest, UntagResourceResult> asyncHandler);

    /**
     * <p>
     * Updates the service settings for Linux subscriptions.
     * </p>
     * 
     * @param updateServiceSettingsRequest
     * @return A Java Future containing the result of the UpdateServiceSettings operation returned by the service.
     * @sample AWSLicenseManagerLinuxSubscriptionsAsync.UpdateServiceSettings
     * @see <a
     *      href="http://docs.aws.amazon.com/goto/WebAPI/license-manager-linux-subscriptions-2018-05-10/UpdateServiceSettings"
     *      target="_top">AWS API Documentation</a>
     */
    java.util.concurrent.Future<UpdateServiceSettingsResult> updateServiceSettingsAsync(UpdateServiceSettingsRequest updateServiceSettingsRequest);

    /**
     * <p>
     * Updates the service settings for Linux subscriptions.
     * </p>
     * 
     * @param updateServiceSettingsRequest
     * @param asyncHandler
     *        Asynchronous callback handler for events in the lifecycle of the request. Users can provide an
     *        implementation of the callback methods in this interface to receive notification of successful or
     *        unsuccessful completion of the operation.
     * @return A Java Future containing the result of the UpdateServiceSettings operation returned by the service.
     * @sample AWSLicenseManagerLinuxSubscriptionsAsyncHandler.UpdateServiceSettings
     * @see <a
     *      href="http://docs.aws.amazon.com/goto/WebAPI/license-manager-linux-subscriptions-2018-05-10/UpdateServiceSettings"
     *      target="_top">AWS API Documentation</a>
     */
    java.util.concurrent.Future<UpdateServiceSettingsResult> updateServiceSettingsAsync(UpdateServiceSettingsRequest updateServiceSettingsRequest,
            com.amazonaws.handlers.AsyncHandler<UpdateServiceSettingsRequest, UpdateServiceSettingsResult> asyncHandler);

}
