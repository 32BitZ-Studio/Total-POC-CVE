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
 * Abstract implementation of {@code AWSLicenseManagerLinuxSubscriptionsAsync}. Convenient method forms pass through to
 * the corresponding overload that takes a request object and an {@code AsyncHandler}, which throws an
 * {@code UnsupportedOperationException}.
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class AbstractAWSLicenseManagerLinuxSubscriptionsAsync extends AbstractAWSLicenseManagerLinuxSubscriptions implements
        AWSLicenseManagerLinuxSubscriptionsAsync {

    protected AbstractAWSLicenseManagerLinuxSubscriptionsAsync() {
    }

    @Override
    public java.util.concurrent.Future<DeregisterSubscriptionProviderResult> deregisterSubscriptionProviderAsync(DeregisterSubscriptionProviderRequest request) {

        return deregisterSubscriptionProviderAsync(request, null);
    }

    @Override
    public java.util.concurrent.Future<DeregisterSubscriptionProviderResult> deregisterSubscriptionProviderAsync(DeregisterSubscriptionProviderRequest request,
            com.amazonaws.handlers.AsyncHandler<DeregisterSubscriptionProviderRequest, DeregisterSubscriptionProviderResult> asyncHandler) {

        throw new java.lang.UnsupportedOperationException();
    }

    @Override
    public java.util.concurrent.Future<GetRegisteredSubscriptionProviderResult> getRegisteredSubscriptionProviderAsync(
            GetRegisteredSubscriptionProviderRequest request) {

        return getRegisteredSubscriptionProviderAsync(request, null);
    }

    @Override
    public java.util.concurrent.Future<GetRegisteredSubscriptionProviderResult> getRegisteredSubscriptionProviderAsync(
            GetRegisteredSubscriptionProviderRequest request,
            com.amazonaws.handlers.AsyncHandler<GetRegisteredSubscriptionProviderRequest, GetRegisteredSubscriptionProviderResult> asyncHandler) {

        throw new java.lang.UnsupportedOperationException();
    }

    @Override
    public java.util.concurrent.Future<GetServiceSettingsResult> getServiceSettingsAsync(GetServiceSettingsRequest request) {

        return getServiceSettingsAsync(request, null);
    }

    @Override
    public java.util.concurrent.Future<GetServiceSettingsResult> getServiceSettingsAsync(GetServiceSettingsRequest request,
            com.amazonaws.handlers.AsyncHandler<GetServiceSettingsRequest, GetServiceSettingsResult> asyncHandler) {

        throw new java.lang.UnsupportedOperationException();
    }

    @Override
    public java.util.concurrent.Future<ListLinuxSubscriptionInstancesResult> listLinuxSubscriptionInstancesAsync(ListLinuxSubscriptionInstancesRequest request) {

        return listLinuxSubscriptionInstancesAsync(request, null);
    }

    @Override
    public java.util.concurrent.Future<ListLinuxSubscriptionInstancesResult> listLinuxSubscriptionInstancesAsync(ListLinuxSubscriptionInstancesRequest request,
            com.amazonaws.handlers.AsyncHandler<ListLinuxSubscriptionInstancesRequest, ListLinuxSubscriptionInstancesResult> asyncHandler) {

        throw new java.lang.UnsupportedOperationException();
    }

    @Override
    public java.util.concurrent.Future<ListLinuxSubscriptionsResult> listLinuxSubscriptionsAsync(ListLinuxSubscriptionsRequest request) {

        return listLinuxSubscriptionsAsync(request, null);
    }

    @Override
    public java.util.concurrent.Future<ListLinuxSubscriptionsResult> listLinuxSubscriptionsAsync(ListLinuxSubscriptionsRequest request,
            com.amazonaws.handlers.AsyncHandler<ListLinuxSubscriptionsRequest, ListLinuxSubscriptionsResult> asyncHandler) {

        throw new java.lang.UnsupportedOperationException();
    }

    @Override
    public java.util.concurrent.Future<ListRegisteredSubscriptionProvidersResult> listRegisteredSubscriptionProvidersAsync(
            ListRegisteredSubscriptionProvidersRequest request) {

        return listRegisteredSubscriptionProvidersAsync(request, null);
    }

    @Override
    public java.util.concurrent.Future<ListRegisteredSubscriptionProvidersResult> listRegisteredSubscriptionProvidersAsync(
            ListRegisteredSubscriptionProvidersRequest request,
            com.amazonaws.handlers.AsyncHandler<ListRegisteredSubscriptionProvidersRequest, ListRegisteredSubscriptionProvidersResult> asyncHandler) {

        throw new java.lang.UnsupportedOperationException();
    }

    @Override
    public java.util.concurrent.Future<ListTagsForResourceResult> listTagsForResourceAsync(ListTagsForResourceRequest request) {

        return listTagsForResourceAsync(request, null);
    }

    @Override
    public java.util.concurrent.Future<ListTagsForResourceResult> listTagsForResourceAsync(ListTagsForResourceRequest request,
            com.amazonaws.handlers.AsyncHandler<ListTagsForResourceRequest, ListTagsForResourceResult> asyncHandler) {

        throw new java.lang.UnsupportedOperationException();
    }

    @Override
    public java.util.concurrent.Future<RegisterSubscriptionProviderResult> registerSubscriptionProviderAsync(RegisterSubscriptionProviderRequest request) {

        return registerSubscriptionProviderAsync(request, null);
    }

    @Override
    public java.util.concurrent.Future<RegisterSubscriptionProviderResult> registerSubscriptionProviderAsync(RegisterSubscriptionProviderRequest request,
            com.amazonaws.handlers.AsyncHandler<RegisterSubscriptionProviderRequest, RegisterSubscriptionProviderResult> asyncHandler) {

        throw new java.lang.UnsupportedOperationException();
    }

    @Override
    public java.util.concurrent.Future<TagResourceResult> tagResourceAsync(TagResourceRequest request) {

        return tagResourceAsync(request, null);
    }

    @Override
    public java.util.concurrent.Future<TagResourceResult> tagResourceAsync(TagResourceRequest request,
            com.amazonaws.handlers.AsyncHandler<TagResourceRequest, TagResourceResult> asyncHandler) {

        throw new java.lang.UnsupportedOperationException();
    }

    @Override
    public java.util.concurrent.Future<UntagResourceResult> untagResourceAsync(UntagResourceRequest request) {

        return untagResourceAsync(request, null);
    }

    @Override
    public java.util.concurrent.Future<UntagResourceResult> untagResourceAsync(UntagResourceRequest request,
            com.amazonaws.handlers.AsyncHandler<UntagResourceRequest, UntagResourceResult> asyncHandler) {

        throw new java.lang.UnsupportedOperationException();
    }

    @Override
    public java.util.concurrent.Future<UpdateServiceSettingsResult> updateServiceSettingsAsync(UpdateServiceSettingsRequest request) {

        return updateServiceSettingsAsync(request, null);
    }

    @Override
    public java.util.concurrent.Future<UpdateServiceSettingsResult> updateServiceSettingsAsync(UpdateServiceSettingsRequest request,
            com.amazonaws.handlers.AsyncHandler<UpdateServiceSettingsRequest, UpdateServiceSettingsResult> asyncHandler) {

        throw new java.lang.UnsupportedOperationException();
    }

}
