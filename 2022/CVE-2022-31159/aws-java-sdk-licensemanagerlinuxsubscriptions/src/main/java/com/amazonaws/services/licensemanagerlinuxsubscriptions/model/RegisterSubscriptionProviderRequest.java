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
package com.amazonaws.services.licensemanagerlinuxsubscriptions.model;

import java.io.Serializable;
import javax.annotation.Generated;

import com.amazonaws.AmazonWebServiceRequest;

/**
 * 
 * @see <a
 *      href="http://docs.aws.amazon.com/goto/WebAPI/license-manager-linux-subscriptions-2018-05-10/RegisterSubscriptionProvider"
 *      target="_top">AWS API Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class RegisterSubscriptionProviderRequest extends com.amazonaws.AmazonWebServiceRequest implements Serializable, Cloneable {

    /**
     * <p>
     * The Amazon Resource Name (ARN) of the secret where you've stored your subscription provider's access token. For
     * RHEL subscriptions managed through the Red Hat Subscription Manager (RHSM), the secret contains your Red Hat
     * Offline token.
     * </p>
     */
    private String secretArn;
    /**
     * <p>
     * The supported Linux subscription provider to register.
     * </p>
     */
    private String subscriptionProviderSource;
    /**
     * <p>
     * The metadata tags to assign to your registered Linux subscription provider resource.
     * </p>
     */
    private java.util.Map<String, String> tags;

    /**
     * <p>
     * The Amazon Resource Name (ARN) of the secret where you've stored your subscription provider's access token. For
     * RHEL subscriptions managed through the Red Hat Subscription Manager (RHSM), the secret contains your Red Hat
     * Offline token.
     * </p>
     * 
     * @param secretArn
     *        The Amazon Resource Name (ARN) of the secret where you've stored your subscription provider's access
     *        token. For RHEL subscriptions managed through the Red Hat Subscription Manager (RHSM), the secret contains
     *        your Red Hat Offline token.
     */

    public void setSecretArn(String secretArn) {
        this.secretArn = secretArn;
    }

    /**
     * <p>
     * The Amazon Resource Name (ARN) of the secret where you've stored your subscription provider's access token. For
     * RHEL subscriptions managed through the Red Hat Subscription Manager (RHSM), the secret contains your Red Hat
     * Offline token.
     * </p>
     * 
     * @return The Amazon Resource Name (ARN) of the secret where you've stored your subscription provider's access
     *         token. For RHEL subscriptions managed through the Red Hat Subscription Manager (RHSM), the secret
     *         contains your Red Hat Offline token.
     */

    public String getSecretArn() {
        return this.secretArn;
    }

    /**
     * <p>
     * The Amazon Resource Name (ARN) of the secret where you've stored your subscription provider's access token. For
     * RHEL subscriptions managed through the Red Hat Subscription Manager (RHSM), the secret contains your Red Hat
     * Offline token.
     * </p>
     * 
     * @param secretArn
     *        The Amazon Resource Name (ARN) of the secret where you've stored your subscription provider's access
     *        token. For RHEL subscriptions managed through the Red Hat Subscription Manager (RHSM), the secret contains
     *        your Red Hat Offline token.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public RegisterSubscriptionProviderRequest withSecretArn(String secretArn) {
        setSecretArn(secretArn);
        return this;
    }

    /**
     * <p>
     * The supported Linux subscription provider to register.
     * </p>
     * 
     * @param subscriptionProviderSource
     *        The supported Linux subscription provider to register.
     * @see SubscriptionProviderSource
     */

    public void setSubscriptionProviderSource(String subscriptionProviderSource) {
        this.subscriptionProviderSource = subscriptionProviderSource;
    }

    /**
     * <p>
     * The supported Linux subscription provider to register.
     * </p>
     * 
     * @return The supported Linux subscription provider to register.
     * @see SubscriptionProviderSource
     */

    public String getSubscriptionProviderSource() {
        return this.subscriptionProviderSource;
    }

    /**
     * <p>
     * The supported Linux subscription provider to register.
     * </p>
     * 
     * @param subscriptionProviderSource
     *        The supported Linux subscription provider to register.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see SubscriptionProviderSource
     */

    public RegisterSubscriptionProviderRequest withSubscriptionProviderSource(String subscriptionProviderSource) {
        setSubscriptionProviderSource(subscriptionProviderSource);
        return this;
    }

    /**
     * <p>
     * The supported Linux subscription provider to register.
     * </p>
     * 
     * @param subscriptionProviderSource
     *        The supported Linux subscription provider to register.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see SubscriptionProviderSource
     */

    public RegisterSubscriptionProviderRequest withSubscriptionProviderSource(SubscriptionProviderSource subscriptionProviderSource) {
        this.subscriptionProviderSource = subscriptionProviderSource.toString();
        return this;
    }

    /**
     * <p>
     * The metadata tags to assign to your registered Linux subscription provider resource.
     * </p>
     * 
     * @return The metadata tags to assign to your registered Linux subscription provider resource.
     */

    public java.util.Map<String, String> getTags() {
        return tags;
    }

    /**
     * <p>
     * The metadata tags to assign to your registered Linux subscription provider resource.
     * </p>
     * 
     * @param tags
     *        The metadata tags to assign to your registered Linux subscription provider resource.
     */

    public void setTags(java.util.Map<String, String> tags) {
        this.tags = tags;
    }

    /**
     * <p>
     * The metadata tags to assign to your registered Linux subscription provider resource.
     * </p>
     * 
     * @param tags
     *        The metadata tags to assign to your registered Linux subscription provider resource.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public RegisterSubscriptionProviderRequest withTags(java.util.Map<String, String> tags) {
        setTags(tags);
        return this;
    }

    /**
     * Add a single Tags entry
     *
     * @see RegisterSubscriptionProviderRequest#withTags
     * @returns a reference to this object so that method calls can be chained together.
     */

    public RegisterSubscriptionProviderRequest addTagsEntry(String key, String value) {
        if (null == this.tags) {
            this.tags = new java.util.HashMap<String, String>();
        }
        if (this.tags.containsKey(key))
            throw new IllegalArgumentException("Duplicated keys (" + key.toString() + ") are provided.");
        this.tags.put(key, value);
        return this;
    }

    /**
     * Removes all the entries added into Tags.
     *
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public RegisterSubscriptionProviderRequest clearTagsEntries() {
        this.tags = null;
        return this;
    }

    /**
     * Returns a string representation of this object. This is useful for testing and debugging. Sensitive data will be
     * redacted from this string using a placeholder value.
     *
     * @return A string representation of this object.
     *
     * @see java.lang.Object#toString()
     */
    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("{");
        if (getSecretArn() != null)
            sb.append("SecretArn: ").append(getSecretArn()).append(",");
        if (getSubscriptionProviderSource() != null)
            sb.append("SubscriptionProviderSource: ").append(getSubscriptionProviderSource()).append(",");
        if (getTags() != null)
            sb.append("Tags: ").append("***Sensitive Data Redacted***");
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof RegisterSubscriptionProviderRequest == false)
            return false;
        RegisterSubscriptionProviderRequest other = (RegisterSubscriptionProviderRequest) obj;
        if (other.getSecretArn() == null ^ this.getSecretArn() == null)
            return false;
        if (other.getSecretArn() != null && other.getSecretArn().equals(this.getSecretArn()) == false)
            return false;
        if (other.getSubscriptionProviderSource() == null ^ this.getSubscriptionProviderSource() == null)
            return false;
        if (other.getSubscriptionProviderSource() != null && other.getSubscriptionProviderSource().equals(this.getSubscriptionProviderSource()) == false)
            return false;
        if (other.getTags() == null ^ this.getTags() == null)
            return false;
        if (other.getTags() != null && other.getTags().equals(this.getTags()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getSecretArn() == null) ? 0 : getSecretArn().hashCode());
        hashCode = prime * hashCode + ((getSubscriptionProviderSource() == null) ? 0 : getSubscriptionProviderSource().hashCode());
        hashCode = prime * hashCode + ((getTags() == null) ? 0 : getTags().hashCode());
        return hashCode;
    }

    @Override
    public RegisterSubscriptionProviderRequest clone() {
        return (RegisterSubscriptionProviderRequest) super.clone();
    }

}
