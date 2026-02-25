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

/**
 * 
 * @see <a
 *      href="http://docs.aws.amazon.com/goto/WebAPI/license-manager-linux-subscriptions-2018-05-10/RegisterSubscriptionProvider"
 *      target="_top">AWS API Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class RegisterSubscriptionProviderResult extends com.amazonaws.AmazonWebServiceResult<com.amazonaws.ResponseMetadata> implements Serializable, Cloneable {

    /**
     * <p>
     * The Amazon Resource Name (ARN) of the Linux subscription provider resource that you registered.
     * </p>
     */
    private String subscriptionProviderArn;
    /**
     * <p>
     * The Linux subscription provider that you registered.
     * </p>
     */
    private String subscriptionProviderSource;
    /**
     * <p>
     * Indicates the status of the registration action for the Linux subscription provider that you requested.
     * </p>
     */
    private String subscriptionProviderStatus;

    /**
     * <p>
     * The Amazon Resource Name (ARN) of the Linux subscription provider resource that you registered.
     * </p>
     * 
     * @param subscriptionProviderArn
     *        The Amazon Resource Name (ARN) of the Linux subscription provider resource that you registered.
     */

    public void setSubscriptionProviderArn(String subscriptionProviderArn) {
        this.subscriptionProviderArn = subscriptionProviderArn;
    }

    /**
     * <p>
     * The Amazon Resource Name (ARN) of the Linux subscription provider resource that you registered.
     * </p>
     * 
     * @return The Amazon Resource Name (ARN) of the Linux subscription provider resource that you registered.
     */

    public String getSubscriptionProviderArn() {
        return this.subscriptionProviderArn;
    }

    /**
     * <p>
     * The Amazon Resource Name (ARN) of the Linux subscription provider resource that you registered.
     * </p>
     * 
     * @param subscriptionProviderArn
     *        The Amazon Resource Name (ARN) of the Linux subscription provider resource that you registered.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public RegisterSubscriptionProviderResult withSubscriptionProviderArn(String subscriptionProviderArn) {
        setSubscriptionProviderArn(subscriptionProviderArn);
        return this;
    }

    /**
     * <p>
     * The Linux subscription provider that you registered.
     * </p>
     * 
     * @param subscriptionProviderSource
     *        The Linux subscription provider that you registered.
     * @see SubscriptionProviderSource
     */

    public void setSubscriptionProviderSource(String subscriptionProviderSource) {
        this.subscriptionProviderSource = subscriptionProviderSource;
    }

    /**
     * <p>
     * The Linux subscription provider that you registered.
     * </p>
     * 
     * @return The Linux subscription provider that you registered.
     * @see SubscriptionProviderSource
     */

    public String getSubscriptionProviderSource() {
        return this.subscriptionProviderSource;
    }

    /**
     * <p>
     * The Linux subscription provider that you registered.
     * </p>
     * 
     * @param subscriptionProviderSource
     *        The Linux subscription provider that you registered.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see SubscriptionProviderSource
     */

    public RegisterSubscriptionProviderResult withSubscriptionProviderSource(String subscriptionProviderSource) {
        setSubscriptionProviderSource(subscriptionProviderSource);
        return this;
    }

    /**
     * <p>
     * The Linux subscription provider that you registered.
     * </p>
     * 
     * @param subscriptionProviderSource
     *        The Linux subscription provider that you registered.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see SubscriptionProviderSource
     */

    public RegisterSubscriptionProviderResult withSubscriptionProviderSource(SubscriptionProviderSource subscriptionProviderSource) {
        this.subscriptionProviderSource = subscriptionProviderSource.toString();
        return this;
    }

    /**
     * <p>
     * Indicates the status of the registration action for the Linux subscription provider that you requested.
     * </p>
     * 
     * @param subscriptionProviderStatus
     *        Indicates the status of the registration action for the Linux subscription provider that you requested.
     * @see SubscriptionProviderStatus
     */

    public void setSubscriptionProviderStatus(String subscriptionProviderStatus) {
        this.subscriptionProviderStatus = subscriptionProviderStatus;
    }

    /**
     * <p>
     * Indicates the status of the registration action for the Linux subscription provider that you requested.
     * </p>
     * 
     * @return Indicates the status of the registration action for the Linux subscription provider that you requested.
     * @see SubscriptionProviderStatus
     */

    public String getSubscriptionProviderStatus() {
        return this.subscriptionProviderStatus;
    }

    /**
     * <p>
     * Indicates the status of the registration action for the Linux subscription provider that you requested.
     * </p>
     * 
     * @param subscriptionProviderStatus
     *        Indicates the status of the registration action for the Linux subscription provider that you requested.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see SubscriptionProviderStatus
     */

    public RegisterSubscriptionProviderResult withSubscriptionProviderStatus(String subscriptionProviderStatus) {
        setSubscriptionProviderStatus(subscriptionProviderStatus);
        return this;
    }

    /**
     * <p>
     * Indicates the status of the registration action for the Linux subscription provider that you requested.
     * </p>
     * 
     * @param subscriptionProviderStatus
     *        Indicates the status of the registration action for the Linux subscription provider that you requested.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see SubscriptionProviderStatus
     */

    public RegisterSubscriptionProviderResult withSubscriptionProviderStatus(SubscriptionProviderStatus subscriptionProviderStatus) {
        this.subscriptionProviderStatus = subscriptionProviderStatus.toString();
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
        if (getSubscriptionProviderArn() != null)
            sb.append("SubscriptionProviderArn: ").append(getSubscriptionProviderArn()).append(",");
        if (getSubscriptionProviderSource() != null)
            sb.append("SubscriptionProviderSource: ").append(getSubscriptionProviderSource()).append(",");
        if (getSubscriptionProviderStatus() != null)
            sb.append("SubscriptionProviderStatus: ").append(getSubscriptionProviderStatus());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof RegisterSubscriptionProviderResult == false)
            return false;
        RegisterSubscriptionProviderResult other = (RegisterSubscriptionProviderResult) obj;
        if (other.getSubscriptionProviderArn() == null ^ this.getSubscriptionProviderArn() == null)
            return false;
        if (other.getSubscriptionProviderArn() != null && other.getSubscriptionProviderArn().equals(this.getSubscriptionProviderArn()) == false)
            return false;
        if (other.getSubscriptionProviderSource() == null ^ this.getSubscriptionProviderSource() == null)
            return false;
        if (other.getSubscriptionProviderSource() != null && other.getSubscriptionProviderSource().equals(this.getSubscriptionProviderSource()) == false)
            return false;
        if (other.getSubscriptionProviderStatus() == null ^ this.getSubscriptionProviderStatus() == null)
            return false;
        if (other.getSubscriptionProviderStatus() != null && other.getSubscriptionProviderStatus().equals(this.getSubscriptionProviderStatus()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getSubscriptionProviderArn() == null) ? 0 : getSubscriptionProviderArn().hashCode());
        hashCode = prime * hashCode + ((getSubscriptionProviderSource() == null) ? 0 : getSubscriptionProviderSource().hashCode());
        hashCode = prime * hashCode + ((getSubscriptionProviderStatus() == null) ? 0 : getSubscriptionProviderStatus().hashCode());
        return hashCode;
    }

    @Override
    public RegisterSubscriptionProviderResult clone() {
        try {
            return (RegisterSubscriptionProviderResult) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

}
