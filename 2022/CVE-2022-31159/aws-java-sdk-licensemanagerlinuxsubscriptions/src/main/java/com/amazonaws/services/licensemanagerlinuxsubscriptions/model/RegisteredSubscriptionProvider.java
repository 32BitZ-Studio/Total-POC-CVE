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
import com.amazonaws.protocol.StructuredPojo;
import com.amazonaws.protocol.ProtocolMarshaller;

/**
 * <p>
 * A third-party provider for operating system (OS) platform software and license subscriptions, such as Red Hat. When
 * you register a third-party Linux subscription provider, License Manager can get subscription data from the registered
 * provider.
 * </p>
 * 
 * @see <a
 *      href="http://docs.aws.amazon.com/goto/WebAPI/license-manager-linux-subscriptions-2018-05-10/RegisteredSubscriptionProvider"
 *      target="_top">AWS API Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class RegisteredSubscriptionProvider implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * The timestamp from the last time that License Manager accessed third-party subscription data for your account
     * from your registered Linux subscription provider.
     * </p>
     */
    private String lastSuccessfulDataRetrievalTime;
    /**
     * <p>
     * The Amazon Resource Name (ARN) of the Secrets Manager secret that stores your registered Linux subscription
     * provider access token. For RHEL account subscriptions, this is the offline token.
     * </p>
     */
    private String secretArn;
    /**
     * <p>
     * The Amazon Resource Name (ARN) of the Linux subscription provider resource that you registered.
     * </p>
     */
    private String subscriptionProviderArn;
    /**
     * <p>
     * A supported third-party Linux subscription provider. License Manager currently supports Red Hat subscriptions.
     * </p>
     */
    private String subscriptionProviderSource;
    /**
     * <p>
     * Indicates the status of your registered Linux subscription provider access token from the last time License
     * Manager retrieved subscription data. For RHEL account subscriptions, this is the status of the offline token.
     * </p>
     */
    private String subscriptionProviderStatus;
    /**
     * <p>
     * A detailed message that's associated with your BYOL subscription provider token status.
     * </p>
     */
    private String subscriptionProviderStatusMessage;

    /**
     * <p>
     * The timestamp from the last time that License Manager accessed third-party subscription data for your account
     * from your registered Linux subscription provider.
     * </p>
     * 
     * @param lastSuccessfulDataRetrievalTime
     *        The timestamp from the last time that License Manager accessed third-party subscription data for your
     *        account from your registered Linux subscription provider.
     */

    public void setLastSuccessfulDataRetrievalTime(String lastSuccessfulDataRetrievalTime) {
        this.lastSuccessfulDataRetrievalTime = lastSuccessfulDataRetrievalTime;
    }

    /**
     * <p>
     * The timestamp from the last time that License Manager accessed third-party subscription data for your account
     * from your registered Linux subscription provider.
     * </p>
     * 
     * @return The timestamp from the last time that License Manager accessed third-party subscription data for your
     *         account from your registered Linux subscription provider.
     */

    public String getLastSuccessfulDataRetrievalTime() {
        return this.lastSuccessfulDataRetrievalTime;
    }

    /**
     * <p>
     * The timestamp from the last time that License Manager accessed third-party subscription data for your account
     * from your registered Linux subscription provider.
     * </p>
     * 
     * @param lastSuccessfulDataRetrievalTime
     *        The timestamp from the last time that License Manager accessed third-party subscription data for your
     *        account from your registered Linux subscription provider.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public RegisteredSubscriptionProvider withLastSuccessfulDataRetrievalTime(String lastSuccessfulDataRetrievalTime) {
        setLastSuccessfulDataRetrievalTime(lastSuccessfulDataRetrievalTime);
        return this;
    }

    /**
     * <p>
     * The Amazon Resource Name (ARN) of the Secrets Manager secret that stores your registered Linux subscription
     * provider access token. For RHEL account subscriptions, this is the offline token.
     * </p>
     * 
     * @param secretArn
     *        The Amazon Resource Name (ARN) of the Secrets Manager secret that stores your registered Linux
     *        subscription provider access token. For RHEL account subscriptions, this is the offline token.
     */

    public void setSecretArn(String secretArn) {
        this.secretArn = secretArn;
    }

    /**
     * <p>
     * The Amazon Resource Name (ARN) of the Secrets Manager secret that stores your registered Linux subscription
     * provider access token. For RHEL account subscriptions, this is the offline token.
     * </p>
     * 
     * @return The Amazon Resource Name (ARN) of the Secrets Manager secret that stores your registered Linux
     *         subscription provider access token. For RHEL account subscriptions, this is the offline token.
     */

    public String getSecretArn() {
        return this.secretArn;
    }

    /**
     * <p>
     * The Amazon Resource Name (ARN) of the Secrets Manager secret that stores your registered Linux subscription
     * provider access token. For RHEL account subscriptions, this is the offline token.
     * </p>
     * 
     * @param secretArn
     *        The Amazon Resource Name (ARN) of the Secrets Manager secret that stores your registered Linux
     *        subscription provider access token. For RHEL account subscriptions, this is the offline token.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public RegisteredSubscriptionProvider withSecretArn(String secretArn) {
        setSecretArn(secretArn);
        return this;
    }

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

    public RegisteredSubscriptionProvider withSubscriptionProviderArn(String subscriptionProviderArn) {
        setSubscriptionProviderArn(subscriptionProviderArn);
        return this;
    }

    /**
     * <p>
     * A supported third-party Linux subscription provider. License Manager currently supports Red Hat subscriptions.
     * </p>
     * 
     * @param subscriptionProviderSource
     *        A supported third-party Linux subscription provider. License Manager currently supports Red Hat
     *        subscriptions.
     * @see SubscriptionProviderSource
     */

    public void setSubscriptionProviderSource(String subscriptionProviderSource) {
        this.subscriptionProviderSource = subscriptionProviderSource;
    }

    /**
     * <p>
     * A supported third-party Linux subscription provider. License Manager currently supports Red Hat subscriptions.
     * </p>
     * 
     * @return A supported third-party Linux subscription provider. License Manager currently supports Red Hat
     *         subscriptions.
     * @see SubscriptionProviderSource
     */

    public String getSubscriptionProviderSource() {
        return this.subscriptionProviderSource;
    }

    /**
     * <p>
     * A supported third-party Linux subscription provider. License Manager currently supports Red Hat subscriptions.
     * </p>
     * 
     * @param subscriptionProviderSource
     *        A supported third-party Linux subscription provider. License Manager currently supports Red Hat
     *        subscriptions.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see SubscriptionProviderSource
     */

    public RegisteredSubscriptionProvider withSubscriptionProviderSource(String subscriptionProviderSource) {
        setSubscriptionProviderSource(subscriptionProviderSource);
        return this;
    }

    /**
     * <p>
     * A supported third-party Linux subscription provider. License Manager currently supports Red Hat subscriptions.
     * </p>
     * 
     * @param subscriptionProviderSource
     *        A supported third-party Linux subscription provider. License Manager currently supports Red Hat
     *        subscriptions.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see SubscriptionProviderSource
     */

    public RegisteredSubscriptionProvider withSubscriptionProviderSource(SubscriptionProviderSource subscriptionProviderSource) {
        this.subscriptionProviderSource = subscriptionProviderSource.toString();
        return this;
    }

    /**
     * <p>
     * Indicates the status of your registered Linux subscription provider access token from the last time License
     * Manager retrieved subscription data. For RHEL account subscriptions, this is the status of the offline token.
     * </p>
     * 
     * @param subscriptionProviderStatus
     *        Indicates the status of your registered Linux subscription provider access token from the last time
     *        License Manager retrieved subscription data. For RHEL account subscriptions, this is the status of the
     *        offline token.
     * @see SubscriptionProviderStatus
     */

    public void setSubscriptionProviderStatus(String subscriptionProviderStatus) {
        this.subscriptionProviderStatus = subscriptionProviderStatus;
    }

    /**
     * <p>
     * Indicates the status of your registered Linux subscription provider access token from the last time License
     * Manager retrieved subscription data. For RHEL account subscriptions, this is the status of the offline token.
     * </p>
     * 
     * @return Indicates the status of your registered Linux subscription provider access token from the last time
     *         License Manager retrieved subscription data. For RHEL account subscriptions, this is the status of the
     *         offline token.
     * @see SubscriptionProviderStatus
     */

    public String getSubscriptionProviderStatus() {
        return this.subscriptionProviderStatus;
    }

    /**
     * <p>
     * Indicates the status of your registered Linux subscription provider access token from the last time License
     * Manager retrieved subscription data. For RHEL account subscriptions, this is the status of the offline token.
     * </p>
     * 
     * @param subscriptionProviderStatus
     *        Indicates the status of your registered Linux subscription provider access token from the last time
     *        License Manager retrieved subscription data. For RHEL account subscriptions, this is the status of the
     *        offline token.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see SubscriptionProviderStatus
     */

    public RegisteredSubscriptionProvider withSubscriptionProviderStatus(String subscriptionProviderStatus) {
        setSubscriptionProviderStatus(subscriptionProviderStatus);
        return this;
    }

    /**
     * <p>
     * Indicates the status of your registered Linux subscription provider access token from the last time License
     * Manager retrieved subscription data. For RHEL account subscriptions, this is the status of the offline token.
     * </p>
     * 
     * @param subscriptionProviderStatus
     *        Indicates the status of your registered Linux subscription provider access token from the last time
     *        License Manager retrieved subscription data. For RHEL account subscriptions, this is the status of the
     *        offline token.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see SubscriptionProviderStatus
     */

    public RegisteredSubscriptionProvider withSubscriptionProviderStatus(SubscriptionProviderStatus subscriptionProviderStatus) {
        this.subscriptionProviderStatus = subscriptionProviderStatus.toString();
        return this;
    }

    /**
     * <p>
     * A detailed message that's associated with your BYOL subscription provider token status.
     * </p>
     * 
     * @param subscriptionProviderStatusMessage
     *        A detailed message that's associated with your BYOL subscription provider token status.
     */

    public void setSubscriptionProviderStatusMessage(String subscriptionProviderStatusMessage) {
        this.subscriptionProviderStatusMessage = subscriptionProviderStatusMessage;
    }

    /**
     * <p>
     * A detailed message that's associated with your BYOL subscription provider token status.
     * </p>
     * 
     * @return A detailed message that's associated with your BYOL subscription provider token status.
     */

    public String getSubscriptionProviderStatusMessage() {
        return this.subscriptionProviderStatusMessage;
    }

    /**
     * <p>
     * A detailed message that's associated with your BYOL subscription provider token status.
     * </p>
     * 
     * @param subscriptionProviderStatusMessage
     *        A detailed message that's associated with your BYOL subscription provider token status.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public RegisteredSubscriptionProvider withSubscriptionProviderStatusMessage(String subscriptionProviderStatusMessage) {
        setSubscriptionProviderStatusMessage(subscriptionProviderStatusMessage);
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
        if (getLastSuccessfulDataRetrievalTime() != null)
            sb.append("LastSuccessfulDataRetrievalTime: ").append(getLastSuccessfulDataRetrievalTime()).append(",");
        if (getSecretArn() != null)
            sb.append("SecretArn: ").append(getSecretArn()).append(",");
        if (getSubscriptionProviderArn() != null)
            sb.append("SubscriptionProviderArn: ").append(getSubscriptionProviderArn()).append(",");
        if (getSubscriptionProviderSource() != null)
            sb.append("SubscriptionProviderSource: ").append(getSubscriptionProviderSource()).append(",");
        if (getSubscriptionProviderStatus() != null)
            sb.append("SubscriptionProviderStatus: ").append(getSubscriptionProviderStatus()).append(",");
        if (getSubscriptionProviderStatusMessage() != null)
            sb.append("SubscriptionProviderStatusMessage: ").append(getSubscriptionProviderStatusMessage());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof RegisteredSubscriptionProvider == false)
            return false;
        RegisteredSubscriptionProvider other = (RegisteredSubscriptionProvider) obj;
        if (other.getLastSuccessfulDataRetrievalTime() == null ^ this.getLastSuccessfulDataRetrievalTime() == null)
            return false;
        if (other.getLastSuccessfulDataRetrievalTime() != null
                && other.getLastSuccessfulDataRetrievalTime().equals(this.getLastSuccessfulDataRetrievalTime()) == false)
            return false;
        if (other.getSecretArn() == null ^ this.getSecretArn() == null)
            return false;
        if (other.getSecretArn() != null && other.getSecretArn().equals(this.getSecretArn()) == false)
            return false;
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
        if (other.getSubscriptionProviderStatusMessage() == null ^ this.getSubscriptionProviderStatusMessage() == null)
            return false;
        if (other.getSubscriptionProviderStatusMessage() != null
                && other.getSubscriptionProviderStatusMessage().equals(this.getSubscriptionProviderStatusMessage()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getLastSuccessfulDataRetrievalTime() == null) ? 0 : getLastSuccessfulDataRetrievalTime().hashCode());
        hashCode = prime * hashCode + ((getSecretArn() == null) ? 0 : getSecretArn().hashCode());
        hashCode = prime * hashCode + ((getSubscriptionProviderArn() == null) ? 0 : getSubscriptionProviderArn().hashCode());
        hashCode = prime * hashCode + ((getSubscriptionProviderSource() == null) ? 0 : getSubscriptionProviderSource().hashCode());
        hashCode = prime * hashCode + ((getSubscriptionProviderStatus() == null) ? 0 : getSubscriptionProviderStatus().hashCode());
        hashCode = prime * hashCode + ((getSubscriptionProviderStatusMessage() == null) ? 0 : getSubscriptionProviderStatusMessage().hashCode());
        return hashCode;
    }

    @Override
    public RegisteredSubscriptionProvider clone() {
        try {
            return (RegisteredSubscriptionProvider) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.licensemanagerlinuxsubscriptions.model.transform.RegisteredSubscriptionProviderMarshaller.getInstance().marshall(this,
                protocolMarshaller);
    }
}
