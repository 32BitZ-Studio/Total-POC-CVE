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
 *      href="http://docs.aws.amazon.com/goto/WebAPI/license-manager-linux-subscriptions-2018-05-10/ListRegisteredSubscriptionProviders"
 *      target="_top">AWS API Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class ListRegisteredSubscriptionProvidersResult extends com.amazonaws.AmazonWebServiceResult<com.amazonaws.ResponseMetadata> implements Serializable,
        Cloneable {

    /**
     * <p>
     * The next token used for paginated responses. When this field isn't empty, there are additional elements that the
     * service hasn't included in this request. Use this token with the next request to retrieve additional objects.
     * </p>
     */
    private String nextToken;
    /**
     * <p>
     * The list of BYOL registration resources that fit the criteria you specified in the request.
     * </p>
     */
    private java.util.List<RegisteredSubscriptionProvider> registeredSubscriptionProviders;

    /**
     * <p>
     * The next token used for paginated responses. When this field isn't empty, there are additional elements that the
     * service hasn't included in this request. Use this token with the next request to retrieve additional objects.
     * </p>
     * 
     * @param nextToken
     *        The next token used for paginated responses. When this field isn't empty, there are additional elements
     *        that the service hasn't included in this request. Use this token with the next request to retrieve
     *        additional objects.
     */

    public void setNextToken(String nextToken) {
        this.nextToken = nextToken;
    }

    /**
     * <p>
     * The next token used for paginated responses. When this field isn't empty, there are additional elements that the
     * service hasn't included in this request. Use this token with the next request to retrieve additional objects.
     * </p>
     * 
     * @return The next token used for paginated responses. When this field isn't empty, there are additional elements
     *         that the service hasn't included in this request. Use this token with the next request to retrieve
     *         additional objects.
     */

    public String getNextToken() {
        return this.nextToken;
    }

    /**
     * <p>
     * The next token used for paginated responses. When this field isn't empty, there are additional elements that the
     * service hasn't included in this request. Use this token with the next request to retrieve additional objects.
     * </p>
     * 
     * @param nextToken
     *        The next token used for paginated responses. When this field isn't empty, there are additional elements
     *        that the service hasn't included in this request. Use this token with the next request to retrieve
     *        additional objects.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ListRegisteredSubscriptionProvidersResult withNextToken(String nextToken) {
        setNextToken(nextToken);
        return this;
    }

    /**
     * <p>
     * The list of BYOL registration resources that fit the criteria you specified in the request.
     * </p>
     * 
     * @return The list of BYOL registration resources that fit the criteria you specified in the request.
     */

    public java.util.List<RegisteredSubscriptionProvider> getRegisteredSubscriptionProviders() {
        return registeredSubscriptionProviders;
    }

    /**
     * <p>
     * The list of BYOL registration resources that fit the criteria you specified in the request.
     * </p>
     * 
     * @param registeredSubscriptionProviders
     *        The list of BYOL registration resources that fit the criteria you specified in the request.
     */

    public void setRegisteredSubscriptionProviders(java.util.Collection<RegisteredSubscriptionProvider> registeredSubscriptionProviders) {
        if (registeredSubscriptionProviders == null) {
            this.registeredSubscriptionProviders = null;
            return;
        }

        this.registeredSubscriptionProviders = new java.util.ArrayList<RegisteredSubscriptionProvider>(registeredSubscriptionProviders);
    }

    /**
     * <p>
     * The list of BYOL registration resources that fit the criteria you specified in the request.
     * </p>
     * <p>
     * <b>NOTE:</b> This method appends the values to the existing list (if any). Use
     * {@link #setRegisteredSubscriptionProviders(java.util.Collection)} or
     * {@link #withRegisteredSubscriptionProviders(java.util.Collection)} if you want to override the existing values.
     * </p>
     * 
     * @param registeredSubscriptionProviders
     *        The list of BYOL registration resources that fit the criteria you specified in the request.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ListRegisteredSubscriptionProvidersResult withRegisteredSubscriptionProviders(RegisteredSubscriptionProvider... registeredSubscriptionProviders) {
        if (this.registeredSubscriptionProviders == null) {
            setRegisteredSubscriptionProviders(new java.util.ArrayList<RegisteredSubscriptionProvider>(registeredSubscriptionProviders.length));
        }
        for (RegisteredSubscriptionProvider ele : registeredSubscriptionProviders) {
            this.registeredSubscriptionProviders.add(ele);
        }
        return this;
    }

    /**
     * <p>
     * The list of BYOL registration resources that fit the criteria you specified in the request.
     * </p>
     * 
     * @param registeredSubscriptionProviders
     *        The list of BYOL registration resources that fit the criteria you specified in the request.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ListRegisteredSubscriptionProvidersResult withRegisteredSubscriptionProviders(
            java.util.Collection<RegisteredSubscriptionProvider> registeredSubscriptionProviders) {
        setRegisteredSubscriptionProviders(registeredSubscriptionProviders);
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
        if (getNextToken() != null)
            sb.append("NextToken: ").append(getNextToken()).append(",");
        if (getRegisteredSubscriptionProviders() != null)
            sb.append("RegisteredSubscriptionProviders: ").append(getRegisteredSubscriptionProviders());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof ListRegisteredSubscriptionProvidersResult == false)
            return false;
        ListRegisteredSubscriptionProvidersResult other = (ListRegisteredSubscriptionProvidersResult) obj;
        if (other.getNextToken() == null ^ this.getNextToken() == null)
            return false;
        if (other.getNextToken() != null && other.getNextToken().equals(this.getNextToken()) == false)
            return false;
        if (other.getRegisteredSubscriptionProviders() == null ^ this.getRegisteredSubscriptionProviders() == null)
            return false;
        if (other.getRegisteredSubscriptionProviders() != null
                && other.getRegisteredSubscriptionProviders().equals(this.getRegisteredSubscriptionProviders()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getNextToken() == null) ? 0 : getNextToken().hashCode());
        hashCode = prime * hashCode + ((getRegisteredSubscriptionProviders() == null) ? 0 : getRegisteredSubscriptionProviders().hashCode());
        return hashCode;
    }

    @Override
    public ListRegisteredSubscriptionProvidersResult clone() {
        try {
            return (ListRegisteredSubscriptionProvidersResult) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

}
