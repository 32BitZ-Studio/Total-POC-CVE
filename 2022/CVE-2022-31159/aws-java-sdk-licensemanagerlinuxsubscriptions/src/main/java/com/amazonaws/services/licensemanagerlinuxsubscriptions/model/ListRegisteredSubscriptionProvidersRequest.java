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
 *      href="http://docs.aws.amazon.com/goto/WebAPI/license-manager-linux-subscriptions-2018-05-10/ListRegisteredSubscriptionProviders"
 *      target="_top">AWS API Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class ListRegisteredSubscriptionProvidersRequest extends com.amazonaws.AmazonWebServiceRequest implements Serializable, Cloneable {

    /**
     * <p>
     * The maximum items to return in a request.
     * </p>
     */
    private Integer maxResults;
    /**
     * <p>
     * A token to specify where to start paginating. This is the nextToken from a previously truncated response.
     * </p>
     */
    private String nextToken;
    /**
     * <p>
     * To filter your results, specify which subscription providers to return in the list.
     * </p>
     */
    private java.util.List<String> subscriptionProviderSources;

    /**
     * <p>
     * The maximum items to return in a request.
     * </p>
     * 
     * @param maxResults
     *        The maximum items to return in a request.
     */

    public void setMaxResults(Integer maxResults) {
        this.maxResults = maxResults;
    }

    /**
     * <p>
     * The maximum items to return in a request.
     * </p>
     * 
     * @return The maximum items to return in a request.
     */

    public Integer getMaxResults() {
        return this.maxResults;
    }

    /**
     * <p>
     * The maximum items to return in a request.
     * </p>
     * 
     * @param maxResults
     *        The maximum items to return in a request.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ListRegisteredSubscriptionProvidersRequest withMaxResults(Integer maxResults) {
        setMaxResults(maxResults);
        return this;
    }

    /**
     * <p>
     * A token to specify where to start paginating. This is the nextToken from a previously truncated response.
     * </p>
     * 
     * @param nextToken
     *        A token to specify where to start paginating. This is the nextToken from a previously truncated response.
     */

    public void setNextToken(String nextToken) {
        this.nextToken = nextToken;
    }

    /**
     * <p>
     * A token to specify where to start paginating. This is the nextToken from a previously truncated response.
     * </p>
     * 
     * @return A token to specify where to start paginating. This is the nextToken from a previously truncated response.
     */

    public String getNextToken() {
        return this.nextToken;
    }

    /**
     * <p>
     * A token to specify where to start paginating. This is the nextToken from a previously truncated response.
     * </p>
     * 
     * @param nextToken
     *        A token to specify where to start paginating. This is the nextToken from a previously truncated response.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ListRegisteredSubscriptionProvidersRequest withNextToken(String nextToken) {
        setNextToken(nextToken);
        return this;
    }

    /**
     * <p>
     * To filter your results, specify which subscription providers to return in the list.
     * </p>
     * 
     * @return To filter your results, specify which subscription providers to return in the list.
     * @see SubscriptionProviderSource
     */

    public java.util.List<String> getSubscriptionProviderSources() {
        return subscriptionProviderSources;
    }

    /**
     * <p>
     * To filter your results, specify which subscription providers to return in the list.
     * </p>
     * 
     * @param subscriptionProviderSources
     *        To filter your results, specify which subscription providers to return in the list.
     * @see SubscriptionProviderSource
     */

    public void setSubscriptionProviderSources(java.util.Collection<String> subscriptionProviderSources) {
        if (subscriptionProviderSources == null) {
            this.subscriptionProviderSources = null;
            return;
        }

        this.subscriptionProviderSources = new java.util.ArrayList<String>(subscriptionProviderSources);
    }

    /**
     * <p>
     * To filter your results, specify which subscription providers to return in the list.
     * </p>
     * <p>
     * <b>NOTE:</b> This method appends the values to the existing list (if any). Use
     * {@link #setSubscriptionProviderSources(java.util.Collection)} or
     * {@link #withSubscriptionProviderSources(java.util.Collection)} if you want to override the existing values.
     * </p>
     * 
     * @param subscriptionProviderSources
     *        To filter your results, specify which subscription providers to return in the list.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see SubscriptionProviderSource
     */

    public ListRegisteredSubscriptionProvidersRequest withSubscriptionProviderSources(String... subscriptionProviderSources) {
        if (this.subscriptionProviderSources == null) {
            setSubscriptionProviderSources(new java.util.ArrayList<String>(subscriptionProviderSources.length));
        }
        for (String ele : subscriptionProviderSources) {
            this.subscriptionProviderSources.add(ele);
        }
        return this;
    }

    /**
     * <p>
     * To filter your results, specify which subscription providers to return in the list.
     * </p>
     * 
     * @param subscriptionProviderSources
     *        To filter your results, specify which subscription providers to return in the list.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see SubscriptionProviderSource
     */

    public ListRegisteredSubscriptionProvidersRequest withSubscriptionProviderSources(java.util.Collection<String> subscriptionProviderSources) {
        setSubscriptionProviderSources(subscriptionProviderSources);
        return this;
    }

    /**
     * <p>
     * To filter your results, specify which subscription providers to return in the list.
     * </p>
     * 
     * @param subscriptionProviderSources
     *        To filter your results, specify which subscription providers to return in the list.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see SubscriptionProviderSource
     */

    public ListRegisteredSubscriptionProvidersRequest withSubscriptionProviderSources(SubscriptionProviderSource... subscriptionProviderSources) {
        java.util.ArrayList<String> subscriptionProviderSourcesCopy = new java.util.ArrayList<String>(subscriptionProviderSources.length);
        for (SubscriptionProviderSource value : subscriptionProviderSources) {
            subscriptionProviderSourcesCopy.add(value.toString());
        }
        if (getSubscriptionProviderSources() == null) {
            setSubscriptionProviderSources(subscriptionProviderSourcesCopy);
        } else {
            getSubscriptionProviderSources().addAll(subscriptionProviderSourcesCopy);
        }
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
        if (getMaxResults() != null)
            sb.append("MaxResults: ").append(getMaxResults()).append(",");
        if (getNextToken() != null)
            sb.append("NextToken: ").append(getNextToken()).append(",");
        if (getSubscriptionProviderSources() != null)
            sb.append("SubscriptionProviderSources: ").append(getSubscriptionProviderSources());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof ListRegisteredSubscriptionProvidersRequest == false)
            return false;
        ListRegisteredSubscriptionProvidersRequest other = (ListRegisteredSubscriptionProvidersRequest) obj;
        if (other.getMaxResults() == null ^ this.getMaxResults() == null)
            return false;
        if (other.getMaxResults() != null && other.getMaxResults().equals(this.getMaxResults()) == false)
            return false;
        if (other.getNextToken() == null ^ this.getNextToken() == null)
            return false;
        if (other.getNextToken() != null && other.getNextToken().equals(this.getNextToken()) == false)
            return false;
        if (other.getSubscriptionProviderSources() == null ^ this.getSubscriptionProviderSources() == null)
            return false;
        if (other.getSubscriptionProviderSources() != null && other.getSubscriptionProviderSources().equals(this.getSubscriptionProviderSources()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getMaxResults() == null) ? 0 : getMaxResults().hashCode());
        hashCode = prime * hashCode + ((getNextToken() == null) ? 0 : getNextToken().hashCode());
        hashCode = prime * hashCode + ((getSubscriptionProviderSources() == null) ? 0 : getSubscriptionProviderSources().hashCode());
        return hashCode;
    }

    @Override
    public ListRegisteredSubscriptionProvidersRequest clone() {
        return (ListRegisteredSubscriptionProvidersRequest) super.clone();
    }

}
