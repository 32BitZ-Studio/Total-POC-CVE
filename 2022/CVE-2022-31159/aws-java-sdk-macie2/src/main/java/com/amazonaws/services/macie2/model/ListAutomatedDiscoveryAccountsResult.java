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
package com.amazonaws.services.macie2.model;

import java.io.Serializable;
import javax.annotation.Generated;

/**
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/macie2-2020-01-01/ListAutomatedDiscoveryAccounts"
 *      target="_top">AWS API Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class ListAutomatedDiscoveryAccountsResult extends com.amazonaws.AmazonWebServiceResult<com.amazonaws.ResponseMetadata> implements Serializable,
        Cloneable {

    /**
     * <p>
     * An array of objects, one for each account specified in the request. Each object specifies the Amazon Web Services
     * account ID for an account and the current status of automated sensitive data discovery for that account.
     * </p>
     */
    private java.util.List<AutomatedDiscoveryAccount> items;
    /**
     * <p>
     * The string to use in a subsequent request to get the next page of results in a paginated response. This value is
     * null if there are no additional pages.
     * </p>
     */
    private String nextToken;

    /**
     * <p>
     * An array of objects, one for each account specified in the request. Each object specifies the Amazon Web Services
     * account ID for an account and the current status of automated sensitive data discovery for that account.
     * </p>
     * 
     * @return An array of objects, one for each account specified in the request. Each object specifies the Amazon Web
     *         Services account ID for an account and the current status of automated sensitive data discovery for that
     *         account.
     */

    public java.util.List<AutomatedDiscoveryAccount> getItems() {
        return items;
    }

    /**
     * <p>
     * An array of objects, one for each account specified in the request. Each object specifies the Amazon Web Services
     * account ID for an account and the current status of automated sensitive data discovery for that account.
     * </p>
     * 
     * @param items
     *        An array of objects, one for each account specified in the request. Each object specifies the Amazon Web
     *        Services account ID for an account and the current status of automated sensitive data discovery for that
     *        account.
     */

    public void setItems(java.util.Collection<AutomatedDiscoveryAccount> items) {
        if (items == null) {
            this.items = null;
            return;
        }

        this.items = new java.util.ArrayList<AutomatedDiscoveryAccount>(items);
    }

    /**
     * <p>
     * An array of objects, one for each account specified in the request. Each object specifies the Amazon Web Services
     * account ID for an account and the current status of automated sensitive data discovery for that account.
     * </p>
     * <p>
     * <b>NOTE:</b> This method appends the values to the existing list (if any). Use
     * {@link #setItems(java.util.Collection)} or {@link #withItems(java.util.Collection)} if you want to override the
     * existing values.
     * </p>
     * 
     * @param items
     *        An array of objects, one for each account specified in the request. Each object specifies the Amazon Web
     *        Services account ID for an account and the current status of automated sensitive data discovery for that
     *        account.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ListAutomatedDiscoveryAccountsResult withItems(AutomatedDiscoveryAccount... items) {
        if (this.items == null) {
            setItems(new java.util.ArrayList<AutomatedDiscoveryAccount>(items.length));
        }
        for (AutomatedDiscoveryAccount ele : items) {
            this.items.add(ele);
        }
        return this;
    }

    /**
     * <p>
     * An array of objects, one for each account specified in the request. Each object specifies the Amazon Web Services
     * account ID for an account and the current status of automated sensitive data discovery for that account.
     * </p>
     * 
     * @param items
     *        An array of objects, one for each account specified in the request. Each object specifies the Amazon Web
     *        Services account ID for an account and the current status of automated sensitive data discovery for that
     *        account.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ListAutomatedDiscoveryAccountsResult withItems(java.util.Collection<AutomatedDiscoveryAccount> items) {
        setItems(items);
        return this;
    }

    /**
     * <p>
     * The string to use in a subsequent request to get the next page of results in a paginated response. This value is
     * null if there are no additional pages.
     * </p>
     * 
     * @param nextToken
     *        The string to use in a subsequent request to get the next page of results in a paginated response. This
     *        value is null if there are no additional pages.
     */

    public void setNextToken(String nextToken) {
        this.nextToken = nextToken;
    }

    /**
     * <p>
     * The string to use in a subsequent request to get the next page of results in a paginated response. This value is
     * null if there are no additional pages.
     * </p>
     * 
     * @return The string to use in a subsequent request to get the next page of results in a paginated response. This
     *         value is null if there are no additional pages.
     */

    public String getNextToken() {
        return this.nextToken;
    }

    /**
     * <p>
     * The string to use in a subsequent request to get the next page of results in a paginated response. This value is
     * null if there are no additional pages.
     * </p>
     * 
     * @param nextToken
     *        The string to use in a subsequent request to get the next page of results in a paginated response. This
     *        value is null if there are no additional pages.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ListAutomatedDiscoveryAccountsResult withNextToken(String nextToken) {
        setNextToken(nextToken);
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
        if (getItems() != null)
            sb.append("Items: ").append(getItems()).append(",");
        if (getNextToken() != null)
            sb.append("NextToken: ").append(getNextToken());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof ListAutomatedDiscoveryAccountsResult == false)
            return false;
        ListAutomatedDiscoveryAccountsResult other = (ListAutomatedDiscoveryAccountsResult) obj;
        if (other.getItems() == null ^ this.getItems() == null)
            return false;
        if (other.getItems() != null && other.getItems().equals(this.getItems()) == false)
            return false;
        if (other.getNextToken() == null ^ this.getNextToken() == null)
            return false;
        if (other.getNextToken() != null && other.getNextToken().equals(this.getNextToken()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getItems() == null) ? 0 : getItems().hashCode());
        hashCode = prime * hashCode + ((getNextToken() == null) ? 0 : getNextToken().hashCode());
        return hashCode;
    }

    @Override
    public ListAutomatedDiscoveryAccountsResult clone() {
        try {
            return (ListAutomatedDiscoveryAccountsResult) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

}
