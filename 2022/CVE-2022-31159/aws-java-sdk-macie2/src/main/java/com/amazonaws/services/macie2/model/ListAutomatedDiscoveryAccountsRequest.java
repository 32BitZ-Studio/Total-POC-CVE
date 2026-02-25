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

import com.amazonaws.AmazonWebServiceRequest;

/**
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/macie2-2020-01-01/ListAutomatedDiscoveryAccounts"
 *      target="_top">AWS API Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class ListAutomatedDiscoveryAccountsRequest extends com.amazonaws.AmazonWebServiceRequest implements Serializable, Cloneable {

    /**
     * <p>
     * The Amazon Web Services account ID for each account, for as many as 50 accounts. To retrieve the status for
     * multiple accounts, append the accountIds parameter and argument for each account, separated by an ampersand
     * (&amp;). To retrieve the status for all the accounts in an organization, omit this parameter.
     * </p>
     */
    private java.util.List<String> accountIds;
    /**
     * <p>
     * The maximum number of items to include in each page of a paginated response.
     * </p>
     */
    private Integer maxResults;
    /**
     * <p>
     * The nextToken string that specifies which page of results to return in a paginated response.
     * </p>
     */
    private String nextToken;

    /**
     * <p>
     * The Amazon Web Services account ID for each account, for as many as 50 accounts. To retrieve the status for
     * multiple accounts, append the accountIds parameter and argument for each account, separated by an ampersand
     * (&amp;). To retrieve the status for all the accounts in an organization, omit this parameter.
     * </p>
     * 
     * @return The Amazon Web Services account ID for each account, for as many as 50 accounts. To retrieve the status
     *         for multiple accounts, append the accountIds parameter and argument for each account, separated by an
     *         ampersand (&amp;). To retrieve the status for all the accounts in an organization, omit this parameter.
     */

    public java.util.List<String> getAccountIds() {
        return accountIds;
    }

    /**
     * <p>
     * The Amazon Web Services account ID for each account, for as many as 50 accounts. To retrieve the status for
     * multiple accounts, append the accountIds parameter and argument for each account, separated by an ampersand
     * (&amp;). To retrieve the status for all the accounts in an organization, omit this parameter.
     * </p>
     * 
     * @param accountIds
     *        The Amazon Web Services account ID for each account, for as many as 50 accounts. To retrieve the status
     *        for multiple accounts, append the accountIds parameter and argument for each account, separated by an
     *        ampersand (&amp;). To retrieve the status for all the accounts in an organization, omit this parameter.
     */

    public void setAccountIds(java.util.Collection<String> accountIds) {
        if (accountIds == null) {
            this.accountIds = null;
            return;
        }

        this.accountIds = new java.util.ArrayList<String>(accountIds);
    }

    /**
     * <p>
     * The Amazon Web Services account ID for each account, for as many as 50 accounts. To retrieve the status for
     * multiple accounts, append the accountIds parameter and argument for each account, separated by an ampersand
     * (&amp;). To retrieve the status for all the accounts in an organization, omit this parameter.
     * </p>
     * <p>
     * <b>NOTE:</b> This method appends the values to the existing list (if any). Use
     * {@link #setAccountIds(java.util.Collection)} or {@link #withAccountIds(java.util.Collection)} if you want to
     * override the existing values.
     * </p>
     * 
     * @param accountIds
     *        The Amazon Web Services account ID for each account, for as many as 50 accounts. To retrieve the status
     *        for multiple accounts, append the accountIds parameter and argument for each account, separated by an
     *        ampersand (&amp;). To retrieve the status for all the accounts in an organization, omit this parameter.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ListAutomatedDiscoveryAccountsRequest withAccountIds(String... accountIds) {
        if (this.accountIds == null) {
            setAccountIds(new java.util.ArrayList<String>(accountIds.length));
        }
        for (String ele : accountIds) {
            this.accountIds.add(ele);
        }
        return this;
    }

    /**
     * <p>
     * The Amazon Web Services account ID for each account, for as many as 50 accounts. To retrieve the status for
     * multiple accounts, append the accountIds parameter and argument for each account, separated by an ampersand
     * (&amp;). To retrieve the status for all the accounts in an organization, omit this parameter.
     * </p>
     * 
     * @param accountIds
     *        The Amazon Web Services account ID for each account, for as many as 50 accounts. To retrieve the status
     *        for multiple accounts, append the accountIds parameter and argument for each account, separated by an
     *        ampersand (&amp;). To retrieve the status for all the accounts in an organization, omit this parameter.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ListAutomatedDiscoveryAccountsRequest withAccountIds(java.util.Collection<String> accountIds) {
        setAccountIds(accountIds);
        return this;
    }

    /**
     * <p>
     * The maximum number of items to include in each page of a paginated response.
     * </p>
     * 
     * @param maxResults
     *        The maximum number of items to include in each page of a paginated response.
     */

    public void setMaxResults(Integer maxResults) {
        this.maxResults = maxResults;
    }

    /**
     * <p>
     * The maximum number of items to include in each page of a paginated response.
     * </p>
     * 
     * @return The maximum number of items to include in each page of a paginated response.
     */

    public Integer getMaxResults() {
        return this.maxResults;
    }

    /**
     * <p>
     * The maximum number of items to include in each page of a paginated response.
     * </p>
     * 
     * @param maxResults
     *        The maximum number of items to include in each page of a paginated response.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ListAutomatedDiscoveryAccountsRequest withMaxResults(Integer maxResults) {
        setMaxResults(maxResults);
        return this;
    }

    /**
     * <p>
     * The nextToken string that specifies which page of results to return in a paginated response.
     * </p>
     * 
     * @param nextToken
     *        The nextToken string that specifies which page of results to return in a paginated response.
     */

    public void setNextToken(String nextToken) {
        this.nextToken = nextToken;
    }

    /**
     * <p>
     * The nextToken string that specifies which page of results to return in a paginated response.
     * </p>
     * 
     * @return The nextToken string that specifies which page of results to return in a paginated response.
     */

    public String getNextToken() {
        return this.nextToken;
    }

    /**
     * <p>
     * The nextToken string that specifies which page of results to return in a paginated response.
     * </p>
     * 
     * @param nextToken
     *        The nextToken string that specifies which page of results to return in a paginated response.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ListAutomatedDiscoveryAccountsRequest withNextToken(String nextToken) {
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
        if (getAccountIds() != null)
            sb.append("AccountIds: ").append(getAccountIds()).append(",");
        if (getMaxResults() != null)
            sb.append("MaxResults: ").append(getMaxResults()).append(",");
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

        if (obj instanceof ListAutomatedDiscoveryAccountsRequest == false)
            return false;
        ListAutomatedDiscoveryAccountsRequest other = (ListAutomatedDiscoveryAccountsRequest) obj;
        if (other.getAccountIds() == null ^ this.getAccountIds() == null)
            return false;
        if (other.getAccountIds() != null && other.getAccountIds().equals(this.getAccountIds()) == false)
            return false;
        if (other.getMaxResults() == null ^ this.getMaxResults() == null)
            return false;
        if (other.getMaxResults() != null && other.getMaxResults().equals(this.getMaxResults()) == false)
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

        hashCode = prime * hashCode + ((getAccountIds() == null) ? 0 : getAccountIds().hashCode());
        hashCode = prime * hashCode + ((getMaxResults() == null) ? 0 : getMaxResults().hashCode());
        hashCode = prime * hashCode + ((getNextToken() == null) ? 0 : getNextToken().hashCode());
        return hashCode;
    }

    @Override
    public ListAutomatedDiscoveryAccountsRequest clone() {
        return (ListAutomatedDiscoveryAccountsRequest) super.clone();
    }

}
