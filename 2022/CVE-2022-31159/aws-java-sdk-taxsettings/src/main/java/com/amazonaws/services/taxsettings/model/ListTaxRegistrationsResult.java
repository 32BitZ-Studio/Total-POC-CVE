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
package com.amazonaws.services.taxsettings.model;

import java.io.Serializable;
import javax.annotation.Generated;

/**
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/taxsettings-2018-05-10/ListTaxRegistrations" target="_top">AWS
 *      API Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class ListTaxRegistrationsResult extends com.amazonaws.AmazonWebServiceResult<com.amazonaws.ResponseMetadata> implements Serializable, Cloneable {

    /**
     * <p>
     * The list of account details. This contains account Ids and TRN Information for each of the linked accounts.
     * </p>
     */
    private java.util.List<AccountDetails> accountDetails;
    /**
     * <p>
     * The token to retrieve the next set of results.
     * </p>
     */
    private String nextToken;

    /**
     * <p>
     * The list of account details. This contains account Ids and TRN Information for each of the linked accounts.
     * </p>
     * 
     * @return The list of account details. This contains account Ids and TRN Information for each of the linked
     *         accounts.
     */

    public java.util.List<AccountDetails> getAccountDetails() {
        return accountDetails;
    }

    /**
     * <p>
     * The list of account details. This contains account Ids and TRN Information for each of the linked accounts.
     * </p>
     * 
     * @param accountDetails
     *        The list of account details. This contains account Ids and TRN Information for each of the linked
     *        accounts.
     */

    public void setAccountDetails(java.util.Collection<AccountDetails> accountDetails) {
        if (accountDetails == null) {
            this.accountDetails = null;
            return;
        }

        this.accountDetails = new java.util.ArrayList<AccountDetails>(accountDetails);
    }

    /**
     * <p>
     * The list of account details. This contains account Ids and TRN Information for each of the linked accounts.
     * </p>
     * <p>
     * <b>NOTE:</b> This method appends the values to the existing list (if any). Use
     * {@link #setAccountDetails(java.util.Collection)} or {@link #withAccountDetails(java.util.Collection)} if you want
     * to override the existing values.
     * </p>
     * 
     * @param accountDetails
     *        The list of account details. This contains account Ids and TRN Information for each of the linked
     *        accounts.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ListTaxRegistrationsResult withAccountDetails(AccountDetails... accountDetails) {
        if (this.accountDetails == null) {
            setAccountDetails(new java.util.ArrayList<AccountDetails>(accountDetails.length));
        }
        for (AccountDetails ele : accountDetails) {
            this.accountDetails.add(ele);
        }
        return this;
    }

    /**
     * <p>
     * The list of account details. This contains account Ids and TRN Information for each of the linked accounts.
     * </p>
     * 
     * @param accountDetails
     *        The list of account details. This contains account Ids and TRN Information for each of the linked
     *        accounts.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ListTaxRegistrationsResult withAccountDetails(java.util.Collection<AccountDetails> accountDetails) {
        setAccountDetails(accountDetails);
        return this;
    }

    /**
     * <p>
     * The token to retrieve the next set of results.
     * </p>
     * 
     * @param nextToken
     *        The token to retrieve the next set of results.
     */

    public void setNextToken(String nextToken) {
        this.nextToken = nextToken;
    }

    /**
     * <p>
     * The token to retrieve the next set of results.
     * </p>
     * 
     * @return The token to retrieve the next set of results.
     */

    public String getNextToken() {
        return this.nextToken;
    }

    /**
     * <p>
     * The token to retrieve the next set of results.
     * </p>
     * 
     * @param nextToken
     *        The token to retrieve the next set of results.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ListTaxRegistrationsResult withNextToken(String nextToken) {
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
        if (getAccountDetails() != null)
            sb.append("AccountDetails: ").append("***Sensitive Data Redacted***").append(",");
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

        if (obj instanceof ListTaxRegistrationsResult == false)
            return false;
        ListTaxRegistrationsResult other = (ListTaxRegistrationsResult) obj;
        if (other.getAccountDetails() == null ^ this.getAccountDetails() == null)
            return false;
        if (other.getAccountDetails() != null && other.getAccountDetails().equals(this.getAccountDetails()) == false)
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

        hashCode = prime * hashCode + ((getAccountDetails() == null) ? 0 : getAccountDetails().hashCode());
        hashCode = prime * hashCode + ((getNextToken() == null) ? 0 : getNextToken().hashCode());
        return hashCode;
    }

    @Override
    public ListTaxRegistrationsResult clone() {
        try {
            return (ListTaxRegistrationsResult) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

}
