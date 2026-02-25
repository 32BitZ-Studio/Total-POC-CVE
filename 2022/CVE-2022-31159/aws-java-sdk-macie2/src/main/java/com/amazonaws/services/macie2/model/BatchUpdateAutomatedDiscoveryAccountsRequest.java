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
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/macie2-2020-01-01/BatchUpdateAutomatedDiscoveryAccounts"
 *      target="_top">AWS API Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class BatchUpdateAutomatedDiscoveryAccountsRequest extends com.amazonaws.AmazonWebServiceRequest implements Serializable, Cloneable {

    /**
     * <p>
     * An array of objects, one for each account to change the status of automated sensitive data discovery for. Each
     * object specifies the Amazon Web Services account ID for an account and a new status for that account.
     * </p>
     */
    private java.util.List<AutomatedDiscoveryAccountUpdate> accounts;

    /**
     * <p>
     * An array of objects, one for each account to change the status of automated sensitive data discovery for. Each
     * object specifies the Amazon Web Services account ID for an account and a new status for that account.
     * </p>
     * 
     * @return An array of objects, one for each account to change the status of automated sensitive data discovery for.
     *         Each object specifies the Amazon Web Services account ID for an account and a new status for that
     *         account.
     */

    public java.util.List<AutomatedDiscoveryAccountUpdate> getAccounts() {
        return accounts;
    }

    /**
     * <p>
     * An array of objects, one for each account to change the status of automated sensitive data discovery for. Each
     * object specifies the Amazon Web Services account ID for an account and a new status for that account.
     * </p>
     * 
     * @param accounts
     *        An array of objects, one for each account to change the status of automated sensitive data discovery for.
     *        Each object specifies the Amazon Web Services account ID for an account and a new status for that account.
     */

    public void setAccounts(java.util.Collection<AutomatedDiscoveryAccountUpdate> accounts) {
        if (accounts == null) {
            this.accounts = null;
            return;
        }

        this.accounts = new java.util.ArrayList<AutomatedDiscoveryAccountUpdate>(accounts);
    }

    /**
     * <p>
     * An array of objects, one for each account to change the status of automated sensitive data discovery for. Each
     * object specifies the Amazon Web Services account ID for an account and a new status for that account.
     * </p>
     * <p>
     * <b>NOTE:</b> This method appends the values to the existing list (if any). Use
     * {@link #setAccounts(java.util.Collection)} or {@link #withAccounts(java.util.Collection)} if you want to override
     * the existing values.
     * </p>
     * 
     * @param accounts
     *        An array of objects, one for each account to change the status of automated sensitive data discovery for.
     *        Each object specifies the Amazon Web Services account ID for an account and a new status for that account.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public BatchUpdateAutomatedDiscoveryAccountsRequest withAccounts(AutomatedDiscoveryAccountUpdate... accounts) {
        if (this.accounts == null) {
            setAccounts(new java.util.ArrayList<AutomatedDiscoveryAccountUpdate>(accounts.length));
        }
        for (AutomatedDiscoveryAccountUpdate ele : accounts) {
            this.accounts.add(ele);
        }
        return this;
    }

    /**
     * <p>
     * An array of objects, one for each account to change the status of automated sensitive data discovery for. Each
     * object specifies the Amazon Web Services account ID for an account and a new status for that account.
     * </p>
     * 
     * @param accounts
     *        An array of objects, one for each account to change the status of automated sensitive data discovery for.
     *        Each object specifies the Amazon Web Services account ID for an account and a new status for that account.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public BatchUpdateAutomatedDiscoveryAccountsRequest withAccounts(java.util.Collection<AutomatedDiscoveryAccountUpdate> accounts) {
        setAccounts(accounts);
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
        if (getAccounts() != null)
            sb.append("Accounts: ").append(getAccounts());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof BatchUpdateAutomatedDiscoveryAccountsRequest == false)
            return false;
        BatchUpdateAutomatedDiscoveryAccountsRequest other = (BatchUpdateAutomatedDiscoveryAccountsRequest) obj;
        if (other.getAccounts() == null ^ this.getAccounts() == null)
            return false;
        if (other.getAccounts() != null && other.getAccounts().equals(this.getAccounts()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getAccounts() == null) ? 0 : getAccounts().hashCode());
        return hashCode;
    }

    @Override
    public BatchUpdateAutomatedDiscoveryAccountsRequest clone() {
        return (BatchUpdateAutomatedDiscoveryAccountsRequest) super.clone();
    }

}
