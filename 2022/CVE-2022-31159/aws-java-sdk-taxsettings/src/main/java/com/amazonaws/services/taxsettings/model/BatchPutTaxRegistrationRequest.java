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

import com.amazonaws.AmazonWebServiceRequest;

/**
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/taxsettings-2018-05-10/BatchPutTaxRegistration"
 *      target="_top">AWS API Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class BatchPutTaxRegistrationRequest extends com.amazonaws.AmazonWebServiceRequest implements Serializable, Cloneable {

    /**
     * <p>
     * List of unique account identifiers.
     * </p>
     */
    private java.util.List<String> accountIds;
    /**
     * <p>
     * Your TRN information that will be stored to the accounts mentioned in <code>putEntries</code>.
     * </p>
     */
    private TaxRegistrationEntry taxRegistrationEntry;

    /**
     * <p>
     * List of unique account identifiers.
     * </p>
     * 
     * @return List of unique account identifiers.
     */

    public java.util.List<String> getAccountIds() {
        return accountIds;
    }

    /**
     * <p>
     * List of unique account identifiers.
     * </p>
     * 
     * @param accountIds
     *        List of unique account identifiers.
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
     * List of unique account identifiers.
     * </p>
     * <p>
     * <b>NOTE:</b> This method appends the values to the existing list (if any). Use
     * {@link #setAccountIds(java.util.Collection)} or {@link #withAccountIds(java.util.Collection)} if you want to
     * override the existing values.
     * </p>
     * 
     * @param accountIds
     *        List of unique account identifiers.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public BatchPutTaxRegistrationRequest withAccountIds(String... accountIds) {
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
     * List of unique account identifiers.
     * </p>
     * 
     * @param accountIds
     *        List of unique account identifiers.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public BatchPutTaxRegistrationRequest withAccountIds(java.util.Collection<String> accountIds) {
        setAccountIds(accountIds);
        return this;
    }

    /**
     * <p>
     * Your TRN information that will be stored to the accounts mentioned in <code>putEntries</code>.
     * </p>
     * 
     * @param taxRegistrationEntry
     *        Your TRN information that will be stored to the accounts mentioned in <code>putEntries</code>.
     */

    public void setTaxRegistrationEntry(TaxRegistrationEntry taxRegistrationEntry) {
        this.taxRegistrationEntry = taxRegistrationEntry;
    }

    /**
     * <p>
     * Your TRN information that will be stored to the accounts mentioned in <code>putEntries</code>.
     * </p>
     * 
     * @return Your TRN information that will be stored to the accounts mentioned in <code>putEntries</code>.
     */

    public TaxRegistrationEntry getTaxRegistrationEntry() {
        return this.taxRegistrationEntry;
    }

    /**
     * <p>
     * Your TRN information that will be stored to the accounts mentioned in <code>putEntries</code>.
     * </p>
     * 
     * @param taxRegistrationEntry
     *        Your TRN information that will be stored to the accounts mentioned in <code>putEntries</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public BatchPutTaxRegistrationRequest withTaxRegistrationEntry(TaxRegistrationEntry taxRegistrationEntry) {
        setTaxRegistrationEntry(taxRegistrationEntry);
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
        if (getTaxRegistrationEntry() != null)
            sb.append("TaxRegistrationEntry: ").append("***Sensitive Data Redacted***");
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof BatchPutTaxRegistrationRequest == false)
            return false;
        BatchPutTaxRegistrationRequest other = (BatchPutTaxRegistrationRequest) obj;
        if (other.getAccountIds() == null ^ this.getAccountIds() == null)
            return false;
        if (other.getAccountIds() != null && other.getAccountIds().equals(this.getAccountIds()) == false)
            return false;
        if (other.getTaxRegistrationEntry() == null ^ this.getTaxRegistrationEntry() == null)
            return false;
        if (other.getTaxRegistrationEntry() != null && other.getTaxRegistrationEntry().equals(this.getTaxRegistrationEntry()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getAccountIds() == null) ? 0 : getAccountIds().hashCode());
        hashCode = prime * hashCode + ((getTaxRegistrationEntry() == null) ? 0 : getTaxRegistrationEntry().hashCode());
        return hashCode;
    }

    @Override
    public BatchPutTaxRegistrationRequest clone() {
        return (BatchPutTaxRegistrationRequest) super.clone();
    }

}
