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
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/taxsettings-2018-05-10/PutTaxRegistration" target="_top">AWS API
 *      Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class PutTaxRegistrationRequest extends com.amazonaws.AmazonWebServiceRequest implements Serializable, Cloneable {

    /**
     * <p>
     * Your unique account identifier.
     * </p>
     */
    private String accountId;
    /**
     * <p>
     * Your TRN information that will be stored to the account mentioned in <code>accountId</code>.
     * </p>
     */
    private TaxRegistrationEntry taxRegistrationEntry;

    /**
     * <p>
     * Your unique account identifier.
     * </p>
     * 
     * @param accountId
     *        Your unique account identifier.
     */

    public void setAccountId(String accountId) {
        this.accountId = accountId;
    }

    /**
     * <p>
     * Your unique account identifier.
     * </p>
     * 
     * @return Your unique account identifier.
     */

    public String getAccountId() {
        return this.accountId;
    }

    /**
     * <p>
     * Your unique account identifier.
     * </p>
     * 
     * @param accountId
     *        Your unique account identifier.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public PutTaxRegistrationRequest withAccountId(String accountId) {
        setAccountId(accountId);
        return this;
    }

    /**
     * <p>
     * Your TRN information that will be stored to the account mentioned in <code>accountId</code>.
     * </p>
     * 
     * @param taxRegistrationEntry
     *        Your TRN information that will be stored to the account mentioned in <code>accountId</code>.
     */

    public void setTaxRegistrationEntry(TaxRegistrationEntry taxRegistrationEntry) {
        this.taxRegistrationEntry = taxRegistrationEntry;
    }

    /**
     * <p>
     * Your TRN information that will be stored to the account mentioned in <code>accountId</code>.
     * </p>
     * 
     * @return Your TRN information that will be stored to the account mentioned in <code>accountId</code>.
     */

    public TaxRegistrationEntry getTaxRegistrationEntry() {
        return this.taxRegistrationEntry;
    }

    /**
     * <p>
     * Your TRN information that will be stored to the account mentioned in <code>accountId</code>.
     * </p>
     * 
     * @param taxRegistrationEntry
     *        Your TRN information that will be stored to the account mentioned in <code>accountId</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public PutTaxRegistrationRequest withTaxRegistrationEntry(TaxRegistrationEntry taxRegistrationEntry) {
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
        if (getAccountId() != null)
            sb.append("AccountId: ").append(getAccountId()).append(",");
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

        if (obj instanceof PutTaxRegistrationRequest == false)
            return false;
        PutTaxRegistrationRequest other = (PutTaxRegistrationRequest) obj;
        if (other.getAccountId() == null ^ this.getAccountId() == null)
            return false;
        if (other.getAccountId() != null && other.getAccountId().equals(this.getAccountId()) == false)
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

        hashCode = prime * hashCode + ((getAccountId() == null) ? 0 : getAccountId().hashCode());
        hashCode = prime * hashCode + ((getTaxRegistrationEntry() == null) ? 0 : getTaxRegistrationEntry().hashCode());
        return hashCode;
    }

    @Override
    public PutTaxRegistrationRequest clone() {
        return (PutTaxRegistrationRequest) super.clone();
    }

}
