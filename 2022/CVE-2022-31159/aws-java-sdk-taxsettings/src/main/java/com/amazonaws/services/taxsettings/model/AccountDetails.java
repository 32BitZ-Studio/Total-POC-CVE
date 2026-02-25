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
import com.amazonaws.protocol.StructuredPojo;
import com.amazonaws.protocol.ProtocolMarshaller;

/**
 * <p>
 * An object with your <code>accountId</code> and TRN information.
 * </p>
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/taxsettings-2018-05-10/AccountDetails" target="_top">AWS API
 *      Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class AccountDetails implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * List of unique account identifiers.
     * </p>
     */
    private String accountId;
    /**
     * <p>
     * The meta data information associated with the account.
     * </p>
     */
    private AccountMetaData accountMetaData;
    /**
     * <p>
     * Tax inheritance information associated with the account.
     * </p>
     */
    private TaxInheritanceDetails taxInheritanceDetails;
    /**
     * <p>
     * Your TRN information. Instead of having full legal address, here TRN information will have jurisdiction details
     * (for example, country code and state/region/province if applicable).
     * </p>
     */
    private TaxRegistrationWithJurisdiction taxRegistration;

    /**
     * <p>
     * List of unique account identifiers.
     * </p>
     * 
     * @param accountId
     *        List of unique account identifiers.
     */

    public void setAccountId(String accountId) {
        this.accountId = accountId;
    }

    /**
     * <p>
     * List of unique account identifiers.
     * </p>
     * 
     * @return List of unique account identifiers.
     */

    public String getAccountId() {
        return this.accountId;
    }

    /**
     * <p>
     * List of unique account identifiers.
     * </p>
     * 
     * @param accountId
     *        List of unique account identifiers.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public AccountDetails withAccountId(String accountId) {
        setAccountId(accountId);
        return this;
    }

    /**
     * <p>
     * The meta data information associated with the account.
     * </p>
     * 
     * @param accountMetaData
     *        The meta data information associated with the account.
     */

    public void setAccountMetaData(AccountMetaData accountMetaData) {
        this.accountMetaData = accountMetaData;
    }

    /**
     * <p>
     * The meta data information associated with the account.
     * </p>
     * 
     * @return The meta data information associated with the account.
     */

    public AccountMetaData getAccountMetaData() {
        return this.accountMetaData;
    }

    /**
     * <p>
     * The meta data information associated with the account.
     * </p>
     * 
     * @param accountMetaData
     *        The meta data information associated with the account.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public AccountDetails withAccountMetaData(AccountMetaData accountMetaData) {
        setAccountMetaData(accountMetaData);
        return this;
    }

    /**
     * <p>
     * Tax inheritance information associated with the account.
     * </p>
     * 
     * @param taxInheritanceDetails
     *        Tax inheritance information associated with the account.
     */

    public void setTaxInheritanceDetails(TaxInheritanceDetails taxInheritanceDetails) {
        this.taxInheritanceDetails = taxInheritanceDetails;
    }

    /**
     * <p>
     * Tax inheritance information associated with the account.
     * </p>
     * 
     * @return Tax inheritance information associated with the account.
     */

    public TaxInheritanceDetails getTaxInheritanceDetails() {
        return this.taxInheritanceDetails;
    }

    /**
     * <p>
     * Tax inheritance information associated with the account.
     * </p>
     * 
     * @param taxInheritanceDetails
     *        Tax inheritance information associated with the account.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public AccountDetails withTaxInheritanceDetails(TaxInheritanceDetails taxInheritanceDetails) {
        setTaxInheritanceDetails(taxInheritanceDetails);
        return this;
    }

    /**
     * <p>
     * Your TRN information. Instead of having full legal address, here TRN information will have jurisdiction details
     * (for example, country code and state/region/province if applicable).
     * </p>
     * 
     * @param taxRegistration
     *        Your TRN information. Instead of having full legal address, here TRN information will have jurisdiction
     *        details (for example, country code and state/region/province if applicable).
     */

    public void setTaxRegistration(TaxRegistrationWithJurisdiction taxRegistration) {
        this.taxRegistration = taxRegistration;
    }

    /**
     * <p>
     * Your TRN information. Instead of having full legal address, here TRN information will have jurisdiction details
     * (for example, country code and state/region/province if applicable).
     * </p>
     * 
     * @return Your TRN information. Instead of having full legal address, here TRN information will have jurisdiction
     *         details (for example, country code and state/region/province if applicable).
     */

    public TaxRegistrationWithJurisdiction getTaxRegistration() {
        return this.taxRegistration;
    }

    /**
     * <p>
     * Your TRN information. Instead of having full legal address, here TRN information will have jurisdiction details
     * (for example, country code and state/region/province if applicable).
     * </p>
     * 
     * @param taxRegistration
     *        Your TRN information. Instead of having full legal address, here TRN information will have jurisdiction
     *        details (for example, country code and state/region/province if applicable).
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public AccountDetails withTaxRegistration(TaxRegistrationWithJurisdiction taxRegistration) {
        setTaxRegistration(taxRegistration);
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
        if (getAccountMetaData() != null)
            sb.append("AccountMetaData: ").append("***Sensitive Data Redacted***").append(",");
        if (getTaxInheritanceDetails() != null)
            sb.append("TaxInheritanceDetails: ").append(getTaxInheritanceDetails()).append(",");
        if (getTaxRegistration() != null)
            sb.append("TaxRegistration: ").append("***Sensitive Data Redacted***");
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof AccountDetails == false)
            return false;
        AccountDetails other = (AccountDetails) obj;
        if (other.getAccountId() == null ^ this.getAccountId() == null)
            return false;
        if (other.getAccountId() != null && other.getAccountId().equals(this.getAccountId()) == false)
            return false;
        if (other.getAccountMetaData() == null ^ this.getAccountMetaData() == null)
            return false;
        if (other.getAccountMetaData() != null && other.getAccountMetaData().equals(this.getAccountMetaData()) == false)
            return false;
        if (other.getTaxInheritanceDetails() == null ^ this.getTaxInheritanceDetails() == null)
            return false;
        if (other.getTaxInheritanceDetails() != null && other.getTaxInheritanceDetails().equals(this.getTaxInheritanceDetails()) == false)
            return false;
        if (other.getTaxRegistration() == null ^ this.getTaxRegistration() == null)
            return false;
        if (other.getTaxRegistration() != null && other.getTaxRegistration().equals(this.getTaxRegistration()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getAccountId() == null) ? 0 : getAccountId().hashCode());
        hashCode = prime * hashCode + ((getAccountMetaData() == null) ? 0 : getAccountMetaData().hashCode());
        hashCode = prime * hashCode + ((getTaxInheritanceDetails() == null) ? 0 : getTaxInheritanceDetails().hashCode());
        hashCode = prime * hashCode + ((getTaxRegistration() == null) ? 0 : getTaxRegistration().hashCode());
        return hashCode;
    }

    @Override
    public AccountDetails clone() {
        try {
            return (AccountDetails) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.taxsettings.model.transform.AccountDetailsMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
