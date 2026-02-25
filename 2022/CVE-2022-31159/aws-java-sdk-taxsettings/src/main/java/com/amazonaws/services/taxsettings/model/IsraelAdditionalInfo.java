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
 * Additional tax information associated with your TRN in Israel.
 * </p>
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/taxsettings-2018-05-10/IsraelAdditionalInfo" target="_top">AWS
 *      API Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class IsraelAdditionalInfo implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * Customer type for your TRN in Israel. The value can be <code>Business</code> or <code>Individual</code>. Use
     * <code>Business</code>for entities such as not-for-profit and financial institutions.
     * </p>
     */
    private String customerType;
    /**
     * <p>
     * Dealer type for your TRN in Israel. If you're not a local authorized dealer with an Israeli VAT ID, specify your
     * tax identification number so that Amazon Web Services can send you a compliant tax invoice.
     * </p>
     */
    private String dealerType;

    /**
     * <p>
     * Customer type for your TRN in Israel. The value can be <code>Business</code> or <code>Individual</code>. Use
     * <code>Business</code>for entities such as not-for-profit and financial institutions.
     * </p>
     * 
     * @param customerType
     *        Customer type for your TRN in Israel. The value can be <code>Business</code> or <code>Individual</code>.
     *        Use <code>Business</code>for entities such as not-for-profit and financial institutions.
     * @see IsraelCustomerType
     */

    public void setCustomerType(String customerType) {
        this.customerType = customerType;
    }

    /**
     * <p>
     * Customer type for your TRN in Israel. The value can be <code>Business</code> or <code>Individual</code>. Use
     * <code>Business</code>for entities such as not-for-profit and financial institutions.
     * </p>
     * 
     * @return Customer type for your TRN in Israel. The value can be <code>Business</code> or <code>Individual</code>.
     *         Use <code>Business</code>for entities such as not-for-profit and financial institutions.
     * @see IsraelCustomerType
     */

    public String getCustomerType() {
        return this.customerType;
    }

    /**
     * <p>
     * Customer type for your TRN in Israel. The value can be <code>Business</code> or <code>Individual</code>. Use
     * <code>Business</code>for entities such as not-for-profit and financial institutions.
     * </p>
     * 
     * @param customerType
     *        Customer type for your TRN in Israel. The value can be <code>Business</code> or <code>Individual</code>.
     *        Use <code>Business</code>for entities such as not-for-profit and financial institutions.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see IsraelCustomerType
     */

    public IsraelAdditionalInfo withCustomerType(String customerType) {
        setCustomerType(customerType);
        return this;
    }

    /**
     * <p>
     * Customer type for your TRN in Israel. The value can be <code>Business</code> or <code>Individual</code>. Use
     * <code>Business</code>for entities such as not-for-profit and financial institutions.
     * </p>
     * 
     * @param customerType
     *        Customer type for your TRN in Israel. The value can be <code>Business</code> or <code>Individual</code>.
     *        Use <code>Business</code>for entities such as not-for-profit and financial institutions.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see IsraelCustomerType
     */

    public IsraelAdditionalInfo withCustomerType(IsraelCustomerType customerType) {
        this.customerType = customerType.toString();
        return this;
    }

    /**
     * <p>
     * Dealer type for your TRN in Israel. If you're not a local authorized dealer with an Israeli VAT ID, specify your
     * tax identification number so that Amazon Web Services can send you a compliant tax invoice.
     * </p>
     * 
     * @param dealerType
     *        Dealer type for your TRN in Israel. If you're not a local authorized dealer with an Israeli VAT ID,
     *        specify your tax identification number so that Amazon Web Services can send you a compliant tax invoice.
     * @see IsraelDealerType
     */

    public void setDealerType(String dealerType) {
        this.dealerType = dealerType;
    }

    /**
     * <p>
     * Dealer type for your TRN in Israel. If you're not a local authorized dealer with an Israeli VAT ID, specify your
     * tax identification number so that Amazon Web Services can send you a compliant tax invoice.
     * </p>
     * 
     * @return Dealer type for your TRN in Israel. If you're not a local authorized dealer with an Israeli VAT ID,
     *         specify your tax identification number so that Amazon Web Services can send you a compliant tax invoice.
     * @see IsraelDealerType
     */

    public String getDealerType() {
        return this.dealerType;
    }

    /**
     * <p>
     * Dealer type for your TRN in Israel. If you're not a local authorized dealer with an Israeli VAT ID, specify your
     * tax identification number so that Amazon Web Services can send you a compliant tax invoice.
     * </p>
     * 
     * @param dealerType
     *        Dealer type for your TRN in Israel. If you're not a local authorized dealer with an Israeli VAT ID,
     *        specify your tax identification number so that Amazon Web Services can send you a compliant tax invoice.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see IsraelDealerType
     */

    public IsraelAdditionalInfo withDealerType(String dealerType) {
        setDealerType(dealerType);
        return this;
    }

    /**
     * <p>
     * Dealer type for your TRN in Israel. If you're not a local authorized dealer with an Israeli VAT ID, specify your
     * tax identification number so that Amazon Web Services can send you a compliant tax invoice.
     * </p>
     * 
     * @param dealerType
     *        Dealer type for your TRN in Israel. If you're not a local authorized dealer with an Israeli VAT ID,
     *        specify your tax identification number so that Amazon Web Services can send you a compliant tax invoice.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see IsraelDealerType
     */

    public IsraelAdditionalInfo withDealerType(IsraelDealerType dealerType) {
        this.dealerType = dealerType.toString();
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
        if (getCustomerType() != null)
            sb.append("CustomerType: ").append(getCustomerType()).append(",");
        if (getDealerType() != null)
            sb.append("DealerType: ").append(getDealerType());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof IsraelAdditionalInfo == false)
            return false;
        IsraelAdditionalInfo other = (IsraelAdditionalInfo) obj;
        if (other.getCustomerType() == null ^ this.getCustomerType() == null)
            return false;
        if (other.getCustomerType() != null && other.getCustomerType().equals(this.getCustomerType()) == false)
            return false;
        if (other.getDealerType() == null ^ this.getDealerType() == null)
            return false;
        if (other.getDealerType() != null && other.getDealerType().equals(this.getDealerType()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getCustomerType() == null) ? 0 : getCustomerType().hashCode());
        hashCode = prime * hashCode + ((getDealerType() == null) ? 0 : getDealerType().hashCode());
        return hashCode;
    }

    @Override
    public IsraelAdditionalInfo clone() {
        try {
            return (IsraelAdditionalInfo) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.taxsettings.model.transform.IsraelAdditionalInfoMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
