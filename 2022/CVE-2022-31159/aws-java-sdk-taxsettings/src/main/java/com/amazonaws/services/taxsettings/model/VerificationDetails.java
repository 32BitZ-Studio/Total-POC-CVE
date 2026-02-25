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
 * Required information to verify your TRN.
 * </p>
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/taxsettings-2018-05-10/VerificationDetails" target="_top">AWS
 *      API Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class VerificationDetails implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * Date of birth to verify your submitted TRN. Use the <code>YYYY-MM-DD</code> format.
     * </p>
     */
    private String dateOfBirth;
    /**
     * <p>
     * The tax registration document, which is required for specific countries such as Bangladesh, Kenya, South Korea
     * and Spain.
     * </p>
     */
    private java.util.List<TaxRegistrationDocument> taxRegistrationDocuments;

    /**
     * <p>
     * Date of birth to verify your submitted TRN. Use the <code>YYYY-MM-DD</code> format.
     * </p>
     * 
     * @param dateOfBirth
     *        Date of birth to verify your submitted TRN. Use the <code>YYYY-MM-DD</code> format.
     */

    public void setDateOfBirth(String dateOfBirth) {
        this.dateOfBirth = dateOfBirth;
    }

    /**
     * <p>
     * Date of birth to verify your submitted TRN. Use the <code>YYYY-MM-DD</code> format.
     * </p>
     * 
     * @return Date of birth to verify your submitted TRN. Use the <code>YYYY-MM-DD</code> format.
     */

    public String getDateOfBirth() {
        return this.dateOfBirth;
    }

    /**
     * <p>
     * Date of birth to verify your submitted TRN. Use the <code>YYYY-MM-DD</code> format.
     * </p>
     * 
     * @param dateOfBirth
     *        Date of birth to verify your submitted TRN. Use the <code>YYYY-MM-DD</code> format.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public VerificationDetails withDateOfBirth(String dateOfBirth) {
        setDateOfBirth(dateOfBirth);
        return this;
    }

    /**
     * <p>
     * The tax registration document, which is required for specific countries such as Bangladesh, Kenya, South Korea
     * and Spain.
     * </p>
     * 
     * @return The tax registration document, which is required for specific countries such as Bangladesh, Kenya, South
     *         Korea and Spain.
     */

    public java.util.List<TaxRegistrationDocument> getTaxRegistrationDocuments() {
        return taxRegistrationDocuments;
    }

    /**
     * <p>
     * The tax registration document, which is required for specific countries such as Bangladesh, Kenya, South Korea
     * and Spain.
     * </p>
     * 
     * @param taxRegistrationDocuments
     *        The tax registration document, which is required for specific countries such as Bangladesh, Kenya, South
     *        Korea and Spain.
     */

    public void setTaxRegistrationDocuments(java.util.Collection<TaxRegistrationDocument> taxRegistrationDocuments) {
        if (taxRegistrationDocuments == null) {
            this.taxRegistrationDocuments = null;
            return;
        }

        this.taxRegistrationDocuments = new java.util.ArrayList<TaxRegistrationDocument>(taxRegistrationDocuments);
    }

    /**
     * <p>
     * The tax registration document, which is required for specific countries such as Bangladesh, Kenya, South Korea
     * and Spain.
     * </p>
     * <p>
     * <b>NOTE:</b> This method appends the values to the existing list (if any). Use
     * {@link #setTaxRegistrationDocuments(java.util.Collection)} or
     * {@link #withTaxRegistrationDocuments(java.util.Collection)} if you want to override the existing values.
     * </p>
     * 
     * @param taxRegistrationDocuments
     *        The tax registration document, which is required for specific countries such as Bangladesh, Kenya, South
     *        Korea and Spain.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public VerificationDetails withTaxRegistrationDocuments(TaxRegistrationDocument... taxRegistrationDocuments) {
        if (this.taxRegistrationDocuments == null) {
            setTaxRegistrationDocuments(new java.util.ArrayList<TaxRegistrationDocument>(taxRegistrationDocuments.length));
        }
        for (TaxRegistrationDocument ele : taxRegistrationDocuments) {
            this.taxRegistrationDocuments.add(ele);
        }
        return this;
    }

    /**
     * <p>
     * The tax registration document, which is required for specific countries such as Bangladesh, Kenya, South Korea
     * and Spain.
     * </p>
     * 
     * @param taxRegistrationDocuments
     *        The tax registration document, which is required for specific countries such as Bangladesh, Kenya, South
     *        Korea and Spain.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public VerificationDetails withTaxRegistrationDocuments(java.util.Collection<TaxRegistrationDocument> taxRegistrationDocuments) {
        setTaxRegistrationDocuments(taxRegistrationDocuments);
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
        if (getDateOfBirth() != null)
            sb.append("DateOfBirth: ").append(getDateOfBirth()).append(",");
        if (getTaxRegistrationDocuments() != null)
            sb.append("TaxRegistrationDocuments: ").append(getTaxRegistrationDocuments());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof VerificationDetails == false)
            return false;
        VerificationDetails other = (VerificationDetails) obj;
        if (other.getDateOfBirth() == null ^ this.getDateOfBirth() == null)
            return false;
        if (other.getDateOfBirth() != null && other.getDateOfBirth().equals(this.getDateOfBirth()) == false)
            return false;
        if (other.getTaxRegistrationDocuments() == null ^ this.getTaxRegistrationDocuments() == null)
            return false;
        if (other.getTaxRegistrationDocuments() != null && other.getTaxRegistrationDocuments().equals(this.getTaxRegistrationDocuments()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getDateOfBirth() == null) ? 0 : getDateOfBirth().hashCode());
        hashCode = prime * hashCode + ((getTaxRegistrationDocuments() == null) ? 0 : getTaxRegistrationDocuments().hashCode());
        return hashCode;
    }

    @Override
    public VerificationDetails clone() {
        try {
            return (VerificationDetails) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.taxsettings.model.transform.VerificationDetailsMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
