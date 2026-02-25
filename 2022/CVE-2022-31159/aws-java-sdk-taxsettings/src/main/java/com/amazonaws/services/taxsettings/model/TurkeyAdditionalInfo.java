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
 * Additional tax information associated with your TRN in Turkey.
 * </p>
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/taxsettings-2018-05-10/TurkeyAdditionalInfo" target="_top">AWS
 *      API Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class TurkeyAdditionalInfo implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * The industry information that tells the Tax Settings API if you're subject to additional withholding taxes. This
     * information required for business-to-business (B2B) customers. This information is conditionally mandatory for
     * B2B customers who are subject to KDV tax.
     * </p>
     */
    private String industries;
    /**
     * <p>
     * The Registered Electronic Mail (REM) that is used to send notarized communication. This parameter is optional for
     * business-to-business (B2B) and business-to-government (B2G) customers. It's not required for business-to-consumer
     * (B2C) customers.
     * </p>
     */
    private String kepEmailId;
    /**
     * <p>
     * Secondary tax ID (“harcama birimi VKN”si”). If one isn't provided, we will use your VKN as the secondary ID.
     * </p>
     */
    private String secondaryTaxId;
    /**
     * <p>
     * The tax office where you're registered. You can enter this information as a string. The Tax Settings API will add
     * this information to your invoice. This parameter is required for business-to-business (B2B) and
     * business-to-government customers. It's not required for business-to-consumer (B2C) customers.
     * </p>
     */
    private String taxOffice;

    /**
     * <p>
     * The industry information that tells the Tax Settings API if you're subject to additional withholding taxes. This
     * information required for business-to-business (B2B) customers. This information is conditionally mandatory for
     * B2B customers who are subject to KDV tax.
     * </p>
     * 
     * @param industries
     *        The industry information that tells the Tax Settings API if you're subject to additional withholding
     *        taxes. This information required for business-to-business (B2B) customers. This information is
     *        conditionally mandatory for B2B customers who are subject to KDV tax.
     * @see Industries
     */

    public void setIndustries(String industries) {
        this.industries = industries;
    }

    /**
     * <p>
     * The industry information that tells the Tax Settings API if you're subject to additional withholding taxes. This
     * information required for business-to-business (B2B) customers. This information is conditionally mandatory for
     * B2B customers who are subject to KDV tax.
     * </p>
     * 
     * @return The industry information that tells the Tax Settings API if you're subject to additional withholding
     *         taxes. This information required for business-to-business (B2B) customers. This information is
     *         conditionally mandatory for B2B customers who are subject to KDV tax.
     * @see Industries
     */

    public String getIndustries() {
        return this.industries;
    }

    /**
     * <p>
     * The industry information that tells the Tax Settings API if you're subject to additional withholding taxes. This
     * information required for business-to-business (B2B) customers. This information is conditionally mandatory for
     * B2B customers who are subject to KDV tax.
     * </p>
     * 
     * @param industries
     *        The industry information that tells the Tax Settings API if you're subject to additional withholding
     *        taxes. This information required for business-to-business (B2B) customers. This information is
     *        conditionally mandatory for B2B customers who are subject to KDV tax.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see Industries
     */

    public TurkeyAdditionalInfo withIndustries(String industries) {
        setIndustries(industries);
        return this;
    }

    /**
     * <p>
     * The industry information that tells the Tax Settings API if you're subject to additional withholding taxes. This
     * information required for business-to-business (B2B) customers. This information is conditionally mandatory for
     * B2B customers who are subject to KDV tax.
     * </p>
     * 
     * @param industries
     *        The industry information that tells the Tax Settings API if you're subject to additional withholding
     *        taxes. This information required for business-to-business (B2B) customers. This information is
     *        conditionally mandatory for B2B customers who are subject to KDV tax.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see Industries
     */

    public TurkeyAdditionalInfo withIndustries(Industries industries) {
        this.industries = industries.toString();
        return this;
    }

    /**
     * <p>
     * The Registered Electronic Mail (REM) that is used to send notarized communication. This parameter is optional for
     * business-to-business (B2B) and business-to-government (B2G) customers. It's not required for business-to-consumer
     * (B2C) customers.
     * </p>
     * 
     * @param kepEmailId
     *        The Registered Electronic Mail (REM) that is used to send notarized communication. This parameter is
     *        optional for business-to-business (B2B) and business-to-government (B2G) customers. It's not required for
     *        business-to-consumer (B2C) customers.
     */

    public void setKepEmailId(String kepEmailId) {
        this.kepEmailId = kepEmailId;
    }

    /**
     * <p>
     * The Registered Electronic Mail (REM) that is used to send notarized communication. This parameter is optional for
     * business-to-business (B2B) and business-to-government (B2G) customers. It's not required for business-to-consumer
     * (B2C) customers.
     * </p>
     * 
     * @return The Registered Electronic Mail (REM) that is used to send notarized communication. This parameter is
     *         optional for business-to-business (B2B) and business-to-government (B2G) customers. It's not required for
     *         business-to-consumer (B2C) customers.
     */

    public String getKepEmailId() {
        return this.kepEmailId;
    }

    /**
     * <p>
     * The Registered Electronic Mail (REM) that is used to send notarized communication. This parameter is optional for
     * business-to-business (B2B) and business-to-government (B2G) customers. It's not required for business-to-consumer
     * (B2C) customers.
     * </p>
     * 
     * @param kepEmailId
     *        The Registered Electronic Mail (REM) that is used to send notarized communication. This parameter is
     *        optional for business-to-business (B2B) and business-to-government (B2G) customers. It's not required for
     *        business-to-consumer (B2C) customers.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public TurkeyAdditionalInfo withKepEmailId(String kepEmailId) {
        setKepEmailId(kepEmailId);
        return this;
    }

    /**
     * <p>
     * Secondary tax ID (“harcama birimi VKN”si”). If one isn't provided, we will use your VKN as the secondary ID.
     * </p>
     * 
     * @param secondaryTaxId
     *        Secondary tax ID (“harcama birimi VKN”si”). If one isn't provided, we will use your VKN as the secondary
     *        ID.
     */

    public void setSecondaryTaxId(String secondaryTaxId) {
        this.secondaryTaxId = secondaryTaxId;
    }

    /**
     * <p>
     * Secondary tax ID (“harcama birimi VKN”si”). If one isn't provided, we will use your VKN as the secondary ID.
     * </p>
     * 
     * @return Secondary tax ID (“harcama birimi VKN”si”). If one isn't provided, we will use your VKN as the secondary
     *         ID.
     */

    public String getSecondaryTaxId() {
        return this.secondaryTaxId;
    }

    /**
     * <p>
     * Secondary tax ID (“harcama birimi VKN”si”). If one isn't provided, we will use your VKN as the secondary ID.
     * </p>
     * 
     * @param secondaryTaxId
     *        Secondary tax ID (“harcama birimi VKN”si”). If one isn't provided, we will use your VKN as the secondary
     *        ID.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public TurkeyAdditionalInfo withSecondaryTaxId(String secondaryTaxId) {
        setSecondaryTaxId(secondaryTaxId);
        return this;
    }

    /**
     * <p>
     * The tax office where you're registered. You can enter this information as a string. The Tax Settings API will add
     * this information to your invoice. This parameter is required for business-to-business (B2B) and
     * business-to-government customers. It's not required for business-to-consumer (B2C) customers.
     * </p>
     * 
     * @param taxOffice
     *        The tax office where you're registered. You can enter this information as a string. The Tax Settings API
     *        will add this information to your invoice. This parameter is required for business-to-business (B2B) and
     *        business-to-government customers. It's not required for business-to-consumer (B2C) customers.
     */

    public void setTaxOffice(String taxOffice) {
        this.taxOffice = taxOffice;
    }

    /**
     * <p>
     * The tax office where you're registered. You can enter this information as a string. The Tax Settings API will add
     * this information to your invoice. This parameter is required for business-to-business (B2B) and
     * business-to-government customers. It's not required for business-to-consumer (B2C) customers.
     * </p>
     * 
     * @return The tax office where you're registered. You can enter this information as a string. The Tax Settings API
     *         will add this information to your invoice. This parameter is required for business-to-business (B2B) and
     *         business-to-government customers. It's not required for business-to-consumer (B2C) customers.
     */

    public String getTaxOffice() {
        return this.taxOffice;
    }

    /**
     * <p>
     * The tax office where you're registered. You can enter this information as a string. The Tax Settings API will add
     * this information to your invoice. This parameter is required for business-to-business (B2B) and
     * business-to-government customers. It's not required for business-to-consumer (B2C) customers.
     * </p>
     * 
     * @param taxOffice
     *        The tax office where you're registered. You can enter this information as a string. The Tax Settings API
     *        will add this information to your invoice. This parameter is required for business-to-business (B2B) and
     *        business-to-government customers. It's not required for business-to-consumer (B2C) customers.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public TurkeyAdditionalInfo withTaxOffice(String taxOffice) {
        setTaxOffice(taxOffice);
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
        if (getIndustries() != null)
            sb.append("Industries: ").append(getIndustries()).append(",");
        if (getKepEmailId() != null)
            sb.append("KepEmailId: ").append(getKepEmailId()).append(",");
        if (getSecondaryTaxId() != null)
            sb.append("SecondaryTaxId: ").append(getSecondaryTaxId()).append(",");
        if (getTaxOffice() != null)
            sb.append("TaxOffice: ").append(getTaxOffice());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof TurkeyAdditionalInfo == false)
            return false;
        TurkeyAdditionalInfo other = (TurkeyAdditionalInfo) obj;
        if (other.getIndustries() == null ^ this.getIndustries() == null)
            return false;
        if (other.getIndustries() != null && other.getIndustries().equals(this.getIndustries()) == false)
            return false;
        if (other.getKepEmailId() == null ^ this.getKepEmailId() == null)
            return false;
        if (other.getKepEmailId() != null && other.getKepEmailId().equals(this.getKepEmailId()) == false)
            return false;
        if (other.getSecondaryTaxId() == null ^ this.getSecondaryTaxId() == null)
            return false;
        if (other.getSecondaryTaxId() != null && other.getSecondaryTaxId().equals(this.getSecondaryTaxId()) == false)
            return false;
        if (other.getTaxOffice() == null ^ this.getTaxOffice() == null)
            return false;
        if (other.getTaxOffice() != null && other.getTaxOffice().equals(this.getTaxOffice()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getIndustries() == null) ? 0 : getIndustries().hashCode());
        hashCode = prime * hashCode + ((getKepEmailId() == null) ? 0 : getKepEmailId().hashCode());
        hashCode = prime * hashCode + ((getSecondaryTaxId() == null) ? 0 : getSecondaryTaxId().hashCode());
        hashCode = prime * hashCode + ((getTaxOffice() == null) ? 0 : getTaxOffice().hashCode());
        return hashCode;
    }

    @Override
    public TurkeyAdditionalInfo clone() {
        try {
            return (TurkeyAdditionalInfo) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.taxsettings.model.transform.TurkeyAdditionalInfoMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
