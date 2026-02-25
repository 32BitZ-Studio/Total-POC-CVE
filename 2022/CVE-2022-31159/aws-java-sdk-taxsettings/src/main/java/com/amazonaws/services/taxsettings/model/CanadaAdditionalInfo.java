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
 * Additional tax information associated with your TRN in Canada .
 * </p>
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/taxsettings-2018-05-10/CanadaAdditionalInfo" target="_top">AWS
 *      API Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class CanadaAdditionalInfo implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * The Quebec Sales Tax ID number. Leave blank if you do not have a Quebec Sales Tax ID number.
     * </p>
     */
    private String canadaQuebecSalesTaxNumber;
    /**
     * <p>
     * Manitoba Retail Sales Tax ID number. Customers purchasing Amazon Web Services for resale in Manitoba must provide
     * a valid Retail Sales Tax ID number for Manitoba. Leave this blank if you do not have a Retail Sales Tax ID number
     * in Manitoba or are not purchasing Amazon Web Services for resale.
     * </p>
     */
    private String canadaRetailSalesTaxNumber;
    /**
     * <p>
     * The value for this parameter must be <code>true</code> if the <code>provincialSalesTaxId</code> value is provided
     * for a TRN in British Columbia, Saskatchewan, or Manitoba provinces.
     * </p>
     * <p>
     * To claim a provincial sales tax (PST) and retail sales tax (RST) reseller exemption, you must confirm that
     * purchases from this account were made for resale. Otherwise, remove the PST or RST number from the
     * <code>provincialSalesTaxId</code> parameter from your request.
     * </p>
     */
    private Boolean isResellerAccount;
    /**
     * <p>
     * The provincial sales tax ID for your TRN in Canada. This parameter can represent the following:
     * </p>
     * <ul>
     * <li>
     * <p>
     * Provincial sales tax ID number for British Columbia and Saskatchewan provinces
     * </p>
     * </li>
     * <li>
     * <p>
     * Manitoba retail sales tax ID number for Manitoba province
     * </p>
     * </li>
     * <li>
     * <p>
     * Quebec sales tax ID number for Quebec province
     * </p>
     * </li>
     * </ul>
     * <p>
     * The Tax Setting API only accepts this parameter if the TRN is specified for the previous provinces. For other
     * provinces, the Tax Settings API doesn't accept this parameter.
     * </p>
     */
    private String provincialSalesTaxId;

    /**
     * <p>
     * The Quebec Sales Tax ID number. Leave blank if you do not have a Quebec Sales Tax ID number.
     * </p>
     * 
     * @param canadaQuebecSalesTaxNumber
     *        The Quebec Sales Tax ID number. Leave blank if you do not have a Quebec Sales Tax ID number.
     */

    public void setCanadaQuebecSalesTaxNumber(String canadaQuebecSalesTaxNumber) {
        this.canadaQuebecSalesTaxNumber = canadaQuebecSalesTaxNumber;
    }

    /**
     * <p>
     * The Quebec Sales Tax ID number. Leave blank if you do not have a Quebec Sales Tax ID number.
     * </p>
     * 
     * @return The Quebec Sales Tax ID number. Leave blank if you do not have a Quebec Sales Tax ID number.
     */

    public String getCanadaQuebecSalesTaxNumber() {
        return this.canadaQuebecSalesTaxNumber;
    }

    /**
     * <p>
     * The Quebec Sales Tax ID number. Leave blank if you do not have a Quebec Sales Tax ID number.
     * </p>
     * 
     * @param canadaQuebecSalesTaxNumber
     *        The Quebec Sales Tax ID number. Leave blank if you do not have a Quebec Sales Tax ID number.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public CanadaAdditionalInfo withCanadaQuebecSalesTaxNumber(String canadaQuebecSalesTaxNumber) {
        setCanadaQuebecSalesTaxNumber(canadaQuebecSalesTaxNumber);
        return this;
    }

    /**
     * <p>
     * Manitoba Retail Sales Tax ID number. Customers purchasing Amazon Web Services for resale in Manitoba must provide
     * a valid Retail Sales Tax ID number for Manitoba. Leave this blank if you do not have a Retail Sales Tax ID number
     * in Manitoba or are not purchasing Amazon Web Services for resale.
     * </p>
     * 
     * @param canadaRetailSalesTaxNumber
     *        Manitoba Retail Sales Tax ID number. Customers purchasing Amazon Web Services for resale in Manitoba must
     *        provide a valid Retail Sales Tax ID number for Manitoba. Leave this blank if you do not have a Retail
     *        Sales Tax ID number in Manitoba or are not purchasing Amazon Web Services for resale.
     */

    public void setCanadaRetailSalesTaxNumber(String canadaRetailSalesTaxNumber) {
        this.canadaRetailSalesTaxNumber = canadaRetailSalesTaxNumber;
    }

    /**
     * <p>
     * Manitoba Retail Sales Tax ID number. Customers purchasing Amazon Web Services for resale in Manitoba must provide
     * a valid Retail Sales Tax ID number for Manitoba. Leave this blank if you do not have a Retail Sales Tax ID number
     * in Manitoba or are not purchasing Amazon Web Services for resale.
     * </p>
     * 
     * @return Manitoba Retail Sales Tax ID number. Customers purchasing Amazon Web Services for resale in Manitoba must
     *         provide a valid Retail Sales Tax ID number for Manitoba. Leave this blank if you do not have a Retail
     *         Sales Tax ID number in Manitoba or are not purchasing Amazon Web Services for resale.
     */

    public String getCanadaRetailSalesTaxNumber() {
        return this.canadaRetailSalesTaxNumber;
    }

    /**
     * <p>
     * Manitoba Retail Sales Tax ID number. Customers purchasing Amazon Web Services for resale in Manitoba must provide
     * a valid Retail Sales Tax ID number for Manitoba. Leave this blank if you do not have a Retail Sales Tax ID number
     * in Manitoba or are not purchasing Amazon Web Services for resale.
     * </p>
     * 
     * @param canadaRetailSalesTaxNumber
     *        Manitoba Retail Sales Tax ID number. Customers purchasing Amazon Web Services for resale in Manitoba must
     *        provide a valid Retail Sales Tax ID number for Manitoba. Leave this blank if you do not have a Retail
     *        Sales Tax ID number in Manitoba or are not purchasing Amazon Web Services for resale.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public CanadaAdditionalInfo withCanadaRetailSalesTaxNumber(String canadaRetailSalesTaxNumber) {
        setCanadaRetailSalesTaxNumber(canadaRetailSalesTaxNumber);
        return this;
    }

    /**
     * <p>
     * The value for this parameter must be <code>true</code> if the <code>provincialSalesTaxId</code> value is provided
     * for a TRN in British Columbia, Saskatchewan, or Manitoba provinces.
     * </p>
     * <p>
     * To claim a provincial sales tax (PST) and retail sales tax (RST) reseller exemption, you must confirm that
     * purchases from this account were made for resale. Otherwise, remove the PST or RST number from the
     * <code>provincialSalesTaxId</code> parameter from your request.
     * </p>
     * 
     * @param isResellerAccount
     *        The value for this parameter must be <code>true</code> if the <code>provincialSalesTaxId</code> value is
     *        provided for a TRN in British Columbia, Saskatchewan, or Manitoba provinces. </p>
     *        <p>
     *        To claim a provincial sales tax (PST) and retail sales tax (RST) reseller exemption, you must confirm that
     *        purchases from this account were made for resale. Otherwise, remove the PST or RST number from the
     *        <code>provincialSalesTaxId</code> parameter from your request.
     */

    public void setIsResellerAccount(Boolean isResellerAccount) {
        this.isResellerAccount = isResellerAccount;
    }

    /**
     * <p>
     * The value for this parameter must be <code>true</code> if the <code>provincialSalesTaxId</code> value is provided
     * for a TRN in British Columbia, Saskatchewan, or Manitoba provinces.
     * </p>
     * <p>
     * To claim a provincial sales tax (PST) and retail sales tax (RST) reseller exemption, you must confirm that
     * purchases from this account were made for resale. Otherwise, remove the PST or RST number from the
     * <code>provincialSalesTaxId</code> parameter from your request.
     * </p>
     * 
     * @return The value for this parameter must be <code>true</code> if the <code>provincialSalesTaxId</code> value is
     *         provided for a TRN in British Columbia, Saskatchewan, or Manitoba provinces. </p>
     *         <p>
     *         To claim a provincial sales tax (PST) and retail sales tax (RST) reseller exemption, you must confirm
     *         that purchases from this account were made for resale. Otherwise, remove the PST or RST number from the
     *         <code>provincialSalesTaxId</code> parameter from your request.
     */

    public Boolean getIsResellerAccount() {
        return this.isResellerAccount;
    }

    /**
     * <p>
     * The value for this parameter must be <code>true</code> if the <code>provincialSalesTaxId</code> value is provided
     * for a TRN in British Columbia, Saskatchewan, or Manitoba provinces.
     * </p>
     * <p>
     * To claim a provincial sales tax (PST) and retail sales tax (RST) reseller exemption, you must confirm that
     * purchases from this account were made for resale. Otherwise, remove the PST or RST number from the
     * <code>provincialSalesTaxId</code> parameter from your request.
     * </p>
     * 
     * @param isResellerAccount
     *        The value for this parameter must be <code>true</code> if the <code>provincialSalesTaxId</code> value is
     *        provided for a TRN in British Columbia, Saskatchewan, or Manitoba provinces. </p>
     *        <p>
     *        To claim a provincial sales tax (PST) and retail sales tax (RST) reseller exemption, you must confirm that
     *        purchases from this account were made for resale. Otherwise, remove the PST or RST number from the
     *        <code>provincialSalesTaxId</code> parameter from your request.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public CanadaAdditionalInfo withIsResellerAccount(Boolean isResellerAccount) {
        setIsResellerAccount(isResellerAccount);
        return this;
    }

    /**
     * <p>
     * The value for this parameter must be <code>true</code> if the <code>provincialSalesTaxId</code> value is provided
     * for a TRN in British Columbia, Saskatchewan, or Manitoba provinces.
     * </p>
     * <p>
     * To claim a provincial sales tax (PST) and retail sales tax (RST) reseller exemption, you must confirm that
     * purchases from this account were made for resale. Otherwise, remove the PST or RST number from the
     * <code>provincialSalesTaxId</code> parameter from your request.
     * </p>
     * 
     * @return The value for this parameter must be <code>true</code> if the <code>provincialSalesTaxId</code> value is
     *         provided for a TRN in British Columbia, Saskatchewan, or Manitoba provinces. </p>
     *         <p>
     *         To claim a provincial sales tax (PST) and retail sales tax (RST) reseller exemption, you must confirm
     *         that purchases from this account were made for resale. Otherwise, remove the PST or RST number from the
     *         <code>provincialSalesTaxId</code> parameter from your request.
     */

    public Boolean isResellerAccount() {
        return this.isResellerAccount;
    }

    /**
     * <p>
     * The provincial sales tax ID for your TRN in Canada. This parameter can represent the following:
     * </p>
     * <ul>
     * <li>
     * <p>
     * Provincial sales tax ID number for British Columbia and Saskatchewan provinces
     * </p>
     * </li>
     * <li>
     * <p>
     * Manitoba retail sales tax ID number for Manitoba province
     * </p>
     * </li>
     * <li>
     * <p>
     * Quebec sales tax ID number for Quebec province
     * </p>
     * </li>
     * </ul>
     * <p>
     * The Tax Setting API only accepts this parameter if the TRN is specified for the previous provinces. For other
     * provinces, the Tax Settings API doesn't accept this parameter.
     * </p>
     * 
     * @param provincialSalesTaxId
     *        The provincial sales tax ID for your TRN in Canada. This parameter can represent the following: </p>
     *        <ul>
     *        <li>
     *        <p>
     *        Provincial sales tax ID number for British Columbia and Saskatchewan provinces
     *        </p>
     *        </li>
     *        <li>
     *        <p>
     *        Manitoba retail sales tax ID number for Manitoba province
     *        </p>
     *        </li>
     *        <li>
     *        <p>
     *        Quebec sales tax ID number for Quebec province
     *        </p>
     *        </li>
     *        </ul>
     *        <p>
     *        The Tax Setting API only accepts this parameter if the TRN is specified for the previous provinces. For
     *        other provinces, the Tax Settings API doesn't accept this parameter.
     */

    public void setProvincialSalesTaxId(String provincialSalesTaxId) {
        this.provincialSalesTaxId = provincialSalesTaxId;
    }

    /**
     * <p>
     * The provincial sales tax ID for your TRN in Canada. This parameter can represent the following:
     * </p>
     * <ul>
     * <li>
     * <p>
     * Provincial sales tax ID number for British Columbia and Saskatchewan provinces
     * </p>
     * </li>
     * <li>
     * <p>
     * Manitoba retail sales tax ID number for Manitoba province
     * </p>
     * </li>
     * <li>
     * <p>
     * Quebec sales tax ID number for Quebec province
     * </p>
     * </li>
     * </ul>
     * <p>
     * The Tax Setting API only accepts this parameter if the TRN is specified for the previous provinces. For other
     * provinces, the Tax Settings API doesn't accept this parameter.
     * </p>
     * 
     * @return The provincial sales tax ID for your TRN in Canada. This parameter can represent the following: </p>
     *         <ul>
     *         <li>
     *         <p>
     *         Provincial sales tax ID number for British Columbia and Saskatchewan provinces
     *         </p>
     *         </li>
     *         <li>
     *         <p>
     *         Manitoba retail sales tax ID number for Manitoba province
     *         </p>
     *         </li>
     *         <li>
     *         <p>
     *         Quebec sales tax ID number for Quebec province
     *         </p>
     *         </li>
     *         </ul>
     *         <p>
     *         The Tax Setting API only accepts this parameter if the TRN is specified for the previous provinces. For
     *         other provinces, the Tax Settings API doesn't accept this parameter.
     */

    public String getProvincialSalesTaxId() {
        return this.provincialSalesTaxId;
    }

    /**
     * <p>
     * The provincial sales tax ID for your TRN in Canada. This parameter can represent the following:
     * </p>
     * <ul>
     * <li>
     * <p>
     * Provincial sales tax ID number for British Columbia and Saskatchewan provinces
     * </p>
     * </li>
     * <li>
     * <p>
     * Manitoba retail sales tax ID number for Manitoba province
     * </p>
     * </li>
     * <li>
     * <p>
     * Quebec sales tax ID number for Quebec province
     * </p>
     * </li>
     * </ul>
     * <p>
     * The Tax Setting API only accepts this parameter if the TRN is specified for the previous provinces. For other
     * provinces, the Tax Settings API doesn't accept this parameter.
     * </p>
     * 
     * @param provincialSalesTaxId
     *        The provincial sales tax ID for your TRN in Canada. This parameter can represent the following: </p>
     *        <ul>
     *        <li>
     *        <p>
     *        Provincial sales tax ID number for British Columbia and Saskatchewan provinces
     *        </p>
     *        </li>
     *        <li>
     *        <p>
     *        Manitoba retail sales tax ID number for Manitoba province
     *        </p>
     *        </li>
     *        <li>
     *        <p>
     *        Quebec sales tax ID number for Quebec province
     *        </p>
     *        </li>
     *        </ul>
     *        <p>
     *        The Tax Setting API only accepts this parameter if the TRN is specified for the previous provinces. For
     *        other provinces, the Tax Settings API doesn't accept this parameter.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public CanadaAdditionalInfo withProvincialSalesTaxId(String provincialSalesTaxId) {
        setProvincialSalesTaxId(provincialSalesTaxId);
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
        if (getCanadaQuebecSalesTaxNumber() != null)
            sb.append("CanadaQuebecSalesTaxNumber: ").append(getCanadaQuebecSalesTaxNumber()).append(",");
        if (getCanadaRetailSalesTaxNumber() != null)
            sb.append("CanadaRetailSalesTaxNumber: ").append(getCanadaRetailSalesTaxNumber()).append(",");
        if (getIsResellerAccount() != null)
            sb.append("IsResellerAccount: ").append(getIsResellerAccount()).append(",");
        if (getProvincialSalesTaxId() != null)
            sb.append("ProvincialSalesTaxId: ").append(getProvincialSalesTaxId());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof CanadaAdditionalInfo == false)
            return false;
        CanadaAdditionalInfo other = (CanadaAdditionalInfo) obj;
        if (other.getCanadaQuebecSalesTaxNumber() == null ^ this.getCanadaQuebecSalesTaxNumber() == null)
            return false;
        if (other.getCanadaQuebecSalesTaxNumber() != null && other.getCanadaQuebecSalesTaxNumber().equals(this.getCanadaQuebecSalesTaxNumber()) == false)
            return false;
        if (other.getCanadaRetailSalesTaxNumber() == null ^ this.getCanadaRetailSalesTaxNumber() == null)
            return false;
        if (other.getCanadaRetailSalesTaxNumber() != null && other.getCanadaRetailSalesTaxNumber().equals(this.getCanadaRetailSalesTaxNumber()) == false)
            return false;
        if (other.getIsResellerAccount() == null ^ this.getIsResellerAccount() == null)
            return false;
        if (other.getIsResellerAccount() != null && other.getIsResellerAccount().equals(this.getIsResellerAccount()) == false)
            return false;
        if (other.getProvincialSalesTaxId() == null ^ this.getProvincialSalesTaxId() == null)
            return false;
        if (other.getProvincialSalesTaxId() != null && other.getProvincialSalesTaxId().equals(this.getProvincialSalesTaxId()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getCanadaQuebecSalesTaxNumber() == null) ? 0 : getCanadaQuebecSalesTaxNumber().hashCode());
        hashCode = prime * hashCode + ((getCanadaRetailSalesTaxNumber() == null) ? 0 : getCanadaRetailSalesTaxNumber().hashCode());
        hashCode = prime * hashCode + ((getIsResellerAccount() == null) ? 0 : getIsResellerAccount().hashCode());
        hashCode = prime * hashCode + ((getProvincialSalesTaxId() == null) ? 0 : getProvincialSalesTaxId().hashCode());
        return hashCode;
    }

    @Override
    public CanadaAdditionalInfo clone() {
        try {
            return (CanadaAdditionalInfo) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.taxsettings.model.transform.CanadaAdditionalInfoMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
