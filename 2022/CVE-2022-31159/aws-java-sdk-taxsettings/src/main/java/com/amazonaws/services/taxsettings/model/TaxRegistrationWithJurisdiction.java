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
 * Your TRN information with jurisdiction details. This doesn't contain the full legal address associated with the TRN
 * information.
 * </p>
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/taxsettings-2018-05-10/TaxRegistrationWithJurisdiction"
 *      target="_top">AWS API Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class TaxRegistrationWithJurisdiction implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * Additional tax information associated with your TRN.
     * </p>
     */
    private AdditionalInfoResponse additionalTaxInformation;
    /**
     * <p>
     * The email address to receive VAT invoices.
     * </p>
     */
    private String certifiedEmailId;
    /**
     * <p>
     * The jurisdiction associated with your TRN information.
     * </p>
     */
    private Jurisdiction jurisdiction;
    /**
     * <p>
     * The legal name associated with your TRN information.
     * </p>
     */
    private String legalName;
    /**
     * <p>
     * Your tax registration unique identifier.
     * </p>
     */
    private String registrationId;
    /**
     * <p>
     * The type of your tax registration. This can be either <code>VAT</code> or <code>GST</code>.
     * </p>
     */
    private String registrationType;
    /**
     * <p>
     * The industry that describes your business. For business-to-business (B2B) customers, specify Business. For
     * business-to-consumer (B2C) customers, specify Individual. For business-to-government (B2G), specify
     * Government.Note that certain values may not applicable for the request country. Please refer to country specific
     * information in API document.
     * </p>
     */
    private String sector;
    /**
     * <p>
     * The status of your TRN. This can be either <code>Verified</code>, <code>Pending</code>, <code>Deleted</code>, or
     * <code>Rejected</code>.
     * </p>
     */
    private String status;
    /**
     * <p>
     * The metadata for your tax document.
     * </p>
     */
    private java.util.List<TaxDocumentMetadata> taxDocumentMetadatas;

    /**
     * <p>
     * Additional tax information associated with your TRN.
     * </p>
     * 
     * @param additionalTaxInformation
     *        Additional tax information associated with your TRN.
     */

    public void setAdditionalTaxInformation(AdditionalInfoResponse additionalTaxInformation) {
        this.additionalTaxInformation = additionalTaxInformation;
    }

    /**
     * <p>
     * Additional tax information associated with your TRN.
     * </p>
     * 
     * @return Additional tax information associated with your TRN.
     */

    public AdditionalInfoResponse getAdditionalTaxInformation() {
        return this.additionalTaxInformation;
    }

    /**
     * <p>
     * Additional tax information associated with your TRN.
     * </p>
     * 
     * @param additionalTaxInformation
     *        Additional tax information associated with your TRN.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public TaxRegistrationWithJurisdiction withAdditionalTaxInformation(AdditionalInfoResponse additionalTaxInformation) {
        setAdditionalTaxInformation(additionalTaxInformation);
        return this;
    }

    /**
     * <p>
     * The email address to receive VAT invoices.
     * </p>
     * 
     * @param certifiedEmailId
     *        The email address to receive VAT invoices.
     */

    public void setCertifiedEmailId(String certifiedEmailId) {
        this.certifiedEmailId = certifiedEmailId;
    }

    /**
     * <p>
     * The email address to receive VAT invoices.
     * </p>
     * 
     * @return The email address to receive VAT invoices.
     */

    public String getCertifiedEmailId() {
        return this.certifiedEmailId;
    }

    /**
     * <p>
     * The email address to receive VAT invoices.
     * </p>
     * 
     * @param certifiedEmailId
     *        The email address to receive VAT invoices.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public TaxRegistrationWithJurisdiction withCertifiedEmailId(String certifiedEmailId) {
        setCertifiedEmailId(certifiedEmailId);
        return this;
    }

    /**
     * <p>
     * The jurisdiction associated with your TRN information.
     * </p>
     * 
     * @param jurisdiction
     *        The jurisdiction associated with your TRN information.
     */

    public void setJurisdiction(Jurisdiction jurisdiction) {
        this.jurisdiction = jurisdiction;
    }

    /**
     * <p>
     * The jurisdiction associated with your TRN information.
     * </p>
     * 
     * @return The jurisdiction associated with your TRN information.
     */

    public Jurisdiction getJurisdiction() {
        return this.jurisdiction;
    }

    /**
     * <p>
     * The jurisdiction associated with your TRN information.
     * </p>
     * 
     * @param jurisdiction
     *        The jurisdiction associated with your TRN information.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public TaxRegistrationWithJurisdiction withJurisdiction(Jurisdiction jurisdiction) {
        setJurisdiction(jurisdiction);
        return this;
    }

    /**
     * <p>
     * The legal name associated with your TRN information.
     * </p>
     * 
     * @param legalName
     *        The legal name associated with your TRN information.
     */

    public void setLegalName(String legalName) {
        this.legalName = legalName;
    }

    /**
     * <p>
     * The legal name associated with your TRN information.
     * </p>
     * 
     * @return The legal name associated with your TRN information.
     */

    public String getLegalName() {
        return this.legalName;
    }

    /**
     * <p>
     * The legal name associated with your TRN information.
     * </p>
     * 
     * @param legalName
     *        The legal name associated with your TRN information.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public TaxRegistrationWithJurisdiction withLegalName(String legalName) {
        setLegalName(legalName);
        return this;
    }

    /**
     * <p>
     * Your tax registration unique identifier.
     * </p>
     * 
     * @param registrationId
     *        Your tax registration unique identifier.
     */

    public void setRegistrationId(String registrationId) {
        this.registrationId = registrationId;
    }

    /**
     * <p>
     * Your tax registration unique identifier.
     * </p>
     * 
     * @return Your tax registration unique identifier.
     */

    public String getRegistrationId() {
        return this.registrationId;
    }

    /**
     * <p>
     * Your tax registration unique identifier.
     * </p>
     * 
     * @param registrationId
     *        Your tax registration unique identifier.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public TaxRegistrationWithJurisdiction withRegistrationId(String registrationId) {
        setRegistrationId(registrationId);
        return this;
    }

    /**
     * <p>
     * The type of your tax registration. This can be either <code>VAT</code> or <code>GST</code>.
     * </p>
     * 
     * @param registrationType
     *        The type of your tax registration. This can be either <code>VAT</code> or <code>GST</code>.
     * @see TaxRegistrationType
     */

    public void setRegistrationType(String registrationType) {
        this.registrationType = registrationType;
    }

    /**
     * <p>
     * The type of your tax registration. This can be either <code>VAT</code> or <code>GST</code>.
     * </p>
     * 
     * @return The type of your tax registration. This can be either <code>VAT</code> or <code>GST</code>.
     * @see TaxRegistrationType
     */

    public String getRegistrationType() {
        return this.registrationType;
    }

    /**
     * <p>
     * The type of your tax registration. This can be either <code>VAT</code> or <code>GST</code>.
     * </p>
     * 
     * @param registrationType
     *        The type of your tax registration. This can be either <code>VAT</code> or <code>GST</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see TaxRegistrationType
     */

    public TaxRegistrationWithJurisdiction withRegistrationType(String registrationType) {
        setRegistrationType(registrationType);
        return this;
    }

    /**
     * <p>
     * The type of your tax registration. This can be either <code>VAT</code> or <code>GST</code>.
     * </p>
     * 
     * @param registrationType
     *        The type of your tax registration. This can be either <code>VAT</code> or <code>GST</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see TaxRegistrationType
     */

    public TaxRegistrationWithJurisdiction withRegistrationType(TaxRegistrationType registrationType) {
        this.registrationType = registrationType.toString();
        return this;
    }

    /**
     * <p>
     * The industry that describes your business. For business-to-business (B2B) customers, specify Business. For
     * business-to-consumer (B2C) customers, specify Individual. For business-to-government (B2G), specify
     * Government.Note that certain values may not applicable for the request country. Please refer to country specific
     * information in API document.
     * </p>
     * 
     * @param sector
     *        The industry that describes your business. For business-to-business (B2B) customers, specify Business. For
     *        business-to-consumer (B2C) customers, specify Individual. For business-to-government (B2G), specify
     *        Government.Note that certain values may not applicable for the request country. Please refer to country
     *        specific information in API document.
     * @see Sector
     */

    public void setSector(String sector) {
        this.sector = sector;
    }

    /**
     * <p>
     * The industry that describes your business. For business-to-business (B2B) customers, specify Business. For
     * business-to-consumer (B2C) customers, specify Individual. For business-to-government (B2G), specify
     * Government.Note that certain values may not applicable for the request country. Please refer to country specific
     * information in API document.
     * </p>
     * 
     * @return The industry that describes your business. For business-to-business (B2B) customers, specify Business.
     *         For business-to-consumer (B2C) customers, specify Individual. For business-to-government (B2G), specify
     *         Government.Note that certain values may not applicable for the request country. Please refer to country
     *         specific information in API document.
     * @see Sector
     */

    public String getSector() {
        return this.sector;
    }

    /**
     * <p>
     * The industry that describes your business. For business-to-business (B2B) customers, specify Business. For
     * business-to-consumer (B2C) customers, specify Individual. For business-to-government (B2G), specify
     * Government.Note that certain values may not applicable for the request country. Please refer to country specific
     * information in API document.
     * </p>
     * 
     * @param sector
     *        The industry that describes your business. For business-to-business (B2B) customers, specify Business. For
     *        business-to-consumer (B2C) customers, specify Individual. For business-to-government (B2G), specify
     *        Government.Note that certain values may not applicable for the request country. Please refer to country
     *        specific information in API document.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see Sector
     */

    public TaxRegistrationWithJurisdiction withSector(String sector) {
        setSector(sector);
        return this;
    }

    /**
     * <p>
     * The industry that describes your business. For business-to-business (B2B) customers, specify Business. For
     * business-to-consumer (B2C) customers, specify Individual. For business-to-government (B2G), specify
     * Government.Note that certain values may not applicable for the request country. Please refer to country specific
     * information in API document.
     * </p>
     * 
     * @param sector
     *        The industry that describes your business. For business-to-business (B2B) customers, specify Business. For
     *        business-to-consumer (B2C) customers, specify Individual. For business-to-government (B2G), specify
     *        Government.Note that certain values may not applicable for the request country. Please refer to country
     *        specific information in API document.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see Sector
     */

    public TaxRegistrationWithJurisdiction withSector(Sector sector) {
        this.sector = sector.toString();
        return this;
    }

    /**
     * <p>
     * The status of your TRN. This can be either <code>Verified</code>, <code>Pending</code>, <code>Deleted</code>, or
     * <code>Rejected</code>.
     * </p>
     * 
     * @param status
     *        The status of your TRN. This can be either <code>Verified</code>, <code>Pending</code>,
     *        <code>Deleted</code>, or <code>Rejected</code>.
     * @see TaxRegistrationStatus
     */

    public void setStatus(String status) {
        this.status = status;
    }

    /**
     * <p>
     * The status of your TRN. This can be either <code>Verified</code>, <code>Pending</code>, <code>Deleted</code>, or
     * <code>Rejected</code>.
     * </p>
     * 
     * @return The status of your TRN. This can be either <code>Verified</code>, <code>Pending</code>,
     *         <code>Deleted</code>, or <code>Rejected</code>.
     * @see TaxRegistrationStatus
     */

    public String getStatus() {
        return this.status;
    }

    /**
     * <p>
     * The status of your TRN. This can be either <code>Verified</code>, <code>Pending</code>, <code>Deleted</code>, or
     * <code>Rejected</code>.
     * </p>
     * 
     * @param status
     *        The status of your TRN. This can be either <code>Verified</code>, <code>Pending</code>,
     *        <code>Deleted</code>, or <code>Rejected</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see TaxRegistrationStatus
     */

    public TaxRegistrationWithJurisdiction withStatus(String status) {
        setStatus(status);
        return this;
    }

    /**
     * <p>
     * The status of your TRN. This can be either <code>Verified</code>, <code>Pending</code>, <code>Deleted</code>, or
     * <code>Rejected</code>.
     * </p>
     * 
     * @param status
     *        The status of your TRN. This can be either <code>Verified</code>, <code>Pending</code>,
     *        <code>Deleted</code>, or <code>Rejected</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see TaxRegistrationStatus
     */

    public TaxRegistrationWithJurisdiction withStatus(TaxRegistrationStatus status) {
        this.status = status.toString();
        return this;
    }

    /**
     * <p>
     * The metadata for your tax document.
     * </p>
     * 
     * @return The metadata for your tax document.
     */

    public java.util.List<TaxDocumentMetadata> getTaxDocumentMetadatas() {
        return taxDocumentMetadatas;
    }

    /**
     * <p>
     * The metadata for your tax document.
     * </p>
     * 
     * @param taxDocumentMetadatas
     *        The metadata for your tax document.
     */

    public void setTaxDocumentMetadatas(java.util.Collection<TaxDocumentMetadata> taxDocumentMetadatas) {
        if (taxDocumentMetadatas == null) {
            this.taxDocumentMetadatas = null;
            return;
        }

        this.taxDocumentMetadatas = new java.util.ArrayList<TaxDocumentMetadata>(taxDocumentMetadatas);
    }

    /**
     * <p>
     * The metadata for your tax document.
     * </p>
     * <p>
     * <b>NOTE:</b> This method appends the values to the existing list (if any). Use
     * {@link #setTaxDocumentMetadatas(java.util.Collection)} or {@link #withTaxDocumentMetadatas(java.util.Collection)}
     * if you want to override the existing values.
     * </p>
     * 
     * @param taxDocumentMetadatas
     *        The metadata for your tax document.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public TaxRegistrationWithJurisdiction withTaxDocumentMetadatas(TaxDocumentMetadata... taxDocumentMetadatas) {
        if (this.taxDocumentMetadatas == null) {
            setTaxDocumentMetadatas(new java.util.ArrayList<TaxDocumentMetadata>(taxDocumentMetadatas.length));
        }
        for (TaxDocumentMetadata ele : taxDocumentMetadatas) {
            this.taxDocumentMetadatas.add(ele);
        }
        return this;
    }

    /**
     * <p>
     * The metadata for your tax document.
     * </p>
     * 
     * @param taxDocumentMetadatas
     *        The metadata for your tax document.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public TaxRegistrationWithJurisdiction withTaxDocumentMetadatas(java.util.Collection<TaxDocumentMetadata> taxDocumentMetadatas) {
        setTaxDocumentMetadatas(taxDocumentMetadatas);
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
        if (getAdditionalTaxInformation() != null)
            sb.append("AdditionalTaxInformation: ").append(getAdditionalTaxInformation()).append(",");
        if (getCertifiedEmailId() != null)
            sb.append("CertifiedEmailId: ").append(getCertifiedEmailId()).append(",");
        if (getJurisdiction() != null)
            sb.append("Jurisdiction: ").append(getJurisdiction()).append(",");
        if (getLegalName() != null)
            sb.append("LegalName: ").append(getLegalName()).append(",");
        if (getRegistrationId() != null)
            sb.append("RegistrationId: ").append(getRegistrationId()).append(",");
        if (getRegistrationType() != null)
            sb.append("RegistrationType: ").append(getRegistrationType()).append(",");
        if (getSector() != null)
            sb.append("Sector: ").append(getSector()).append(",");
        if (getStatus() != null)
            sb.append("Status: ").append(getStatus()).append(",");
        if (getTaxDocumentMetadatas() != null)
            sb.append("TaxDocumentMetadatas: ").append(getTaxDocumentMetadatas());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof TaxRegistrationWithJurisdiction == false)
            return false;
        TaxRegistrationWithJurisdiction other = (TaxRegistrationWithJurisdiction) obj;
        if (other.getAdditionalTaxInformation() == null ^ this.getAdditionalTaxInformation() == null)
            return false;
        if (other.getAdditionalTaxInformation() != null && other.getAdditionalTaxInformation().equals(this.getAdditionalTaxInformation()) == false)
            return false;
        if (other.getCertifiedEmailId() == null ^ this.getCertifiedEmailId() == null)
            return false;
        if (other.getCertifiedEmailId() != null && other.getCertifiedEmailId().equals(this.getCertifiedEmailId()) == false)
            return false;
        if (other.getJurisdiction() == null ^ this.getJurisdiction() == null)
            return false;
        if (other.getJurisdiction() != null && other.getJurisdiction().equals(this.getJurisdiction()) == false)
            return false;
        if (other.getLegalName() == null ^ this.getLegalName() == null)
            return false;
        if (other.getLegalName() != null && other.getLegalName().equals(this.getLegalName()) == false)
            return false;
        if (other.getRegistrationId() == null ^ this.getRegistrationId() == null)
            return false;
        if (other.getRegistrationId() != null && other.getRegistrationId().equals(this.getRegistrationId()) == false)
            return false;
        if (other.getRegistrationType() == null ^ this.getRegistrationType() == null)
            return false;
        if (other.getRegistrationType() != null && other.getRegistrationType().equals(this.getRegistrationType()) == false)
            return false;
        if (other.getSector() == null ^ this.getSector() == null)
            return false;
        if (other.getSector() != null && other.getSector().equals(this.getSector()) == false)
            return false;
        if (other.getStatus() == null ^ this.getStatus() == null)
            return false;
        if (other.getStatus() != null && other.getStatus().equals(this.getStatus()) == false)
            return false;
        if (other.getTaxDocumentMetadatas() == null ^ this.getTaxDocumentMetadatas() == null)
            return false;
        if (other.getTaxDocumentMetadatas() != null && other.getTaxDocumentMetadatas().equals(this.getTaxDocumentMetadatas()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getAdditionalTaxInformation() == null) ? 0 : getAdditionalTaxInformation().hashCode());
        hashCode = prime * hashCode + ((getCertifiedEmailId() == null) ? 0 : getCertifiedEmailId().hashCode());
        hashCode = prime * hashCode + ((getJurisdiction() == null) ? 0 : getJurisdiction().hashCode());
        hashCode = prime * hashCode + ((getLegalName() == null) ? 0 : getLegalName().hashCode());
        hashCode = prime * hashCode + ((getRegistrationId() == null) ? 0 : getRegistrationId().hashCode());
        hashCode = prime * hashCode + ((getRegistrationType() == null) ? 0 : getRegistrationType().hashCode());
        hashCode = prime * hashCode + ((getSector() == null) ? 0 : getSector().hashCode());
        hashCode = prime * hashCode + ((getStatus() == null) ? 0 : getStatus().hashCode());
        hashCode = prime * hashCode + ((getTaxDocumentMetadatas() == null) ? 0 : getTaxDocumentMetadatas().hashCode());
        return hashCode;
    }

    @Override
    public TaxRegistrationWithJurisdiction clone() {
        try {
            return (TaxRegistrationWithJurisdiction) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.taxsettings.model.transform.TaxRegistrationWithJurisdictionMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
