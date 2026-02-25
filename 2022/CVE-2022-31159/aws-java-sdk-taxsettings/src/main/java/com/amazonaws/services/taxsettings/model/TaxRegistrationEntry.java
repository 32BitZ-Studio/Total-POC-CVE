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
 * The TRN information you provide when you add a new TRN, or update.
 * </p>
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/taxsettings-2018-05-10/TaxRegistrationEntry" target="_top">AWS
 *      API Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class TaxRegistrationEntry implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * Additional tax information associated with your TRN. You only need to specify this parameter if Amazon Web
     * Services collects any additional information for your country within <a>AdditionalInfoRequest</a>.
     * </p>
     */
    private AdditionalInfoRequest additionalTaxInformation;
    /**
     * <p>
     * The email address to receive VAT invoices.
     * </p>
     */
    private String certifiedEmailId;
    /**
     * <p>
     * The legal address associated with your TRN.
     * </p>
     * <note>
     * <p>
     * If you're setting a TRN in Brazil for the CNPJ tax type, you don't need to specify the legal address.
     * </p>
     * <p>
     * For TRNs in other countries and for CPF tax types Brazil, you must specify the legal address.
     * </p>
     * </note>
     */
    private Address legalAddress;
    /**
     * <p>
     * The legal name associated with your TRN.
     * </p>
     * <note>
     * <p>
     * If you're setting a TRN in Brazil, you don't need to specify the legal name. For TRNs in other countries, you
     * must specify the legal name.
     * </p>
     * </note>
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
     * Your tax registration type. This can be either <code>VAT</code> or <code>GST</code>.
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
     * Additional details needed to verify your TRN information in Brazil. You only need to specify this parameter when
     * you set a TRN in Brazil that is the CPF tax type.
     * </p>
     * <note>
     * <p>
     * Don't specify this parameter to set a TRN in Brazil of the CNPJ tax type or to set a TRN for another country.
     * </p>
     * </note>
     */
    private VerificationDetails verificationDetails;

    /**
     * <p>
     * Additional tax information associated with your TRN. You only need to specify this parameter if Amazon Web
     * Services collects any additional information for your country within <a>AdditionalInfoRequest</a>.
     * </p>
     * 
     * @param additionalTaxInformation
     *        Additional tax information associated with your TRN. You only need to specify this parameter if Amazon Web
     *        Services collects any additional information for your country within <a>AdditionalInfoRequest</a>.
     */

    public void setAdditionalTaxInformation(AdditionalInfoRequest additionalTaxInformation) {
        this.additionalTaxInformation = additionalTaxInformation;
    }

    /**
     * <p>
     * Additional tax information associated with your TRN. You only need to specify this parameter if Amazon Web
     * Services collects any additional information for your country within <a>AdditionalInfoRequest</a>.
     * </p>
     * 
     * @return Additional tax information associated with your TRN. You only need to specify this parameter if Amazon
     *         Web Services collects any additional information for your country within <a>AdditionalInfoRequest</a>.
     */

    public AdditionalInfoRequest getAdditionalTaxInformation() {
        return this.additionalTaxInformation;
    }

    /**
     * <p>
     * Additional tax information associated with your TRN. You only need to specify this parameter if Amazon Web
     * Services collects any additional information for your country within <a>AdditionalInfoRequest</a>.
     * </p>
     * 
     * @param additionalTaxInformation
     *        Additional tax information associated with your TRN. You only need to specify this parameter if Amazon Web
     *        Services collects any additional information for your country within <a>AdditionalInfoRequest</a>.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public TaxRegistrationEntry withAdditionalTaxInformation(AdditionalInfoRequest additionalTaxInformation) {
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

    public TaxRegistrationEntry withCertifiedEmailId(String certifiedEmailId) {
        setCertifiedEmailId(certifiedEmailId);
        return this;
    }

    /**
     * <p>
     * The legal address associated with your TRN.
     * </p>
     * <note>
     * <p>
     * If you're setting a TRN in Brazil for the CNPJ tax type, you don't need to specify the legal address.
     * </p>
     * <p>
     * For TRNs in other countries and for CPF tax types Brazil, you must specify the legal address.
     * </p>
     * </note>
     * 
     * @param legalAddress
     *        The legal address associated with your TRN.</p> <note>
     *        <p>
     *        If you're setting a TRN in Brazil for the CNPJ tax type, you don't need to specify the legal address.
     *        </p>
     *        <p>
     *        For TRNs in other countries and for CPF tax types Brazil, you must specify the legal address.
     *        </p>
     */

    public void setLegalAddress(Address legalAddress) {
        this.legalAddress = legalAddress;
    }

    /**
     * <p>
     * The legal address associated with your TRN.
     * </p>
     * <note>
     * <p>
     * If you're setting a TRN in Brazil for the CNPJ tax type, you don't need to specify the legal address.
     * </p>
     * <p>
     * For TRNs in other countries and for CPF tax types Brazil, you must specify the legal address.
     * </p>
     * </note>
     * 
     * @return The legal address associated with your TRN.</p> <note>
     *         <p>
     *         If you're setting a TRN in Brazil for the CNPJ tax type, you don't need to specify the legal address.
     *         </p>
     *         <p>
     *         For TRNs in other countries and for CPF tax types Brazil, you must specify the legal address.
     *         </p>
     */

    public Address getLegalAddress() {
        return this.legalAddress;
    }

    /**
     * <p>
     * The legal address associated with your TRN.
     * </p>
     * <note>
     * <p>
     * If you're setting a TRN in Brazil for the CNPJ tax type, you don't need to specify the legal address.
     * </p>
     * <p>
     * For TRNs in other countries and for CPF tax types Brazil, you must specify the legal address.
     * </p>
     * </note>
     * 
     * @param legalAddress
     *        The legal address associated with your TRN.</p> <note>
     *        <p>
     *        If you're setting a TRN in Brazil for the CNPJ tax type, you don't need to specify the legal address.
     *        </p>
     *        <p>
     *        For TRNs in other countries and for CPF tax types Brazil, you must specify the legal address.
     *        </p>
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public TaxRegistrationEntry withLegalAddress(Address legalAddress) {
        setLegalAddress(legalAddress);
        return this;
    }

    /**
     * <p>
     * The legal name associated with your TRN.
     * </p>
     * <note>
     * <p>
     * If you're setting a TRN in Brazil, you don't need to specify the legal name. For TRNs in other countries, you
     * must specify the legal name.
     * </p>
     * </note>
     * 
     * @param legalName
     *        The legal name associated with your TRN. </p> <note>
     *        <p>
     *        If you're setting a TRN in Brazil, you don't need to specify the legal name. For TRNs in other countries,
     *        you must specify the legal name.
     *        </p>
     */

    public void setLegalName(String legalName) {
        this.legalName = legalName;
    }

    /**
     * <p>
     * The legal name associated with your TRN.
     * </p>
     * <note>
     * <p>
     * If you're setting a TRN in Brazil, you don't need to specify the legal name. For TRNs in other countries, you
     * must specify the legal name.
     * </p>
     * </note>
     * 
     * @return The legal name associated with your TRN. </p> <note>
     *         <p>
     *         If you're setting a TRN in Brazil, you don't need to specify the legal name. For TRNs in other countries,
     *         you must specify the legal name.
     *         </p>
     */

    public String getLegalName() {
        return this.legalName;
    }

    /**
     * <p>
     * The legal name associated with your TRN.
     * </p>
     * <note>
     * <p>
     * If you're setting a TRN in Brazil, you don't need to specify the legal name. For TRNs in other countries, you
     * must specify the legal name.
     * </p>
     * </note>
     * 
     * @param legalName
     *        The legal name associated with your TRN. </p> <note>
     *        <p>
     *        If you're setting a TRN in Brazil, you don't need to specify the legal name. For TRNs in other countries,
     *        you must specify the legal name.
     *        </p>
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public TaxRegistrationEntry withLegalName(String legalName) {
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

    public TaxRegistrationEntry withRegistrationId(String registrationId) {
        setRegistrationId(registrationId);
        return this;
    }

    /**
     * <p>
     * Your tax registration type. This can be either <code>VAT</code> or <code>GST</code>.
     * </p>
     * 
     * @param registrationType
     *        Your tax registration type. This can be either <code>VAT</code> or <code>GST</code>.
     * @see TaxRegistrationType
     */

    public void setRegistrationType(String registrationType) {
        this.registrationType = registrationType;
    }

    /**
     * <p>
     * Your tax registration type. This can be either <code>VAT</code> or <code>GST</code>.
     * </p>
     * 
     * @return Your tax registration type. This can be either <code>VAT</code> or <code>GST</code>.
     * @see TaxRegistrationType
     */

    public String getRegistrationType() {
        return this.registrationType;
    }

    /**
     * <p>
     * Your tax registration type. This can be either <code>VAT</code> or <code>GST</code>.
     * </p>
     * 
     * @param registrationType
     *        Your tax registration type. This can be either <code>VAT</code> or <code>GST</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see TaxRegistrationType
     */

    public TaxRegistrationEntry withRegistrationType(String registrationType) {
        setRegistrationType(registrationType);
        return this;
    }

    /**
     * <p>
     * Your tax registration type. This can be either <code>VAT</code> or <code>GST</code>.
     * </p>
     * 
     * @param registrationType
     *        Your tax registration type. This can be either <code>VAT</code> or <code>GST</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see TaxRegistrationType
     */

    public TaxRegistrationEntry withRegistrationType(TaxRegistrationType registrationType) {
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

    public TaxRegistrationEntry withSector(String sector) {
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

    public TaxRegistrationEntry withSector(Sector sector) {
        this.sector = sector.toString();
        return this;
    }

    /**
     * <p>
     * Additional details needed to verify your TRN information in Brazil. You only need to specify this parameter when
     * you set a TRN in Brazil that is the CPF tax type.
     * </p>
     * <note>
     * <p>
     * Don't specify this parameter to set a TRN in Brazil of the CNPJ tax type or to set a TRN for another country.
     * </p>
     * </note>
     * 
     * @param verificationDetails
     *        Additional details needed to verify your TRN information in Brazil. You only need to specify this
     *        parameter when you set a TRN in Brazil that is the CPF tax type.</p> <note>
     *        <p>
     *        Don't specify this parameter to set a TRN in Brazil of the CNPJ tax type or to set a TRN for another
     *        country.
     *        </p>
     */

    public void setVerificationDetails(VerificationDetails verificationDetails) {
        this.verificationDetails = verificationDetails;
    }

    /**
     * <p>
     * Additional details needed to verify your TRN information in Brazil. You only need to specify this parameter when
     * you set a TRN in Brazil that is the CPF tax type.
     * </p>
     * <note>
     * <p>
     * Don't specify this parameter to set a TRN in Brazil of the CNPJ tax type or to set a TRN for another country.
     * </p>
     * </note>
     * 
     * @return Additional details needed to verify your TRN information in Brazil. You only need to specify this
     *         parameter when you set a TRN in Brazil that is the CPF tax type.</p> <note>
     *         <p>
     *         Don't specify this parameter to set a TRN in Brazil of the CNPJ tax type or to set a TRN for another
     *         country.
     *         </p>
     */

    public VerificationDetails getVerificationDetails() {
        return this.verificationDetails;
    }

    /**
     * <p>
     * Additional details needed to verify your TRN information in Brazil. You only need to specify this parameter when
     * you set a TRN in Brazil that is the CPF tax type.
     * </p>
     * <note>
     * <p>
     * Don't specify this parameter to set a TRN in Brazil of the CNPJ tax type or to set a TRN for another country.
     * </p>
     * </note>
     * 
     * @param verificationDetails
     *        Additional details needed to verify your TRN information in Brazil. You only need to specify this
     *        parameter when you set a TRN in Brazil that is the CPF tax type.</p> <note>
     *        <p>
     *        Don't specify this parameter to set a TRN in Brazil of the CNPJ tax type or to set a TRN for another
     *        country.
     *        </p>
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public TaxRegistrationEntry withVerificationDetails(VerificationDetails verificationDetails) {
        setVerificationDetails(verificationDetails);
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
        if (getLegalAddress() != null)
            sb.append("LegalAddress: ").append(getLegalAddress()).append(",");
        if (getLegalName() != null)
            sb.append("LegalName: ").append(getLegalName()).append(",");
        if (getRegistrationId() != null)
            sb.append("RegistrationId: ").append(getRegistrationId()).append(",");
        if (getRegistrationType() != null)
            sb.append("RegistrationType: ").append(getRegistrationType()).append(",");
        if (getSector() != null)
            sb.append("Sector: ").append(getSector()).append(",");
        if (getVerificationDetails() != null)
            sb.append("VerificationDetails: ").append(getVerificationDetails());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof TaxRegistrationEntry == false)
            return false;
        TaxRegistrationEntry other = (TaxRegistrationEntry) obj;
        if (other.getAdditionalTaxInformation() == null ^ this.getAdditionalTaxInformation() == null)
            return false;
        if (other.getAdditionalTaxInformation() != null && other.getAdditionalTaxInformation().equals(this.getAdditionalTaxInformation()) == false)
            return false;
        if (other.getCertifiedEmailId() == null ^ this.getCertifiedEmailId() == null)
            return false;
        if (other.getCertifiedEmailId() != null && other.getCertifiedEmailId().equals(this.getCertifiedEmailId()) == false)
            return false;
        if (other.getLegalAddress() == null ^ this.getLegalAddress() == null)
            return false;
        if (other.getLegalAddress() != null && other.getLegalAddress().equals(this.getLegalAddress()) == false)
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
        if (other.getVerificationDetails() == null ^ this.getVerificationDetails() == null)
            return false;
        if (other.getVerificationDetails() != null && other.getVerificationDetails().equals(this.getVerificationDetails()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getAdditionalTaxInformation() == null) ? 0 : getAdditionalTaxInformation().hashCode());
        hashCode = prime * hashCode + ((getCertifiedEmailId() == null) ? 0 : getCertifiedEmailId().hashCode());
        hashCode = prime * hashCode + ((getLegalAddress() == null) ? 0 : getLegalAddress().hashCode());
        hashCode = prime * hashCode + ((getLegalName() == null) ? 0 : getLegalName().hashCode());
        hashCode = prime * hashCode + ((getRegistrationId() == null) ? 0 : getRegistrationId().hashCode());
        hashCode = prime * hashCode + ((getRegistrationType() == null) ? 0 : getRegistrationType().hashCode());
        hashCode = prime * hashCode + ((getSector() == null) ? 0 : getSector().hashCode());
        hashCode = prime * hashCode + ((getVerificationDetails() == null) ? 0 : getVerificationDetails().hashCode());
        return hashCode;
    }

    @Override
    public TaxRegistrationEntry clone() {
        try {
            return (TaxRegistrationEntry) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.taxsettings.model.transform.TaxRegistrationEntryMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
