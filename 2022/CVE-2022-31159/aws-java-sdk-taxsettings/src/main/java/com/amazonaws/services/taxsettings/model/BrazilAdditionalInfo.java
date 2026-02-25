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
 * Additional tax information associated with your TRN in Brazil.
 * </p>
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/taxsettings-2018-05-10/BrazilAdditionalInfo" target="_top">AWS
 *      API Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class BrazilAdditionalInfo implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * The Cadastro de Contribuintes Mobiliários (CCM) code for your TRN in Brazil. This only applies for a CNPJ tax
     * type for the São Paulo municipality.
     * </p>
     */
    private String ccmCode;
    /**
     * <p>
     * Legal nature of business, based on your TRN in Brazil. This only applies for a CNPJ tax type.
     * </p>
     */
    private String legalNatureCode;

    /**
     * <p>
     * The Cadastro de Contribuintes Mobiliários (CCM) code for your TRN in Brazil. This only applies for a CNPJ tax
     * type for the São Paulo municipality.
     * </p>
     * 
     * @param ccmCode
     *        The Cadastro de Contribuintes Mobiliários (CCM) code for your TRN in Brazil. This only applies for a CNPJ
     *        tax type for the São Paulo municipality.
     */

    public void setCcmCode(String ccmCode) {
        this.ccmCode = ccmCode;
    }

    /**
     * <p>
     * The Cadastro de Contribuintes Mobiliários (CCM) code for your TRN in Brazil. This only applies for a CNPJ tax
     * type for the São Paulo municipality.
     * </p>
     * 
     * @return The Cadastro de Contribuintes Mobiliários (CCM) code for your TRN in Brazil. This only applies for a CNPJ
     *         tax type for the São Paulo municipality.
     */

    public String getCcmCode() {
        return this.ccmCode;
    }

    /**
     * <p>
     * The Cadastro de Contribuintes Mobiliários (CCM) code for your TRN in Brazil. This only applies for a CNPJ tax
     * type for the São Paulo municipality.
     * </p>
     * 
     * @param ccmCode
     *        The Cadastro de Contribuintes Mobiliários (CCM) code for your TRN in Brazil. This only applies for a CNPJ
     *        tax type for the São Paulo municipality.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public BrazilAdditionalInfo withCcmCode(String ccmCode) {
        setCcmCode(ccmCode);
        return this;
    }

    /**
     * <p>
     * Legal nature of business, based on your TRN in Brazil. This only applies for a CNPJ tax type.
     * </p>
     * 
     * @param legalNatureCode
     *        Legal nature of business, based on your TRN in Brazil. This only applies for a CNPJ tax type.
     */

    public void setLegalNatureCode(String legalNatureCode) {
        this.legalNatureCode = legalNatureCode;
    }

    /**
     * <p>
     * Legal nature of business, based on your TRN in Brazil. This only applies for a CNPJ tax type.
     * </p>
     * 
     * @return Legal nature of business, based on your TRN in Brazil. This only applies for a CNPJ tax type.
     */

    public String getLegalNatureCode() {
        return this.legalNatureCode;
    }

    /**
     * <p>
     * Legal nature of business, based on your TRN in Brazil. This only applies for a CNPJ tax type.
     * </p>
     * 
     * @param legalNatureCode
     *        Legal nature of business, based on your TRN in Brazil. This only applies for a CNPJ tax type.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public BrazilAdditionalInfo withLegalNatureCode(String legalNatureCode) {
        setLegalNatureCode(legalNatureCode);
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
        if (getCcmCode() != null)
            sb.append("CcmCode: ").append(getCcmCode()).append(",");
        if (getLegalNatureCode() != null)
            sb.append("LegalNatureCode: ").append(getLegalNatureCode());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof BrazilAdditionalInfo == false)
            return false;
        BrazilAdditionalInfo other = (BrazilAdditionalInfo) obj;
        if (other.getCcmCode() == null ^ this.getCcmCode() == null)
            return false;
        if (other.getCcmCode() != null && other.getCcmCode().equals(this.getCcmCode()) == false)
            return false;
        if (other.getLegalNatureCode() == null ^ this.getLegalNatureCode() == null)
            return false;
        if (other.getLegalNatureCode() != null && other.getLegalNatureCode().equals(this.getLegalNatureCode()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getCcmCode() == null) ? 0 : getCcmCode().hashCode());
        hashCode = prime * hashCode + ((getLegalNatureCode() == null) ? 0 : getLegalNatureCode().hashCode());
        return hashCode;
    }

    @Override
    public BrazilAdditionalInfo clone() {
        try {
            return (BrazilAdditionalInfo) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.taxsettings.model.transform.BrazilAdditionalInfoMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
