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
 * Additional tax information associated with your TRN in Italy.
 * </p>
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/taxsettings-2018-05-10/ItalyAdditionalInfo" target="_top">AWS
 *      API Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class ItalyAdditionalInfo implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * The tender procedure identification code.
     * </p>
     */
    private String cigNumber;
    /**
     * <p>
     * Additional tax information to specify for a TRN in Italy. This is managed by the Interministerial Committee for
     * Economic Planning (CIPE) which characterizes every public investment project (Individual Project Code).
     * </p>
     */
    private String cupNumber;
    /**
     * <p>
     * Additional tax information to specify for a TRN in Italy. Use CodiceDestinatario to receive your invoices via web
     * service (API) or FTP.
     * </p>
     */
    private String sdiAccountId;
    /**
     * <p>
     * List of service tax codes for your TRN in Italy. You can use your customer tax code as part of a VAT Group.
     * </p>
     */
    private String taxCode;

    /**
     * <p>
     * The tender procedure identification code.
     * </p>
     * 
     * @param cigNumber
     *        The tender procedure identification code.
     */

    public void setCigNumber(String cigNumber) {
        this.cigNumber = cigNumber;
    }

    /**
     * <p>
     * The tender procedure identification code.
     * </p>
     * 
     * @return The tender procedure identification code.
     */

    public String getCigNumber() {
        return this.cigNumber;
    }

    /**
     * <p>
     * The tender procedure identification code.
     * </p>
     * 
     * @param cigNumber
     *        The tender procedure identification code.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ItalyAdditionalInfo withCigNumber(String cigNumber) {
        setCigNumber(cigNumber);
        return this;
    }

    /**
     * <p>
     * Additional tax information to specify for a TRN in Italy. This is managed by the Interministerial Committee for
     * Economic Planning (CIPE) which characterizes every public investment project (Individual Project Code).
     * </p>
     * 
     * @param cupNumber
     *        Additional tax information to specify for a TRN in Italy. This is managed by the Interministerial
     *        Committee for Economic Planning (CIPE) which characterizes every public investment project (Individual
     *        Project Code).
     */

    public void setCupNumber(String cupNumber) {
        this.cupNumber = cupNumber;
    }

    /**
     * <p>
     * Additional tax information to specify for a TRN in Italy. This is managed by the Interministerial Committee for
     * Economic Planning (CIPE) which characterizes every public investment project (Individual Project Code).
     * </p>
     * 
     * @return Additional tax information to specify for a TRN in Italy. This is managed by the Interministerial
     *         Committee for Economic Planning (CIPE) which characterizes every public investment project (Individual
     *         Project Code).
     */

    public String getCupNumber() {
        return this.cupNumber;
    }

    /**
     * <p>
     * Additional tax information to specify for a TRN in Italy. This is managed by the Interministerial Committee for
     * Economic Planning (CIPE) which characterizes every public investment project (Individual Project Code).
     * </p>
     * 
     * @param cupNumber
     *        Additional tax information to specify for a TRN in Italy. This is managed by the Interministerial
     *        Committee for Economic Planning (CIPE) which characterizes every public investment project (Individual
     *        Project Code).
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ItalyAdditionalInfo withCupNumber(String cupNumber) {
        setCupNumber(cupNumber);
        return this;
    }

    /**
     * <p>
     * Additional tax information to specify for a TRN in Italy. Use CodiceDestinatario to receive your invoices via web
     * service (API) or FTP.
     * </p>
     * 
     * @param sdiAccountId
     *        Additional tax information to specify for a TRN in Italy. Use CodiceDestinatario to receive your invoices
     *        via web service (API) or FTP.
     */

    public void setSdiAccountId(String sdiAccountId) {
        this.sdiAccountId = sdiAccountId;
    }

    /**
     * <p>
     * Additional tax information to specify for a TRN in Italy. Use CodiceDestinatario to receive your invoices via web
     * service (API) or FTP.
     * </p>
     * 
     * @return Additional tax information to specify for a TRN in Italy. Use CodiceDestinatario to receive your invoices
     *         via web service (API) or FTP.
     */

    public String getSdiAccountId() {
        return this.sdiAccountId;
    }

    /**
     * <p>
     * Additional tax information to specify for a TRN in Italy. Use CodiceDestinatario to receive your invoices via web
     * service (API) or FTP.
     * </p>
     * 
     * @param sdiAccountId
     *        Additional tax information to specify for a TRN in Italy. Use CodiceDestinatario to receive your invoices
     *        via web service (API) or FTP.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ItalyAdditionalInfo withSdiAccountId(String sdiAccountId) {
        setSdiAccountId(sdiAccountId);
        return this;
    }

    /**
     * <p>
     * List of service tax codes for your TRN in Italy. You can use your customer tax code as part of a VAT Group.
     * </p>
     * 
     * @param taxCode
     *        List of service tax codes for your TRN in Italy. You can use your customer tax code as part of a VAT
     *        Group.
     */

    public void setTaxCode(String taxCode) {
        this.taxCode = taxCode;
    }

    /**
     * <p>
     * List of service tax codes for your TRN in Italy. You can use your customer tax code as part of a VAT Group.
     * </p>
     * 
     * @return List of service tax codes for your TRN in Italy. You can use your customer tax code as part of a VAT
     *         Group.
     */

    public String getTaxCode() {
        return this.taxCode;
    }

    /**
     * <p>
     * List of service tax codes for your TRN in Italy. You can use your customer tax code as part of a VAT Group.
     * </p>
     * 
     * @param taxCode
     *        List of service tax codes for your TRN in Italy. You can use your customer tax code as part of a VAT
     *        Group.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ItalyAdditionalInfo withTaxCode(String taxCode) {
        setTaxCode(taxCode);
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
        if (getCigNumber() != null)
            sb.append("CigNumber: ").append(getCigNumber()).append(",");
        if (getCupNumber() != null)
            sb.append("CupNumber: ").append(getCupNumber()).append(",");
        if (getSdiAccountId() != null)
            sb.append("SdiAccountId: ").append(getSdiAccountId()).append(",");
        if (getTaxCode() != null)
            sb.append("TaxCode: ").append(getTaxCode());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof ItalyAdditionalInfo == false)
            return false;
        ItalyAdditionalInfo other = (ItalyAdditionalInfo) obj;
        if (other.getCigNumber() == null ^ this.getCigNumber() == null)
            return false;
        if (other.getCigNumber() != null && other.getCigNumber().equals(this.getCigNumber()) == false)
            return false;
        if (other.getCupNumber() == null ^ this.getCupNumber() == null)
            return false;
        if (other.getCupNumber() != null && other.getCupNumber().equals(this.getCupNumber()) == false)
            return false;
        if (other.getSdiAccountId() == null ^ this.getSdiAccountId() == null)
            return false;
        if (other.getSdiAccountId() != null && other.getSdiAccountId().equals(this.getSdiAccountId()) == false)
            return false;
        if (other.getTaxCode() == null ^ this.getTaxCode() == null)
            return false;
        if (other.getTaxCode() != null && other.getTaxCode().equals(this.getTaxCode()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getCigNumber() == null) ? 0 : getCigNumber().hashCode());
        hashCode = prime * hashCode + ((getCupNumber() == null) ? 0 : getCupNumber().hashCode());
        hashCode = prime * hashCode + ((getSdiAccountId() == null) ? 0 : getSdiAccountId().hashCode());
        hashCode = prime * hashCode + ((getTaxCode() == null) ? 0 : getTaxCode().hashCode());
        return hashCode;
    }

    @Override
    public ItalyAdditionalInfo clone() {
        try {
            return (ItalyAdditionalInfo) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.taxsettings.model.transform.ItalyAdditionalInfoMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
