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
 * The metadata for your tax document.
 * </p>
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/taxsettings-2018-05-10/TaxDocumentMetadata" target="_top">AWS
 *      API Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class TaxDocumentMetadata implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * The tax document access token, which contains information that the Tax Settings API uses to locate the tax
     * document.
     * </p>
     * <note>
     * <p>
     * If you update your tax registration, the existing <code>taxDocumentAccessToken</code> won't be valid. To get the
     * latest token, call the <code>GetTaxRegistration</code> or <code>ListTaxRegistrations</code> API operation. This
     * token is valid for 24 hours.
     * </p>
     * </note>
     */
    private String taxDocumentAccessToken;
    /**
     * <p>
     * The name of your tax document.
     * </p>
     */
    private String taxDocumentName;

    /**
     * <p>
     * The tax document access token, which contains information that the Tax Settings API uses to locate the tax
     * document.
     * </p>
     * <note>
     * <p>
     * If you update your tax registration, the existing <code>taxDocumentAccessToken</code> won't be valid. To get the
     * latest token, call the <code>GetTaxRegistration</code> or <code>ListTaxRegistrations</code> API operation. This
     * token is valid for 24 hours.
     * </p>
     * </note>
     * 
     * @param taxDocumentAccessToken
     *        The tax document access token, which contains information that the Tax Settings API uses to locate the tax
     *        document.</p> <note>
     *        <p>
     *        If you update your tax registration, the existing <code>taxDocumentAccessToken</code> won't be valid. To
     *        get the latest token, call the <code>GetTaxRegistration</code> or <code>ListTaxRegistrations</code> API
     *        operation. This token is valid for 24 hours.
     *        </p>
     */

    public void setTaxDocumentAccessToken(String taxDocumentAccessToken) {
        this.taxDocumentAccessToken = taxDocumentAccessToken;
    }

    /**
     * <p>
     * The tax document access token, which contains information that the Tax Settings API uses to locate the tax
     * document.
     * </p>
     * <note>
     * <p>
     * If you update your tax registration, the existing <code>taxDocumentAccessToken</code> won't be valid. To get the
     * latest token, call the <code>GetTaxRegistration</code> or <code>ListTaxRegistrations</code> API operation. This
     * token is valid for 24 hours.
     * </p>
     * </note>
     * 
     * @return The tax document access token, which contains information that the Tax Settings API uses to locate the
     *         tax document.</p> <note>
     *         <p>
     *         If you update your tax registration, the existing <code>taxDocumentAccessToken</code> won't be valid. To
     *         get the latest token, call the <code>GetTaxRegistration</code> or <code>ListTaxRegistrations</code> API
     *         operation. This token is valid for 24 hours.
     *         </p>
     */

    public String getTaxDocumentAccessToken() {
        return this.taxDocumentAccessToken;
    }

    /**
     * <p>
     * The tax document access token, which contains information that the Tax Settings API uses to locate the tax
     * document.
     * </p>
     * <note>
     * <p>
     * If you update your tax registration, the existing <code>taxDocumentAccessToken</code> won't be valid. To get the
     * latest token, call the <code>GetTaxRegistration</code> or <code>ListTaxRegistrations</code> API operation. This
     * token is valid for 24 hours.
     * </p>
     * </note>
     * 
     * @param taxDocumentAccessToken
     *        The tax document access token, which contains information that the Tax Settings API uses to locate the tax
     *        document.</p> <note>
     *        <p>
     *        If you update your tax registration, the existing <code>taxDocumentAccessToken</code> won't be valid. To
     *        get the latest token, call the <code>GetTaxRegistration</code> or <code>ListTaxRegistrations</code> API
     *        operation. This token is valid for 24 hours.
     *        </p>
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public TaxDocumentMetadata withTaxDocumentAccessToken(String taxDocumentAccessToken) {
        setTaxDocumentAccessToken(taxDocumentAccessToken);
        return this;
    }

    /**
     * <p>
     * The name of your tax document.
     * </p>
     * 
     * @param taxDocumentName
     *        The name of your tax document.
     */

    public void setTaxDocumentName(String taxDocumentName) {
        this.taxDocumentName = taxDocumentName;
    }

    /**
     * <p>
     * The name of your tax document.
     * </p>
     * 
     * @return The name of your tax document.
     */

    public String getTaxDocumentName() {
        return this.taxDocumentName;
    }

    /**
     * <p>
     * The name of your tax document.
     * </p>
     * 
     * @param taxDocumentName
     *        The name of your tax document.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public TaxDocumentMetadata withTaxDocumentName(String taxDocumentName) {
        setTaxDocumentName(taxDocumentName);
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
        if (getTaxDocumentAccessToken() != null)
            sb.append("TaxDocumentAccessToken: ").append(getTaxDocumentAccessToken()).append(",");
        if (getTaxDocumentName() != null)
            sb.append("TaxDocumentName: ").append(getTaxDocumentName());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof TaxDocumentMetadata == false)
            return false;
        TaxDocumentMetadata other = (TaxDocumentMetadata) obj;
        if (other.getTaxDocumentAccessToken() == null ^ this.getTaxDocumentAccessToken() == null)
            return false;
        if (other.getTaxDocumentAccessToken() != null && other.getTaxDocumentAccessToken().equals(this.getTaxDocumentAccessToken()) == false)
            return false;
        if (other.getTaxDocumentName() == null ^ this.getTaxDocumentName() == null)
            return false;
        if (other.getTaxDocumentName() != null && other.getTaxDocumentName().equals(this.getTaxDocumentName()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getTaxDocumentAccessToken() == null) ? 0 : getTaxDocumentAccessToken().hashCode());
        hashCode = prime * hashCode + ((getTaxDocumentName() == null) ? 0 : getTaxDocumentName().hashCode());
        return hashCode;
    }

    @Override
    public TaxDocumentMetadata clone() {
        try {
            return (TaxDocumentMetadata) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.taxsettings.model.transform.TaxDocumentMetadataMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
