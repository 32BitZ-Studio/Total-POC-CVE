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
package com.amazonaws.services.pcaconnectorscep.model;

import java.io.Serializable;
import javax.annotation.Generated;
import com.amazonaws.protocol.StructuredPojo;
import com.amazonaws.protocol.ProtocolMarshaller;

/**
 * <p>
 * Contains OpenID Connect (OIDC) parameters for use with Microsoft Intune. For more information about using Connector
 * for SCEP for Microsoft Intune, see <a
 * href="https://docs.aws.amazon.com/privateca/latest/userguide/scep-connector.htmlconnector-for-scep-intune.html">Using
 * Connector for SCEP for Microsoft Intune</a>.
 * </p>
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/pca-connector-scep-2018-05-10/OpenIdConfiguration"
 *      target="_top">AWS API Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class OpenIdConfiguration implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * The issuer value to copy into your Microsoft Entra app registration's OIDC.
     * </p>
     */
    private String issuer;
    /**
     * <p>
     * The subject value to copy into your Microsoft Entra app registration's OIDC.
     * </p>
     */
    private String subject;
    /**
     * <p>
     * The audience value to copy into your Microsoft Entra app registration's OIDC.
     * </p>
     */
    private String audience;

    /**
     * <p>
     * The issuer value to copy into your Microsoft Entra app registration's OIDC.
     * </p>
     * 
     * @param issuer
     *        The issuer value to copy into your Microsoft Entra app registration's OIDC.
     */

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    /**
     * <p>
     * The issuer value to copy into your Microsoft Entra app registration's OIDC.
     * </p>
     * 
     * @return The issuer value to copy into your Microsoft Entra app registration's OIDC.
     */

    public String getIssuer() {
        return this.issuer;
    }

    /**
     * <p>
     * The issuer value to copy into your Microsoft Entra app registration's OIDC.
     * </p>
     * 
     * @param issuer
     *        The issuer value to copy into your Microsoft Entra app registration's OIDC.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public OpenIdConfiguration withIssuer(String issuer) {
        setIssuer(issuer);
        return this;
    }

    /**
     * <p>
     * The subject value to copy into your Microsoft Entra app registration's OIDC.
     * </p>
     * 
     * @param subject
     *        The subject value to copy into your Microsoft Entra app registration's OIDC.
     */

    public void setSubject(String subject) {
        this.subject = subject;
    }

    /**
     * <p>
     * The subject value to copy into your Microsoft Entra app registration's OIDC.
     * </p>
     * 
     * @return The subject value to copy into your Microsoft Entra app registration's OIDC.
     */

    public String getSubject() {
        return this.subject;
    }

    /**
     * <p>
     * The subject value to copy into your Microsoft Entra app registration's OIDC.
     * </p>
     * 
     * @param subject
     *        The subject value to copy into your Microsoft Entra app registration's OIDC.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public OpenIdConfiguration withSubject(String subject) {
        setSubject(subject);
        return this;
    }

    /**
     * <p>
     * The audience value to copy into your Microsoft Entra app registration's OIDC.
     * </p>
     * 
     * @param audience
     *        The audience value to copy into your Microsoft Entra app registration's OIDC.
     */

    public void setAudience(String audience) {
        this.audience = audience;
    }

    /**
     * <p>
     * The audience value to copy into your Microsoft Entra app registration's OIDC.
     * </p>
     * 
     * @return The audience value to copy into your Microsoft Entra app registration's OIDC.
     */

    public String getAudience() {
        return this.audience;
    }

    /**
     * <p>
     * The audience value to copy into your Microsoft Entra app registration's OIDC.
     * </p>
     * 
     * @param audience
     *        The audience value to copy into your Microsoft Entra app registration's OIDC.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public OpenIdConfiguration withAudience(String audience) {
        setAudience(audience);
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
        if (getIssuer() != null)
            sb.append("Issuer: ").append(getIssuer()).append(",");
        if (getSubject() != null)
            sb.append("Subject: ").append(getSubject()).append(",");
        if (getAudience() != null)
            sb.append("Audience: ").append(getAudience());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof OpenIdConfiguration == false)
            return false;
        OpenIdConfiguration other = (OpenIdConfiguration) obj;
        if (other.getIssuer() == null ^ this.getIssuer() == null)
            return false;
        if (other.getIssuer() != null && other.getIssuer().equals(this.getIssuer()) == false)
            return false;
        if (other.getSubject() == null ^ this.getSubject() == null)
            return false;
        if (other.getSubject() != null && other.getSubject().equals(this.getSubject()) == false)
            return false;
        if (other.getAudience() == null ^ this.getAudience() == null)
            return false;
        if (other.getAudience() != null && other.getAudience().equals(this.getAudience()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getIssuer() == null) ? 0 : getIssuer().hashCode());
        hashCode = prime * hashCode + ((getSubject() == null) ? 0 : getSubject().hashCode());
        hashCode = prime * hashCode + ((getAudience() == null) ? 0 : getAudience().hashCode());
        return hashCode;
    }

    @Override
    public OpenIdConfiguration clone() {
        try {
            return (OpenIdConfiguration) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.pcaconnectorscep.model.transform.OpenIdConfigurationMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
