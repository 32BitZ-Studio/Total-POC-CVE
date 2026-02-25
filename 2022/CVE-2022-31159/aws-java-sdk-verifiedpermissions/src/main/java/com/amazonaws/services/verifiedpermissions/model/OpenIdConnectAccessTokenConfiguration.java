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
package com.amazonaws.services.verifiedpermissions.model;

import java.io.Serializable;
import javax.annotation.Generated;
import com.amazonaws.protocol.StructuredPojo;
import com.amazonaws.protocol.ProtocolMarshaller;

/**
 * <p>
 * The configuration of an OpenID Connect (OIDC) identity source for handling access token claims. Contains the claim
 * that you want to identify as the principal in an authorization request, and the values of the <code>aud</code> claim,
 * or audiences, that you want to accept.
 * </p>
 * <p>
 * This data type is part of a <a
 * href="https://docs.aws.amazon.com/verifiedpermissions/latest/apireference/API_OpenIdConnectTokenSelection.html"
 * >OpenIdConnectTokenSelection</a> structure, which is a parameter of <a
 * href="https://docs.aws.amazon.com/verifiedpermissions/latest/apireference/API_CreateIdentitySource.html"
 * >CreateIdentitySource</a>.
 * </p>
 * 
 * @see <a
 *      href="http://docs.aws.amazon.com/goto/WebAPI/verifiedpermissions-2021-12-01/OpenIdConnectAccessTokenConfiguration"
 *      target="_top">AWS API Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class OpenIdConnectAccessTokenConfiguration implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * The claim that determines the principal in OIDC access tokens. For example, <code>sub</code>.
     * </p>
     */
    private String principalIdClaim;
    /**
     * <p>
     * The access token <code>aud</code> claim values that you want to accept in your policy store. For example,
     * <code>https://myapp.example.com, https://myapp2.example.com</code>.
     * </p>
     */
    private java.util.List<String> audiences;

    /**
     * <p>
     * The claim that determines the principal in OIDC access tokens. For example, <code>sub</code>.
     * </p>
     * 
     * @param principalIdClaim
     *        The claim that determines the principal in OIDC access tokens. For example, <code>sub</code>.
     */

    public void setPrincipalIdClaim(String principalIdClaim) {
        this.principalIdClaim = principalIdClaim;
    }

    /**
     * <p>
     * The claim that determines the principal in OIDC access tokens. For example, <code>sub</code>.
     * </p>
     * 
     * @return The claim that determines the principal in OIDC access tokens. For example, <code>sub</code>.
     */

    public String getPrincipalIdClaim() {
        return this.principalIdClaim;
    }

    /**
     * <p>
     * The claim that determines the principal in OIDC access tokens. For example, <code>sub</code>.
     * </p>
     * 
     * @param principalIdClaim
     *        The claim that determines the principal in OIDC access tokens. For example, <code>sub</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public OpenIdConnectAccessTokenConfiguration withPrincipalIdClaim(String principalIdClaim) {
        setPrincipalIdClaim(principalIdClaim);
        return this;
    }

    /**
     * <p>
     * The access token <code>aud</code> claim values that you want to accept in your policy store. For example,
     * <code>https://myapp.example.com, https://myapp2.example.com</code>.
     * </p>
     * 
     * @return The access token <code>aud</code> claim values that you want to accept in your policy store. For example,
     *         <code>https://myapp.example.com, https://myapp2.example.com</code>.
     */

    public java.util.List<String> getAudiences() {
        return audiences;
    }

    /**
     * <p>
     * The access token <code>aud</code> claim values that you want to accept in your policy store. For example,
     * <code>https://myapp.example.com, https://myapp2.example.com</code>.
     * </p>
     * 
     * @param audiences
     *        The access token <code>aud</code> claim values that you want to accept in your policy store. For example,
     *        <code>https://myapp.example.com, https://myapp2.example.com</code>.
     */

    public void setAudiences(java.util.Collection<String> audiences) {
        if (audiences == null) {
            this.audiences = null;
            return;
        }

        this.audiences = new java.util.ArrayList<String>(audiences);
    }

    /**
     * <p>
     * The access token <code>aud</code> claim values that you want to accept in your policy store. For example,
     * <code>https://myapp.example.com, https://myapp2.example.com</code>.
     * </p>
     * <p>
     * <b>NOTE:</b> This method appends the values to the existing list (if any). Use
     * {@link #setAudiences(java.util.Collection)} or {@link #withAudiences(java.util.Collection)} if you want to
     * override the existing values.
     * </p>
     * 
     * @param audiences
     *        The access token <code>aud</code> claim values that you want to accept in your policy store. For example,
     *        <code>https://myapp.example.com, https://myapp2.example.com</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public OpenIdConnectAccessTokenConfiguration withAudiences(String... audiences) {
        if (this.audiences == null) {
            setAudiences(new java.util.ArrayList<String>(audiences.length));
        }
        for (String ele : audiences) {
            this.audiences.add(ele);
        }
        return this;
    }

    /**
     * <p>
     * The access token <code>aud</code> claim values that you want to accept in your policy store. For example,
     * <code>https://myapp.example.com, https://myapp2.example.com</code>.
     * </p>
     * 
     * @param audiences
     *        The access token <code>aud</code> claim values that you want to accept in your policy store. For example,
     *        <code>https://myapp.example.com, https://myapp2.example.com</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public OpenIdConnectAccessTokenConfiguration withAudiences(java.util.Collection<String> audiences) {
        setAudiences(audiences);
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
        if (getPrincipalIdClaim() != null)
            sb.append("PrincipalIdClaim: ").append("***Sensitive Data Redacted***").append(",");
        if (getAudiences() != null)
            sb.append("Audiences: ").append(getAudiences());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof OpenIdConnectAccessTokenConfiguration == false)
            return false;
        OpenIdConnectAccessTokenConfiguration other = (OpenIdConnectAccessTokenConfiguration) obj;
        if (other.getPrincipalIdClaim() == null ^ this.getPrincipalIdClaim() == null)
            return false;
        if (other.getPrincipalIdClaim() != null && other.getPrincipalIdClaim().equals(this.getPrincipalIdClaim()) == false)
            return false;
        if (other.getAudiences() == null ^ this.getAudiences() == null)
            return false;
        if (other.getAudiences() != null && other.getAudiences().equals(this.getAudiences()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getPrincipalIdClaim() == null) ? 0 : getPrincipalIdClaim().hashCode());
        hashCode = prime * hashCode + ((getAudiences() == null) ? 0 : getAudiences().hashCode());
        return hashCode;
    }

    @Override
    public OpenIdConnectAccessTokenConfiguration clone() {
        try {
            return (OpenIdConnectAccessTokenConfiguration) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.verifiedpermissions.model.transform.OpenIdConnectAccessTokenConfigurationMarshaller.getInstance().marshall(this,
                protocolMarshaller);
    }
}
