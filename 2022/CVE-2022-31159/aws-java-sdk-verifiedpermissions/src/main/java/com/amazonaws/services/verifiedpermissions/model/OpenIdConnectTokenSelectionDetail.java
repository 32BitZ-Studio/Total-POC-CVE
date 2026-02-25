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
 * The token type that you want to process from your OIDC identity provider. Your policy store can process either
 * identity (ID) or access tokens from a given OIDC identity source.
 * </p>
 * <p>
 * This data type is part of a <a href=
 * "https://docs.aws.amazon.com/verifiedpermissions/latest/apireference/API_OpenIdConnectConfigurationDetail.html"
 * >OpenIdConnectConfigurationDetail</a> structure, which is a parameter of <a
 * href="https://docs.aws.amazon.com/verifiedpermissions/latest/apireference/API_GetIdentitySource.html"
 * >GetIdentitySource</a>.
 * </p>
 * 
 * @see <a
 *      href="http://docs.aws.amazon.com/goto/WebAPI/verifiedpermissions-2021-12-01/OpenIdConnectTokenSelectionDetail"
 *      target="_top">AWS API Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class OpenIdConnectTokenSelectionDetail implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * The OIDC configuration for processing access tokens. Contains allowed audience claims, for example
     * <code>https://auth.example.com</code>, and the claim that you want to map to the principal, for example
     * <code>sub</code>.
     * </p>
     */
    private OpenIdConnectAccessTokenConfigurationDetail accessTokenOnly;
    /**
     * <p>
     * The OIDC configuration for processing identity (ID) tokens. Contains allowed client ID claims, for example
     * <code>1example23456789</code>, and the claim that you want to map to the principal, for example <code>sub</code>.
     * </p>
     */
    private OpenIdConnectIdentityTokenConfigurationDetail identityTokenOnly;

    /**
     * <p>
     * The OIDC configuration for processing access tokens. Contains allowed audience claims, for example
     * <code>https://auth.example.com</code>, and the claim that you want to map to the principal, for example
     * <code>sub</code>.
     * </p>
     * 
     * @param accessTokenOnly
     *        The OIDC configuration for processing access tokens. Contains allowed audience claims, for example
     *        <code>https://auth.example.com</code>, and the claim that you want to map to the principal, for example
     *        <code>sub</code>.
     */

    public void setAccessTokenOnly(OpenIdConnectAccessTokenConfigurationDetail accessTokenOnly) {
        this.accessTokenOnly = accessTokenOnly;
    }

    /**
     * <p>
     * The OIDC configuration for processing access tokens. Contains allowed audience claims, for example
     * <code>https://auth.example.com</code>, and the claim that you want to map to the principal, for example
     * <code>sub</code>.
     * </p>
     * 
     * @return The OIDC configuration for processing access tokens. Contains allowed audience claims, for example
     *         <code>https://auth.example.com</code>, and the claim that you want to map to the principal, for example
     *         <code>sub</code>.
     */

    public OpenIdConnectAccessTokenConfigurationDetail getAccessTokenOnly() {
        return this.accessTokenOnly;
    }

    /**
     * <p>
     * The OIDC configuration for processing access tokens. Contains allowed audience claims, for example
     * <code>https://auth.example.com</code>, and the claim that you want to map to the principal, for example
     * <code>sub</code>.
     * </p>
     * 
     * @param accessTokenOnly
     *        The OIDC configuration for processing access tokens. Contains allowed audience claims, for example
     *        <code>https://auth.example.com</code>, and the claim that you want to map to the principal, for example
     *        <code>sub</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public OpenIdConnectTokenSelectionDetail withAccessTokenOnly(OpenIdConnectAccessTokenConfigurationDetail accessTokenOnly) {
        setAccessTokenOnly(accessTokenOnly);
        return this;
    }

    /**
     * <p>
     * The OIDC configuration for processing identity (ID) tokens. Contains allowed client ID claims, for example
     * <code>1example23456789</code>, and the claim that you want to map to the principal, for example <code>sub</code>.
     * </p>
     * 
     * @param identityTokenOnly
     *        The OIDC configuration for processing identity (ID) tokens. Contains allowed client ID claims, for example
     *        <code>1example23456789</code>, and the claim that you want to map to the principal, for example
     *        <code>sub</code>.
     */

    public void setIdentityTokenOnly(OpenIdConnectIdentityTokenConfigurationDetail identityTokenOnly) {
        this.identityTokenOnly = identityTokenOnly;
    }

    /**
     * <p>
     * The OIDC configuration for processing identity (ID) tokens. Contains allowed client ID claims, for example
     * <code>1example23456789</code>, and the claim that you want to map to the principal, for example <code>sub</code>.
     * </p>
     * 
     * @return The OIDC configuration for processing identity (ID) tokens. Contains allowed client ID claims, for
     *         example <code>1example23456789</code>, and the claim that you want to map to the principal, for example
     *         <code>sub</code>.
     */

    public OpenIdConnectIdentityTokenConfigurationDetail getIdentityTokenOnly() {
        return this.identityTokenOnly;
    }

    /**
     * <p>
     * The OIDC configuration for processing identity (ID) tokens. Contains allowed client ID claims, for example
     * <code>1example23456789</code>, and the claim that you want to map to the principal, for example <code>sub</code>.
     * </p>
     * 
     * @param identityTokenOnly
     *        The OIDC configuration for processing identity (ID) tokens. Contains allowed client ID claims, for example
     *        <code>1example23456789</code>, and the claim that you want to map to the principal, for example
     *        <code>sub</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public OpenIdConnectTokenSelectionDetail withIdentityTokenOnly(OpenIdConnectIdentityTokenConfigurationDetail identityTokenOnly) {
        setIdentityTokenOnly(identityTokenOnly);
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
        if (getAccessTokenOnly() != null)
            sb.append("AccessTokenOnly: ").append(getAccessTokenOnly()).append(",");
        if (getIdentityTokenOnly() != null)
            sb.append("IdentityTokenOnly: ").append(getIdentityTokenOnly());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof OpenIdConnectTokenSelectionDetail == false)
            return false;
        OpenIdConnectTokenSelectionDetail other = (OpenIdConnectTokenSelectionDetail) obj;
        if (other.getAccessTokenOnly() == null ^ this.getAccessTokenOnly() == null)
            return false;
        if (other.getAccessTokenOnly() != null && other.getAccessTokenOnly().equals(this.getAccessTokenOnly()) == false)
            return false;
        if (other.getIdentityTokenOnly() == null ^ this.getIdentityTokenOnly() == null)
            return false;
        if (other.getIdentityTokenOnly() != null && other.getIdentityTokenOnly().equals(this.getIdentityTokenOnly()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getAccessTokenOnly() == null) ? 0 : getAccessTokenOnly().hashCode());
        hashCode = prime * hashCode + ((getIdentityTokenOnly() == null) ? 0 : getIdentityTokenOnly().hashCode());
        return hashCode;
    }

    @Override
    public OpenIdConnectTokenSelectionDetail clone() {
        try {
            return (OpenIdConnectTokenSelectionDetail) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.verifiedpermissions.model.transform.OpenIdConnectTokenSelectionDetailMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
