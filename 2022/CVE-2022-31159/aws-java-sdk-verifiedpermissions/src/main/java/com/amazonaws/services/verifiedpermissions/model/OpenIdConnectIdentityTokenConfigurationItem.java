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
 * The configuration of an OpenID Connect (OIDC) identity source for handling identity (ID) token claims. Contains the
 * claim that you want to identify as the principal in an authorization request, and the values of the <code>aud</code>
 * claim, or audiences, that you want to accept.
 * </p>
 * <p>
 * This data type is part of a <a
 * href="https://docs.aws.amazon.com/verifiedpermissions/latest/apireference/API_OpenIdConnectTokenSelectionItem.html"
 * >OpenIdConnectTokenSelectionItem</a> structure, which is a parameter of <a
 * href="https://docs.aws.amazon.com/verifiedpermissions/latest/apireference/API_ListIdentitySources.html"
 * >ListIdentitySources</a>.
 * </p>
 * 
 * @see <a
 *      href="http://docs.aws.amazon.com/goto/WebAPI/verifiedpermissions-2021-12-01/OpenIdConnectIdentityTokenConfigurationItem"
 *      target="_top">AWS API Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class OpenIdConnectIdentityTokenConfigurationItem implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * The claim that determines the principal in OIDC access tokens. For example, <code>sub</code>.
     * </p>
     */
    private String principalIdClaim;
    /**
     * <p>
     * The ID token audience, or client ID, claim values that you want to accept in your policy store from an OIDC
     * identity provider. For example, <code>1example23456789, 2example10111213</code>.
     * </p>
     */
    private java.util.List<String> clientIds;

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

    public OpenIdConnectIdentityTokenConfigurationItem withPrincipalIdClaim(String principalIdClaim) {
        setPrincipalIdClaim(principalIdClaim);
        return this;
    }

    /**
     * <p>
     * The ID token audience, or client ID, claim values that you want to accept in your policy store from an OIDC
     * identity provider. For example, <code>1example23456789, 2example10111213</code>.
     * </p>
     * 
     * @return The ID token audience, or client ID, claim values that you want to accept in your policy store from an
     *         OIDC identity provider. For example, <code>1example23456789, 2example10111213</code>.
     */

    public java.util.List<String> getClientIds() {
        return clientIds;
    }

    /**
     * <p>
     * The ID token audience, or client ID, claim values that you want to accept in your policy store from an OIDC
     * identity provider. For example, <code>1example23456789, 2example10111213</code>.
     * </p>
     * 
     * @param clientIds
     *        The ID token audience, or client ID, claim values that you want to accept in your policy store from an
     *        OIDC identity provider. For example, <code>1example23456789, 2example10111213</code>.
     */

    public void setClientIds(java.util.Collection<String> clientIds) {
        if (clientIds == null) {
            this.clientIds = null;
            return;
        }

        this.clientIds = new java.util.ArrayList<String>(clientIds);
    }

    /**
     * <p>
     * The ID token audience, or client ID, claim values that you want to accept in your policy store from an OIDC
     * identity provider. For example, <code>1example23456789, 2example10111213</code>.
     * </p>
     * <p>
     * <b>NOTE:</b> This method appends the values to the existing list (if any). Use
     * {@link #setClientIds(java.util.Collection)} or {@link #withClientIds(java.util.Collection)} if you want to
     * override the existing values.
     * </p>
     * 
     * @param clientIds
     *        The ID token audience, or client ID, claim values that you want to accept in your policy store from an
     *        OIDC identity provider. For example, <code>1example23456789, 2example10111213</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public OpenIdConnectIdentityTokenConfigurationItem withClientIds(String... clientIds) {
        if (this.clientIds == null) {
            setClientIds(new java.util.ArrayList<String>(clientIds.length));
        }
        for (String ele : clientIds) {
            this.clientIds.add(ele);
        }
        return this;
    }

    /**
     * <p>
     * The ID token audience, or client ID, claim values that you want to accept in your policy store from an OIDC
     * identity provider. For example, <code>1example23456789, 2example10111213</code>.
     * </p>
     * 
     * @param clientIds
     *        The ID token audience, or client ID, claim values that you want to accept in your policy store from an
     *        OIDC identity provider. For example, <code>1example23456789, 2example10111213</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public OpenIdConnectIdentityTokenConfigurationItem withClientIds(java.util.Collection<String> clientIds) {
        setClientIds(clientIds);
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
        if (getClientIds() != null)
            sb.append("ClientIds: ").append("***Sensitive Data Redacted***");
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof OpenIdConnectIdentityTokenConfigurationItem == false)
            return false;
        OpenIdConnectIdentityTokenConfigurationItem other = (OpenIdConnectIdentityTokenConfigurationItem) obj;
        if (other.getPrincipalIdClaim() == null ^ this.getPrincipalIdClaim() == null)
            return false;
        if (other.getPrincipalIdClaim() != null && other.getPrincipalIdClaim().equals(this.getPrincipalIdClaim()) == false)
            return false;
        if (other.getClientIds() == null ^ this.getClientIds() == null)
            return false;
        if (other.getClientIds() != null && other.getClientIds().equals(this.getClientIds()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getPrincipalIdClaim() == null) ? 0 : getPrincipalIdClaim().hashCode());
        hashCode = prime * hashCode + ((getClientIds() == null) ? 0 : getClientIds().hashCode());
        return hashCode;
    }

    @Override
    public OpenIdConnectIdentityTokenConfigurationItem clone() {
        try {
            return (OpenIdConnectIdentityTokenConfigurationItem) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.verifiedpermissions.model.transform.OpenIdConnectIdentityTokenConfigurationItemMarshaller.getInstance().marshall(this,
                protocolMarshaller);
    }
}
