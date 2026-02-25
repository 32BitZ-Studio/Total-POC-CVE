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
 * Contains configuration details of an OpenID Connect (OIDC) identity provider, or identity source, that Verified
 * Permissions can use to generate entities from authenticated identities. It specifies the issuer URL, token type that
 * you want to use, and policy store entity details.
 * </p>
 * <p>
 * This data type is part of a <a
 * href="https://docs.aws.amazon.com/verifiedpermissions/latest/apireference/API_UpdateConfiguration.html"
 * >UpdateConfiguration</a> structure, which is a parameter to <a
 * href="https://docs.aws.amazon.com/verifiedpermissions/latest/apireference/API_UpdateIdentitySource.html"
 * >UpdateIdentitySource</a>.
 * </p>
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/verifiedpermissions-2021-12-01/UpdateOpenIdConnectConfiguration"
 *      target="_top">AWS API Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class UpdateOpenIdConnectConfiguration implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * The issuer URL of an OIDC identity provider. This URL must have an OIDC discovery endpoint at the path
     * <code>.well-known/openid-configuration</code>.
     * </p>
     */
    private String issuer;
    /**
     * <p>
     * A descriptive string that you want to prefix to user entities from your OIDC identity provider. For example, if
     * you set an <code>entityIdPrefix</code> of <code>MyOIDCProvider</code>, you can reference principals in your
     * policies in the format <code>MyCorp::User::MyOIDCProvider|Carlos</code>.
     * </p>
     */
    private String entityIdPrefix;
    /**
     * <p>
     * The claim in OIDC identity provider tokens that indicates a user's group membership, and the entity type that you
     * want to map it to. For example, this object can map the contents of a <code>groups</code> claim to
     * <code>MyCorp::UserGroup</code>.
     * </p>
     */
    private UpdateOpenIdConnectGroupConfiguration groupConfiguration;
    /**
     * <p>
     * The token type that you want to process from your OIDC identity provider. Your policy store can process either
     * identity (ID) or access tokens from a given OIDC identity source.
     * </p>
     */
    private UpdateOpenIdConnectTokenSelection tokenSelection;

    /**
     * <p>
     * The issuer URL of an OIDC identity provider. This URL must have an OIDC discovery endpoint at the path
     * <code>.well-known/openid-configuration</code>.
     * </p>
     * 
     * @param issuer
     *        The issuer URL of an OIDC identity provider. This URL must have an OIDC discovery endpoint at the path
     *        <code>.well-known/openid-configuration</code>.
     */

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    /**
     * <p>
     * The issuer URL of an OIDC identity provider. This URL must have an OIDC discovery endpoint at the path
     * <code>.well-known/openid-configuration</code>.
     * </p>
     * 
     * @return The issuer URL of an OIDC identity provider. This URL must have an OIDC discovery endpoint at the path
     *         <code>.well-known/openid-configuration</code>.
     */

    public String getIssuer() {
        return this.issuer;
    }

    /**
     * <p>
     * The issuer URL of an OIDC identity provider. This URL must have an OIDC discovery endpoint at the path
     * <code>.well-known/openid-configuration</code>.
     * </p>
     * 
     * @param issuer
     *        The issuer URL of an OIDC identity provider. This URL must have an OIDC discovery endpoint at the path
     *        <code>.well-known/openid-configuration</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public UpdateOpenIdConnectConfiguration withIssuer(String issuer) {
        setIssuer(issuer);
        return this;
    }

    /**
     * <p>
     * A descriptive string that you want to prefix to user entities from your OIDC identity provider. For example, if
     * you set an <code>entityIdPrefix</code> of <code>MyOIDCProvider</code>, you can reference principals in your
     * policies in the format <code>MyCorp::User::MyOIDCProvider|Carlos</code>.
     * </p>
     * 
     * @param entityIdPrefix
     *        A descriptive string that you want to prefix to user entities from your OIDC identity provider. For
     *        example, if you set an <code>entityIdPrefix</code> of <code>MyOIDCProvider</code>, you can reference
     *        principals in your policies in the format <code>MyCorp::User::MyOIDCProvider|Carlos</code>.
     */

    public void setEntityIdPrefix(String entityIdPrefix) {
        this.entityIdPrefix = entityIdPrefix;
    }

    /**
     * <p>
     * A descriptive string that you want to prefix to user entities from your OIDC identity provider. For example, if
     * you set an <code>entityIdPrefix</code> of <code>MyOIDCProvider</code>, you can reference principals in your
     * policies in the format <code>MyCorp::User::MyOIDCProvider|Carlos</code>.
     * </p>
     * 
     * @return A descriptive string that you want to prefix to user entities from your OIDC identity provider. For
     *         example, if you set an <code>entityIdPrefix</code> of <code>MyOIDCProvider</code>, you can reference
     *         principals in your policies in the format <code>MyCorp::User::MyOIDCProvider|Carlos</code>.
     */

    public String getEntityIdPrefix() {
        return this.entityIdPrefix;
    }

    /**
     * <p>
     * A descriptive string that you want to prefix to user entities from your OIDC identity provider. For example, if
     * you set an <code>entityIdPrefix</code> of <code>MyOIDCProvider</code>, you can reference principals in your
     * policies in the format <code>MyCorp::User::MyOIDCProvider|Carlos</code>.
     * </p>
     * 
     * @param entityIdPrefix
     *        A descriptive string that you want to prefix to user entities from your OIDC identity provider. For
     *        example, if you set an <code>entityIdPrefix</code> of <code>MyOIDCProvider</code>, you can reference
     *        principals in your policies in the format <code>MyCorp::User::MyOIDCProvider|Carlos</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public UpdateOpenIdConnectConfiguration withEntityIdPrefix(String entityIdPrefix) {
        setEntityIdPrefix(entityIdPrefix);
        return this;
    }

    /**
     * <p>
     * The claim in OIDC identity provider tokens that indicates a user's group membership, and the entity type that you
     * want to map it to. For example, this object can map the contents of a <code>groups</code> claim to
     * <code>MyCorp::UserGroup</code>.
     * </p>
     * 
     * @param groupConfiguration
     *        The claim in OIDC identity provider tokens that indicates a user's group membership, and the entity type
     *        that you want to map it to. For example, this object can map the contents of a <code>groups</code> claim
     *        to <code>MyCorp::UserGroup</code>.
     */

    public void setGroupConfiguration(UpdateOpenIdConnectGroupConfiguration groupConfiguration) {
        this.groupConfiguration = groupConfiguration;
    }

    /**
     * <p>
     * The claim in OIDC identity provider tokens that indicates a user's group membership, and the entity type that you
     * want to map it to. For example, this object can map the contents of a <code>groups</code> claim to
     * <code>MyCorp::UserGroup</code>.
     * </p>
     * 
     * @return The claim in OIDC identity provider tokens that indicates a user's group membership, and the entity type
     *         that you want to map it to. For example, this object can map the contents of a <code>groups</code> claim
     *         to <code>MyCorp::UserGroup</code>.
     */

    public UpdateOpenIdConnectGroupConfiguration getGroupConfiguration() {
        return this.groupConfiguration;
    }

    /**
     * <p>
     * The claim in OIDC identity provider tokens that indicates a user's group membership, and the entity type that you
     * want to map it to. For example, this object can map the contents of a <code>groups</code> claim to
     * <code>MyCorp::UserGroup</code>.
     * </p>
     * 
     * @param groupConfiguration
     *        The claim in OIDC identity provider tokens that indicates a user's group membership, and the entity type
     *        that you want to map it to. For example, this object can map the contents of a <code>groups</code> claim
     *        to <code>MyCorp::UserGroup</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public UpdateOpenIdConnectConfiguration withGroupConfiguration(UpdateOpenIdConnectGroupConfiguration groupConfiguration) {
        setGroupConfiguration(groupConfiguration);
        return this;
    }

    /**
     * <p>
     * The token type that you want to process from your OIDC identity provider. Your policy store can process either
     * identity (ID) or access tokens from a given OIDC identity source.
     * </p>
     * 
     * @param tokenSelection
     *        The token type that you want to process from your OIDC identity provider. Your policy store can process
     *        either identity (ID) or access tokens from a given OIDC identity source.
     */

    public void setTokenSelection(UpdateOpenIdConnectTokenSelection tokenSelection) {
        this.tokenSelection = tokenSelection;
    }

    /**
     * <p>
     * The token type that you want to process from your OIDC identity provider. Your policy store can process either
     * identity (ID) or access tokens from a given OIDC identity source.
     * </p>
     * 
     * @return The token type that you want to process from your OIDC identity provider. Your policy store can process
     *         either identity (ID) or access tokens from a given OIDC identity source.
     */

    public UpdateOpenIdConnectTokenSelection getTokenSelection() {
        return this.tokenSelection;
    }

    /**
     * <p>
     * The token type that you want to process from your OIDC identity provider. Your policy store can process either
     * identity (ID) or access tokens from a given OIDC identity source.
     * </p>
     * 
     * @param tokenSelection
     *        The token type that you want to process from your OIDC identity provider. Your policy store can process
     *        either identity (ID) or access tokens from a given OIDC identity source.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public UpdateOpenIdConnectConfiguration withTokenSelection(UpdateOpenIdConnectTokenSelection tokenSelection) {
        setTokenSelection(tokenSelection);
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
        if (getEntityIdPrefix() != null)
            sb.append("EntityIdPrefix: ").append("***Sensitive Data Redacted***").append(",");
        if (getGroupConfiguration() != null)
            sb.append("GroupConfiguration: ").append(getGroupConfiguration()).append(",");
        if (getTokenSelection() != null)
            sb.append("TokenSelection: ").append(getTokenSelection());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof UpdateOpenIdConnectConfiguration == false)
            return false;
        UpdateOpenIdConnectConfiguration other = (UpdateOpenIdConnectConfiguration) obj;
        if (other.getIssuer() == null ^ this.getIssuer() == null)
            return false;
        if (other.getIssuer() != null && other.getIssuer().equals(this.getIssuer()) == false)
            return false;
        if (other.getEntityIdPrefix() == null ^ this.getEntityIdPrefix() == null)
            return false;
        if (other.getEntityIdPrefix() != null && other.getEntityIdPrefix().equals(this.getEntityIdPrefix()) == false)
            return false;
        if (other.getGroupConfiguration() == null ^ this.getGroupConfiguration() == null)
            return false;
        if (other.getGroupConfiguration() != null && other.getGroupConfiguration().equals(this.getGroupConfiguration()) == false)
            return false;
        if (other.getTokenSelection() == null ^ this.getTokenSelection() == null)
            return false;
        if (other.getTokenSelection() != null && other.getTokenSelection().equals(this.getTokenSelection()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getIssuer() == null) ? 0 : getIssuer().hashCode());
        hashCode = prime * hashCode + ((getEntityIdPrefix() == null) ? 0 : getEntityIdPrefix().hashCode());
        hashCode = prime * hashCode + ((getGroupConfiguration() == null) ? 0 : getGroupConfiguration().hashCode());
        hashCode = prime * hashCode + ((getTokenSelection() == null) ? 0 : getTokenSelection().hashCode());
        return hashCode;
    }

    @Override
    public UpdateOpenIdConnectConfiguration clone() {
        try {
            return (UpdateOpenIdConnectConfiguration) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.verifiedpermissions.model.transform.UpdateOpenIdConnectConfigurationMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
