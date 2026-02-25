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
 * The claim in OIDC identity provider tokens that indicates a user's group membership, and the entity type that you
 * want to map it to. For example, this object can map the contents of a <code>groups</code> claim to
 * <code>MyCorp::UserGroup</code>.
 * </p>
 * <p>
 * This data type is part of a <a
 * href="https://docs.aws.amazon.com/verifiedpermissions/latest/apireference/API_OpenIdConnectConfiguration.html"
 * >OpenIdConnectConfiguration</a> structure, which is a parameter of <a
 * href="https://docs.aws.amazon.com/verifiedpermissions/latest/apireference/API_CreateIdentitySource.html"
 * >CreateIdentitySource</a>.
 * </p>
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/verifiedpermissions-2021-12-01/OpenIdConnectGroupConfiguration"
 *      target="_top">AWS API Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class OpenIdConnectGroupConfiguration implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * The token claim that you want Verified Permissions to interpret as group membership. For example,
     * <code>groups</code>.
     * </p>
     */
    private String groupClaim;
    /**
     * <p>
     * The policy store entity type that you want to map your users' group claim to. For example,
     * <code>MyCorp::UserGroup</code>. A group entity type is an entity that can have a user entity type as a member.
     * </p>
     */
    private String groupEntityType;

    /**
     * <p>
     * The token claim that you want Verified Permissions to interpret as group membership. For example,
     * <code>groups</code>.
     * </p>
     * 
     * @param groupClaim
     *        The token claim that you want Verified Permissions to interpret as group membership. For example,
     *        <code>groups</code>.
     */

    public void setGroupClaim(String groupClaim) {
        this.groupClaim = groupClaim;
    }

    /**
     * <p>
     * The token claim that you want Verified Permissions to interpret as group membership. For example,
     * <code>groups</code>.
     * </p>
     * 
     * @return The token claim that you want Verified Permissions to interpret as group membership. For example,
     *         <code>groups</code>.
     */

    public String getGroupClaim() {
        return this.groupClaim;
    }

    /**
     * <p>
     * The token claim that you want Verified Permissions to interpret as group membership. For example,
     * <code>groups</code>.
     * </p>
     * 
     * @param groupClaim
     *        The token claim that you want Verified Permissions to interpret as group membership. For example,
     *        <code>groups</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public OpenIdConnectGroupConfiguration withGroupClaim(String groupClaim) {
        setGroupClaim(groupClaim);
        return this;
    }

    /**
     * <p>
     * The policy store entity type that you want to map your users' group claim to. For example,
     * <code>MyCorp::UserGroup</code>. A group entity type is an entity that can have a user entity type as a member.
     * </p>
     * 
     * @param groupEntityType
     *        The policy store entity type that you want to map your users' group claim to. For example,
     *        <code>MyCorp::UserGroup</code>. A group entity type is an entity that can have a user entity type as a
     *        member.
     */

    public void setGroupEntityType(String groupEntityType) {
        this.groupEntityType = groupEntityType;
    }

    /**
     * <p>
     * The policy store entity type that you want to map your users' group claim to. For example,
     * <code>MyCorp::UserGroup</code>. A group entity type is an entity that can have a user entity type as a member.
     * </p>
     * 
     * @return The policy store entity type that you want to map your users' group claim to. For example,
     *         <code>MyCorp::UserGroup</code>. A group entity type is an entity that can have a user entity type as a
     *         member.
     */

    public String getGroupEntityType() {
        return this.groupEntityType;
    }

    /**
     * <p>
     * The policy store entity type that you want to map your users' group claim to. For example,
     * <code>MyCorp::UserGroup</code>. A group entity type is an entity that can have a user entity type as a member.
     * </p>
     * 
     * @param groupEntityType
     *        The policy store entity type that you want to map your users' group claim to. For example,
     *        <code>MyCorp::UserGroup</code>. A group entity type is an entity that can have a user entity type as a
     *        member.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public OpenIdConnectGroupConfiguration withGroupEntityType(String groupEntityType) {
        setGroupEntityType(groupEntityType);
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
        if (getGroupClaim() != null)
            sb.append("GroupClaim: ").append("***Sensitive Data Redacted***").append(",");
        if (getGroupEntityType() != null)
            sb.append("GroupEntityType: ").append("***Sensitive Data Redacted***");
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof OpenIdConnectGroupConfiguration == false)
            return false;
        OpenIdConnectGroupConfiguration other = (OpenIdConnectGroupConfiguration) obj;
        if (other.getGroupClaim() == null ^ this.getGroupClaim() == null)
            return false;
        if (other.getGroupClaim() != null && other.getGroupClaim().equals(this.getGroupClaim()) == false)
            return false;
        if (other.getGroupEntityType() == null ^ this.getGroupEntityType() == null)
            return false;
        if (other.getGroupEntityType() != null && other.getGroupEntityType().equals(this.getGroupEntityType()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getGroupClaim() == null) ? 0 : getGroupClaim().hashCode());
        hashCode = prime * hashCode + ((getGroupEntityType() == null) ? 0 : getGroupEntityType().hashCode());
        return hashCode;
    }

    @Override
    public OpenIdConnectGroupConfiguration clone() {
        try {
            return (OpenIdConnectGroupConfiguration) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.verifiedpermissions.model.transform.OpenIdConnectGroupConfigurationMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
