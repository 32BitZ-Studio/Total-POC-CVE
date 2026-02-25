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
package com.amazonaws.services.opensearch.model;

import java.io.Serializable;
import javax.annotation.Generated;
import com.amazonaws.protocol.StructuredPojo;
import com.amazonaws.protocol.ProtocolMarshaller;

/**
 * <p>
 * The JWT authentication and authorization configuration for an Amazon OpenSearch Service domain.
 * </p>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class JWTOptionsInput implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * True to enable JWT authentication and authorization for a domain.
     * </p>
     */
    private Boolean enabled;
    /**
     * <p>
     * Element of the JWT assertion to use for the user name.
     * </p>
     */
    private String subjectKey;
    /**
     * <p>
     * Element of the JWT assertion to use for roles.
     * </p>
     */
    private String rolesKey;
    /**
     * <p>
     * Element of the JWT assertion used by the cluster to verify JWT signatures.
     * </p>
     */
    private String publicKey;

    /**
     * <p>
     * True to enable JWT authentication and authorization for a domain.
     * </p>
     * 
     * @param enabled
     *        True to enable JWT authentication and authorization for a domain.
     */

    public void setEnabled(Boolean enabled) {
        this.enabled = enabled;
    }

    /**
     * <p>
     * True to enable JWT authentication and authorization for a domain.
     * </p>
     * 
     * @return True to enable JWT authentication and authorization for a domain.
     */

    public Boolean getEnabled() {
        return this.enabled;
    }

    /**
     * <p>
     * True to enable JWT authentication and authorization for a domain.
     * </p>
     * 
     * @param enabled
     *        True to enable JWT authentication and authorization for a domain.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public JWTOptionsInput withEnabled(Boolean enabled) {
        setEnabled(enabled);
        return this;
    }

    /**
     * <p>
     * True to enable JWT authentication and authorization for a domain.
     * </p>
     * 
     * @return True to enable JWT authentication and authorization for a domain.
     */

    public Boolean isEnabled() {
        return this.enabled;
    }

    /**
     * <p>
     * Element of the JWT assertion to use for the user name.
     * </p>
     * 
     * @param subjectKey
     *        Element of the JWT assertion to use for the user name.
     */

    public void setSubjectKey(String subjectKey) {
        this.subjectKey = subjectKey;
    }

    /**
     * <p>
     * Element of the JWT assertion to use for the user name.
     * </p>
     * 
     * @return Element of the JWT assertion to use for the user name.
     */

    public String getSubjectKey() {
        return this.subjectKey;
    }

    /**
     * <p>
     * Element of the JWT assertion to use for the user name.
     * </p>
     * 
     * @param subjectKey
     *        Element of the JWT assertion to use for the user name.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public JWTOptionsInput withSubjectKey(String subjectKey) {
        setSubjectKey(subjectKey);
        return this;
    }

    /**
     * <p>
     * Element of the JWT assertion to use for roles.
     * </p>
     * 
     * @param rolesKey
     *        Element of the JWT assertion to use for roles.
     */

    public void setRolesKey(String rolesKey) {
        this.rolesKey = rolesKey;
    }

    /**
     * <p>
     * Element of the JWT assertion to use for roles.
     * </p>
     * 
     * @return Element of the JWT assertion to use for roles.
     */

    public String getRolesKey() {
        return this.rolesKey;
    }

    /**
     * <p>
     * Element of the JWT assertion to use for roles.
     * </p>
     * 
     * @param rolesKey
     *        Element of the JWT assertion to use for roles.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public JWTOptionsInput withRolesKey(String rolesKey) {
        setRolesKey(rolesKey);
        return this;
    }

    /**
     * <p>
     * Element of the JWT assertion used by the cluster to verify JWT signatures.
     * </p>
     * 
     * @param publicKey
     *        Element of the JWT assertion used by the cluster to verify JWT signatures.
     */

    public void setPublicKey(String publicKey) {
        this.publicKey = publicKey;
    }

    /**
     * <p>
     * Element of the JWT assertion used by the cluster to verify JWT signatures.
     * </p>
     * 
     * @return Element of the JWT assertion used by the cluster to verify JWT signatures.
     */

    public String getPublicKey() {
        return this.publicKey;
    }

    /**
     * <p>
     * Element of the JWT assertion used by the cluster to verify JWT signatures.
     * </p>
     * 
     * @param publicKey
     *        Element of the JWT assertion used by the cluster to verify JWT signatures.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public JWTOptionsInput withPublicKey(String publicKey) {
        setPublicKey(publicKey);
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
        if (getEnabled() != null)
            sb.append("Enabled: ").append(getEnabled()).append(",");
        if (getSubjectKey() != null)
            sb.append("SubjectKey: ").append(getSubjectKey()).append(",");
        if (getRolesKey() != null)
            sb.append("RolesKey: ").append(getRolesKey()).append(",");
        if (getPublicKey() != null)
            sb.append("PublicKey: ").append(getPublicKey());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof JWTOptionsInput == false)
            return false;
        JWTOptionsInput other = (JWTOptionsInput) obj;
        if (other.getEnabled() == null ^ this.getEnabled() == null)
            return false;
        if (other.getEnabled() != null && other.getEnabled().equals(this.getEnabled()) == false)
            return false;
        if (other.getSubjectKey() == null ^ this.getSubjectKey() == null)
            return false;
        if (other.getSubjectKey() != null && other.getSubjectKey().equals(this.getSubjectKey()) == false)
            return false;
        if (other.getRolesKey() == null ^ this.getRolesKey() == null)
            return false;
        if (other.getRolesKey() != null && other.getRolesKey().equals(this.getRolesKey()) == false)
            return false;
        if (other.getPublicKey() == null ^ this.getPublicKey() == null)
            return false;
        if (other.getPublicKey() != null && other.getPublicKey().equals(this.getPublicKey()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getEnabled() == null) ? 0 : getEnabled().hashCode());
        hashCode = prime * hashCode + ((getSubjectKey() == null) ? 0 : getSubjectKey().hashCode());
        hashCode = prime * hashCode + ((getRolesKey() == null) ? 0 : getRolesKey().hashCode());
        hashCode = prime * hashCode + ((getPublicKey() == null) ? 0 : getPublicKey().hashCode());
        return hashCode;
    }

    @Override
    public JWTOptionsInput clone() {
        try {
            return (JWTOptionsInput) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.opensearch.model.transform.JWTOptionsInputMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
