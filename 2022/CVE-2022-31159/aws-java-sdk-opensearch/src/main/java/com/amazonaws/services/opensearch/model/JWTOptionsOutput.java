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
 * Describes the JWT options configured for the domain.
 * </p>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class JWTOptionsOutput implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * True if JWT use is enabled.
     * </p>
     */
    private Boolean enabled;
    /**
     * <p>
     * The key used for matching the JWT subject attribute.
     * </p>
     */
    private String subjectKey;
    /**
     * <p>
     * The key used for matching the JWT roles attribute.
     * </p>
     */
    private String rolesKey;
    /**
     * <p>
     * The key used to verify the signature of incoming JWT requests.
     * </p>
     */
    private String publicKey;

    /**
     * <p>
     * True if JWT use is enabled.
     * </p>
     * 
     * @param enabled
     *        True if JWT use is enabled.
     */

    public void setEnabled(Boolean enabled) {
        this.enabled = enabled;
    }

    /**
     * <p>
     * True if JWT use is enabled.
     * </p>
     * 
     * @return True if JWT use is enabled.
     */

    public Boolean getEnabled() {
        return this.enabled;
    }

    /**
     * <p>
     * True if JWT use is enabled.
     * </p>
     * 
     * @param enabled
     *        True if JWT use is enabled.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public JWTOptionsOutput withEnabled(Boolean enabled) {
        setEnabled(enabled);
        return this;
    }

    /**
     * <p>
     * True if JWT use is enabled.
     * </p>
     * 
     * @return True if JWT use is enabled.
     */

    public Boolean isEnabled() {
        return this.enabled;
    }

    /**
     * <p>
     * The key used for matching the JWT subject attribute.
     * </p>
     * 
     * @param subjectKey
     *        The key used for matching the JWT subject attribute.
     */

    public void setSubjectKey(String subjectKey) {
        this.subjectKey = subjectKey;
    }

    /**
     * <p>
     * The key used for matching the JWT subject attribute.
     * </p>
     * 
     * @return The key used for matching the JWT subject attribute.
     */

    public String getSubjectKey() {
        return this.subjectKey;
    }

    /**
     * <p>
     * The key used for matching the JWT subject attribute.
     * </p>
     * 
     * @param subjectKey
     *        The key used for matching the JWT subject attribute.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public JWTOptionsOutput withSubjectKey(String subjectKey) {
        setSubjectKey(subjectKey);
        return this;
    }

    /**
     * <p>
     * The key used for matching the JWT roles attribute.
     * </p>
     * 
     * @param rolesKey
     *        The key used for matching the JWT roles attribute.
     */

    public void setRolesKey(String rolesKey) {
        this.rolesKey = rolesKey;
    }

    /**
     * <p>
     * The key used for matching the JWT roles attribute.
     * </p>
     * 
     * @return The key used for matching the JWT roles attribute.
     */

    public String getRolesKey() {
        return this.rolesKey;
    }

    /**
     * <p>
     * The key used for matching the JWT roles attribute.
     * </p>
     * 
     * @param rolesKey
     *        The key used for matching the JWT roles attribute.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public JWTOptionsOutput withRolesKey(String rolesKey) {
        setRolesKey(rolesKey);
        return this;
    }

    /**
     * <p>
     * The key used to verify the signature of incoming JWT requests.
     * </p>
     * 
     * @param publicKey
     *        The key used to verify the signature of incoming JWT requests.
     */

    public void setPublicKey(String publicKey) {
        this.publicKey = publicKey;
    }

    /**
     * <p>
     * The key used to verify the signature of incoming JWT requests.
     * </p>
     * 
     * @return The key used to verify the signature of incoming JWT requests.
     */

    public String getPublicKey() {
        return this.publicKey;
    }

    /**
     * <p>
     * The key used to verify the signature of incoming JWT requests.
     * </p>
     * 
     * @param publicKey
     *        The key used to verify the signature of incoming JWT requests.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public JWTOptionsOutput withPublicKey(String publicKey) {
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

        if (obj instanceof JWTOptionsOutput == false)
            return false;
        JWTOptionsOutput other = (JWTOptionsOutput) obj;
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
    public JWTOptionsOutput clone() {
        try {
            return (JWTOptionsOutput) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.opensearch.model.transform.JWTOptionsOutputMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
