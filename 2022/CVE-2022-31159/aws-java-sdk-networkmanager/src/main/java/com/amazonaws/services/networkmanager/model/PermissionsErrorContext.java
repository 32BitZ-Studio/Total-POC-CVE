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
package com.amazonaws.services.networkmanager.model;

import java.io.Serializable;
import javax.annotation.Generated;
import com.amazonaws.protocol.StructuredPojo;
import com.amazonaws.protocol.ProtocolMarshaller;

/**
 * <p>
 * Describes additional information about missing permissions.
 * </p>
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/networkmanager-2019-07-05/PermissionsErrorContext"
 *      target="_top">AWS API Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class PermissionsErrorContext implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * The missing permissions.
     * </p>
     */
    private String missingPermission;

    /**
     * <p>
     * The missing permissions.
     * </p>
     * 
     * @param missingPermission
     *        The missing permissions.
     */

    public void setMissingPermission(String missingPermission) {
        this.missingPermission = missingPermission;
    }

    /**
     * <p>
     * The missing permissions.
     * </p>
     * 
     * @return The missing permissions.
     */

    public String getMissingPermission() {
        return this.missingPermission;
    }

    /**
     * <p>
     * The missing permissions.
     * </p>
     * 
     * @param missingPermission
     *        The missing permissions.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public PermissionsErrorContext withMissingPermission(String missingPermission) {
        setMissingPermission(missingPermission);
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
        if (getMissingPermission() != null)
            sb.append("MissingPermission: ").append(getMissingPermission());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof PermissionsErrorContext == false)
            return false;
        PermissionsErrorContext other = (PermissionsErrorContext) obj;
        if (other.getMissingPermission() == null ^ this.getMissingPermission() == null)
            return false;
        if (other.getMissingPermission() != null && other.getMissingPermission().equals(this.getMissingPermission()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getMissingPermission() == null) ? 0 : getMissingPermission().hashCode());
        return hashCode;
    }

    @Override
    public PermissionsErrorContext clone() {
        try {
            return (PermissionsErrorContext) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.networkmanager.model.transform.PermissionsErrorContextMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
