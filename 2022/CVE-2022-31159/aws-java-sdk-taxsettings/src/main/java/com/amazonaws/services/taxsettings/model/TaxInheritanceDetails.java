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
 * Tax inheritance information associated with the account.
 * </p>
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/taxsettings-2018-05-10/TaxInheritanceDetails" target="_top">AWS
 *      API Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class TaxInheritanceDetails implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * Tax inheritance reason information associated with the account.
     * </p>
     */
    private String inheritanceObtainedReason;
    /**
     * <p>
     * Tax inheritance parent account information associated with the account.
     * </p>
     */
    private String parentEntityId;

    /**
     * <p>
     * Tax inheritance reason information associated with the account.
     * </p>
     * 
     * @param inheritanceObtainedReason
     *        Tax inheritance reason information associated with the account.
     */

    public void setInheritanceObtainedReason(String inheritanceObtainedReason) {
        this.inheritanceObtainedReason = inheritanceObtainedReason;
    }

    /**
     * <p>
     * Tax inheritance reason information associated with the account.
     * </p>
     * 
     * @return Tax inheritance reason information associated with the account.
     */

    public String getInheritanceObtainedReason() {
        return this.inheritanceObtainedReason;
    }

    /**
     * <p>
     * Tax inheritance reason information associated with the account.
     * </p>
     * 
     * @param inheritanceObtainedReason
     *        Tax inheritance reason information associated with the account.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public TaxInheritanceDetails withInheritanceObtainedReason(String inheritanceObtainedReason) {
        setInheritanceObtainedReason(inheritanceObtainedReason);
        return this;
    }

    /**
     * <p>
     * Tax inheritance parent account information associated with the account.
     * </p>
     * 
     * @param parentEntityId
     *        Tax inheritance parent account information associated with the account.
     */

    public void setParentEntityId(String parentEntityId) {
        this.parentEntityId = parentEntityId;
    }

    /**
     * <p>
     * Tax inheritance parent account information associated with the account.
     * </p>
     * 
     * @return Tax inheritance parent account information associated with the account.
     */

    public String getParentEntityId() {
        return this.parentEntityId;
    }

    /**
     * <p>
     * Tax inheritance parent account information associated with the account.
     * </p>
     * 
     * @param parentEntityId
     *        Tax inheritance parent account information associated with the account.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public TaxInheritanceDetails withParentEntityId(String parentEntityId) {
        setParentEntityId(parentEntityId);
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
        if (getInheritanceObtainedReason() != null)
            sb.append("InheritanceObtainedReason: ").append(getInheritanceObtainedReason()).append(",");
        if (getParentEntityId() != null)
            sb.append("ParentEntityId: ").append(getParentEntityId());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof TaxInheritanceDetails == false)
            return false;
        TaxInheritanceDetails other = (TaxInheritanceDetails) obj;
        if (other.getInheritanceObtainedReason() == null ^ this.getInheritanceObtainedReason() == null)
            return false;
        if (other.getInheritanceObtainedReason() != null && other.getInheritanceObtainedReason().equals(this.getInheritanceObtainedReason()) == false)
            return false;
        if (other.getParentEntityId() == null ^ this.getParentEntityId() == null)
            return false;
        if (other.getParentEntityId() != null && other.getParentEntityId().equals(this.getParentEntityId()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getInheritanceObtainedReason() == null) ? 0 : getInheritanceObtainedReason().hashCode());
        hashCode = prime * hashCode + ((getParentEntityId() == null) ? 0 : getParentEntityId().hashCode());
        return hashCode;
    }

    @Override
    public TaxInheritanceDetails clone() {
        try {
            return (TaxInheritanceDetails) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.taxsettings.model.transform.TaxInheritanceDetailsMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
