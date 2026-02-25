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
 * Additional tax information associated with your TRN in Ukraine.
 * </p>
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/taxsettings-2018-05-10/UkraineAdditionalInfo" target="_top">AWS
 *      API Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class UkraineAdditionalInfo implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * The tax registration type.
     * </p>
     */
    private String ukraineTrnType;

    /**
     * <p>
     * The tax registration type.
     * </p>
     * 
     * @param ukraineTrnType
     *        The tax registration type.
     * @see UkraineTrnType
     */

    public void setUkraineTrnType(String ukraineTrnType) {
        this.ukraineTrnType = ukraineTrnType;
    }

    /**
     * <p>
     * The tax registration type.
     * </p>
     * 
     * @return The tax registration type.
     * @see UkraineTrnType
     */

    public String getUkraineTrnType() {
        return this.ukraineTrnType;
    }

    /**
     * <p>
     * The tax registration type.
     * </p>
     * 
     * @param ukraineTrnType
     *        The tax registration type.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see UkraineTrnType
     */

    public UkraineAdditionalInfo withUkraineTrnType(String ukraineTrnType) {
        setUkraineTrnType(ukraineTrnType);
        return this;
    }

    /**
     * <p>
     * The tax registration type.
     * </p>
     * 
     * @param ukraineTrnType
     *        The tax registration type.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see UkraineTrnType
     */

    public UkraineAdditionalInfo withUkraineTrnType(UkraineTrnType ukraineTrnType) {
        this.ukraineTrnType = ukraineTrnType.toString();
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
        if (getUkraineTrnType() != null)
            sb.append("UkraineTrnType: ").append(getUkraineTrnType());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof UkraineAdditionalInfo == false)
            return false;
        UkraineAdditionalInfo other = (UkraineAdditionalInfo) obj;
        if (other.getUkraineTrnType() == null ^ this.getUkraineTrnType() == null)
            return false;
        if (other.getUkraineTrnType() != null && other.getUkraineTrnType().equals(this.getUkraineTrnType()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getUkraineTrnType() == null) ? 0 : getUkraineTrnType().hashCode());
        return hashCode;
    }

    @Override
    public UkraineAdditionalInfo clone() {
        try {
            return (UkraineAdditionalInfo) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.taxsettings.model.transform.UkraineAdditionalInfoMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
