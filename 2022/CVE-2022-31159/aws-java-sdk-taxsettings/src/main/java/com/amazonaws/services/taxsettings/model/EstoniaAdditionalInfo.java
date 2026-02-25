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
 * Additional tax information associated with your TRN in Estonia.
 * </p>
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/taxsettings-2018-05-10/EstoniaAdditionalInfo" target="_top">AWS
 *      API Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class EstoniaAdditionalInfo implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * Registry commercial code (RCC) for your TRN in Estonia. This value is an eight-numeric string, such as
     * <code>12345678</code>.
     * </p>
     */
    private String registryCommercialCode;

    /**
     * <p>
     * Registry commercial code (RCC) for your TRN in Estonia. This value is an eight-numeric string, such as
     * <code>12345678</code>.
     * </p>
     * 
     * @param registryCommercialCode
     *        Registry commercial code (RCC) for your TRN in Estonia. This value is an eight-numeric string, such as
     *        <code>12345678</code>.
     */

    public void setRegistryCommercialCode(String registryCommercialCode) {
        this.registryCommercialCode = registryCommercialCode;
    }

    /**
     * <p>
     * Registry commercial code (RCC) for your TRN in Estonia. This value is an eight-numeric string, such as
     * <code>12345678</code>.
     * </p>
     * 
     * @return Registry commercial code (RCC) for your TRN in Estonia. This value is an eight-numeric string, such as
     *         <code>12345678</code>.
     */

    public String getRegistryCommercialCode() {
        return this.registryCommercialCode;
    }

    /**
     * <p>
     * Registry commercial code (RCC) for your TRN in Estonia. This value is an eight-numeric string, such as
     * <code>12345678</code>.
     * </p>
     * 
     * @param registryCommercialCode
     *        Registry commercial code (RCC) for your TRN in Estonia. This value is an eight-numeric string, such as
     *        <code>12345678</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public EstoniaAdditionalInfo withRegistryCommercialCode(String registryCommercialCode) {
        setRegistryCommercialCode(registryCommercialCode);
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
        if (getRegistryCommercialCode() != null)
            sb.append("RegistryCommercialCode: ").append(getRegistryCommercialCode());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof EstoniaAdditionalInfo == false)
            return false;
        EstoniaAdditionalInfo other = (EstoniaAdditionalInfo) obj;
        if (other.getRegistryCommercialCode() == null ^ this.getRegistryCommercialCode() == null)
            return false;
        if (other.getRegistryCommercialCode() != null && other.getRegistryCommercialCode().equals(this.getRegistryCommercialCode()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getRegistryCommercialCode() == null) ? 0 : getRegistryCommercialCode().hashCode());
        return hashCode;
    }

    @Override
    public EstoniaAdditionalInfo clone() {
        try {
            return (EstoniaAdditionalInfo) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.taxsettings.model.transform.EstoniaAdditionalInfoMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
