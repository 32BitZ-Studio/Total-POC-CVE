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
 * Additional tax information associated with your TRN in Spain.
 * </p>
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/taxsettings-2018-05-10/SpainAdditionalInfo" target="_top">AWS
 *      API Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class SpainAdditionalInfo implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * The registration type in Spain.
     * </p>
     */
    private String registrationType;

    /**
     * <p>
     * The registration type in Spain.
     * </p>
     * 
     * @param registrationType
     *        The registration type in Spain.
     * @see RegistrationType
     */

    public void setRegistrationType(String registrationType) {
        this.registrationType = registrationType;
    }

    /**
     * <p>
     * The registration type in Spain.
     * </p>
     * 
     * @return The registration type in Spain.
     * @see RegistrationType
     */

    public String getRegistrationType() {
        return this.registrationType;
    }

    /**
     * <p>
     * The registration type in Spain.
     * </p>
     * 
     * @param registrationType
     *        The registration type in Spain.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see RegistrationType
     */

    public SpainAdditionalInfo withRegistrationType(String registrationType) {
        setRegistrationType(registrationType);
        return this;
    }

    /**
     * <p>
     * The registration type in Spain.
     * </p>
     * 
     * @param registrationType
     *        The registration type in Spain.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see RegistrationType
     */

    public SpainAdditionalInfo withRegistrationType(RegistrationType registrationType) {
        this.registrationType = registrationType.toString();
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
        if (getRegistrationType() != null)
            sb.append("RegistrationType: ").append(getRegistrationType());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof SpainAdditionalInfo == false)
            return false;
        SpainAdditionalInfo other = (SpainAdditionalInfo) obj;
        if (other.getRegistrationType() == null ^ this.getRegistrationType() == null)
            return false;
        if (other.getRegistrationType() != null && other.getRegistrationType().equals(this.getRegistrationType()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getRegistrationType() == null) ? 0 : getRegistrationType().hashCode());
        return hashCode;
    }

    @Override
    public SpainAdditionalInfo clone() {
        try {
            return (SpainAdditionalInfo) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.taxsettings.model.transform.SpainAdditionalInfoMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
