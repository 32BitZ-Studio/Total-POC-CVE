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
 * Additional tax information associated with your TRN in Georgia.
 * </p>
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/taxsettings-2018-05-10/GeorgiaAdditionalInfo" target="_top">AWS
 *      API Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class GeorgiaAdditionalInfo implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * The legal person or physical person assigned to this TRN in Georgia.
     * </p>
     */
    private String personType;

    /**
     * <p>
     * The legal person or physical person assigned to this TRN in Georgia.
     * </p>
     * 
     * @param personType
     *        The legal person or physical person assigned to this TRN in Georgia.
     * @see PersonType
     */

    public void setPersonType(String personType) {
        this.personType = personType;
    }

    /**
     * <p>
     * The legal person or physical person assigned to this TRN in Georgia.
     * </p>
     * 
     * @return The legal person or physical person assigned to this TRN in Georgia.
     * @see PersonType
     */

    public String getPersonType() {
        return this.personType;
    }

    /**
     * <p>
     * The legal person or physical person assigned to this TRN in Georgia.
     * </p>
     * 
     * @param personType
     *        The legal person or physical person assigned to this TRN in Georgia.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see PersonType
     */

    public GeorgiaAdditionalInfo withPersonType(String personType) {
        setPersonType(personType);
        return this;
    }

    /**
     * <p>
     * The legal person or physical person assigned to this TRN in Georgia.
     * </p>
     * 
     * @param personType
     *        The legal person or physical person assigned to this TRN in Georgia.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see PersonType
     */

    public GeorgiaAdditionalInfo withPersonType(PersonType personType) {
        this.personType = personType.toString();
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
        if (getPersonType() != null)
            sb.append("PersonType: ").append(getPersonType());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof GeorgiaAdditionalInfo == false)
            return false;
        GeorgiaAdditionalInfo other = (GeorgiaAdditionalInfo) obj;
        if (other.getPersonType() == null ^ this.getPersonType() == null)
            return false;
        if (other.getPersonType() != null && other.getPersonType().equals(this.getPersonType()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getPersonType() == null) ? 0 : getPersonType().hashCode());
        return hashCode;
    }

    @Override
    public GeorgiaAdditionalInfo clone() {
        try {
            return (GeorgiaAdditionalInfo) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.taxsettings.model.transform.GeorgiaAdditionalInfoMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
