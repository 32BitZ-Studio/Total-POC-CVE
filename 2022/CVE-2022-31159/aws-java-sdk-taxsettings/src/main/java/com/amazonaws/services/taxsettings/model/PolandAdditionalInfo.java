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
 * Additional tax information associated with your TRN in Poland.
 * </p>
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/taxsettings-2018-05-10/PolandAdditionalInfo" target="_top">AWS
 *      API Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class PolandAdditionalInfo implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * The individual tax registration number (NIP). Individual NIP is valid for other taxes excluding VAT purposes.
     * </p>
     */
    private String individualRegistrationNumber;
    /**
     * <p>
     * True if your business is a member of a VAT group with a NIP active for VAT purposes. Otherwise, this is false.
     * </p>
     */
    private Boolean isGroupVatEnabled;

    /**
     * <p>
     * The individual tax registration number (NIP). Individual NIP is valid for other taxes excluding VAT purposes.
     * </p>
     * 
     * @param individualRegistrationNumber
     *        The individual tax registration number (NIP). Individual NIP is valid for other taxes excluding VAT
     *        purposes.
     */

    public void setIndividualRegistrationNumber(String individualRegistrationNumber) {
        this.individualRegistrationNumber = individualRegistrationNumber;
    }

    /**
     * <p>
     * The individual tax registration number (NIP). Individual NIP is valid for other taxes excluding VAT purposes.
     * </p>
     * 
     * @return The individual tax registration number (NIP). Individual NIP is valid for other taxes excluding VAT
     *         purposes.
     */

    public String getIndividualRegistrationNumber() {
        return this.individualRegistrationNumber;
    }

    /**
     * <p>
     * The individual tax registration number (NIP). Individual NIP is valid for other taxes excluding VAT purposes.
     * </p>
     * 
     * @param individualRegistrationNumber
     *        The individual tax registration number (NIP). Individual NIP is valid for other taxes excluding VAT
     *        purposes.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public PolandAdditionalInfo withIndividualRegistrationNumber(String individualRegistrationNumber) {
        setIndividualRegistrationNumber(individualRegistrationNumber);
        return this;
    }

    /**
     * <p>
     * True if your business is a member of a VAT group with a NIP active for VAT purposes. Otherwise, this is false.
     * </p>
     * 
     * @param isGroupVatEnabled
     *        True if your business is a member of a VAT group with a NIP active for VAT purposes. Otherwise, this is
     *        false.
     */

    public void setIsGroupVatEnabled(Boolean isGroupVatEnabled) {
        this.isGroupVatEnabled = isGroupVatEnabled;
    }

    /**
     * <p>
     * True if your business is a member of a VAT group with a NIP active for VAT purposes. Otherwise, this is false.
     * </p>
     * 
     * @return True if your business is a member of a VAT group with a NIP active for VAT purposes. Otherwise, this is
     *         false.
     */

    public Boolean getIsGroupVatEnabled() {
        return this.isGroupVatEnabled;
    }

    /**
     * <p>
     * True if your business is a member of a VAT group with a NIP active for VAT purposes. Otherwise, this is false.
     * </p>
     * 
     * @param isGroupVatEnabled
     *        True if your business is a member of a VAT group with a NIP active for VAT purposes. Otherwise, this is
     *        false.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public PolandAdditionalInfo withIsGroupVatEnabled(Boolean isGroupVatEnabled) {
        setIsGroupVatEnabled(isGroupVatEnabled);
        return this;
    }

    /**
     * <p>
     * True if your business is a member of a VAT group with a NIP active for VAT purposes. Otherwise, this is false.
     * </p>
     * 
     * @return True if your business is a member of a VAT group with a NIP active for VAT purposes. Otherwise, this is
     *         false.
     */

    public Boolean isGroupVatEnabled() {
        return this.isGroupVatEnabled;
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
        if (getIndividualRegistrationNumber() != null)
            sb.append("IndividualRegistrationNumber: ").append(getIndividualRegistrationNumber()).append(",");
        if (getIsGroupVatEnabled() != null)
            sb.append("IsGroupVatEnabled: ").append(getIsGroupVatEnabled());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof PolandAdditionalInfo == false)
            return false;
        PolandAdditionalInfo other = (PolandAdditionalInfo) obj;
        if (other.getIndividualRegistrationNumber() == null ^ this.getIndividualRegistrationNumber() == null)
            return false;
        if (other.getIndividualRegistrationNumber() != null && other.getIndividualRegistrationNumber().equals(this.getIndividualRegistrationNumber()) == false)
            return false;
        if (other.getIsGroupVatEnabled() == null ^ this.getIsGroupVatEnabled() == null)
            return false;
        if (other.getIsGroupVatEnabled() != null && other.getIsGroupVatEnabled().equals(this.getIsGroupVatEnabled()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getIndividualRegistrationNumber() == null) ? 0 : getIndividualRegistrationNumber().hashCode());
        hashCode = prime * hashCode + ((getIsGroupVatEnabled() == null) ? 0 : getIsGroupVatEnabled().hashCode());
        return hashCode;
    }

    @Override
    public PolandAdditionalInfo clone() {
        try {
            return (PolandAdditionalInfo) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.taxsettings.model.transform.PolandAdditionalInfoMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
