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
 * Additional tax information associated with your TRN in Malaysia.
 * </p>
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/taxsettings-2018-05-10/MalaysiaAdditionalInfo" target="_top">AWS
 *      API Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class MalaysiaAdditionalInfo implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * List of service tax codes for your TRN in Malaysia.
     * </p>
     */
    private java.util.List<String> serviceTaxCodes;

    /**
     * <p>
     * List of service tax codes for your TRN in Malaysia.
     * </p>
     * 
     * @return List of service tax codes for your TRN in Malaysia.
     * @see MalaysiaServiceTaxCode
     */

    public java.util.List<String> getServiceTaxCodes() {
        return serviceTaxCodes;
    }

    /**
     * <p>
     * List of service tax codes for your TRN in Malaysia.
     * </p>
     * 
     * @param serviceTaxCodes
     *        List of service tax codes for your TRN in Malaysia.
     * @see MalaysiaServiceTaxCode
     */

    public void setServiceTaxCodes(java.util.Collection<String> serviceTaxCodes) {
        if (serviceTaxCodes == null) {
            this.serviceTaxCodes = null;
            return;
        }

        this.serviceTaxCodes = new java.util.ArrayList<String>(serviceTaxCodes);
    }

    /**
     * <p>
     * List of service tax codes for your TRN in Malaysia.
     * </p>
     * <p>
     * <b>NOTE:</b> This method appends the values to the existing list (if any). Use
     * {@link #setServiceTaxCodes(java.util.Collection)} or {@link #withServiceTaxCodes(java.util.Collection)} if you
     * want to override the existing values.
     * </p>
     * 
     * @param serviceTaxCodes
     *        List of service tax codes for your TRN in Malaysia.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see MalaysiaServiceTaxCode
     */

    public MalaysiaAdditionalInfo withServiceTaxCodes(String... serviceTaxCodes) {
        if (this.serviceTaxCodes == null) {
            setServiceTaxCodes(new java.util.ArrayList<String>(serviceTaxCodes.length));
        }
        for (String ele : serviceTaxCodes) {
            this.serviceTaxCodes.add(ele);
        }
        return this;
    }

    /**
     * <p>
     * List of service tax codes for your TRN in Malaysia.
     * </p>
     * 
     * @param serviceTaxCodes
     *        List of service tax codes for your TRN in Malaysia.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see MalaysiaServiceTaxCode
     */

    public MalaysiaAdditionalInfo withServiceTaxCodes(java.util.Collection<String> serviceTaxCodes) {
        setServiceTaxCodes(serviceTaxCodes);
        return this;
    }

    /**
     * <p>
     * List of service tax codes for your TRN in Malaysia.
     * </p>
     * 
     * @param serviceTaxCodes
     *        List of service tax codes for your TRN in Malaysia.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see MalaysiaServiceTaxCode
     */

    public MalaysiaAdditionalInfo withServiceTaxCodes(MalaysiaServiceTaxCode... serviceTaxCodes) {
        java.util.ArrayList<String> serviceTaxCodesCopy = new java.util.ArrayList<String>(serviceTaxCodes.length);
        for (MalaysiaServiceTaxCode value : serviceTaxCodes) {
            serviceTaxCodesCopy.add(value.toString());
        }
        if (getServiceTaxCodes() == null) {
            setServiceTaxCodes(serviceTaxCodesCopy);
        } else {
            getServiceTaxCodes().addAll(serviceTaxCodesCopy);
        }
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
        if (getServiceTaxCodes() != null)
            sb.append("ServiceTaxCodes: ").append(getServiceTaxCodes());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof MalaysiaAdditionalInfo == false)
            return false;
        MalaysiaAdditionalInfo other = (MalaysiaAdditionalInfo) obj;
        if (other.getServiceTaxCodes() == null ^ this.getServiceTaxCodes() == null)
            return false;
        if (other.getServiceTaxCodes() != null && other.getServiceTaxCodes().equals(this.getServiceTaxCodes()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getServiceTaxCodes() == null) ? 0 : getServiceTaxCodes().hashCode());
        return hashCode;
    }

    @Override
    public MalaysiaAdditionalInfo clone() {
        try {
            return (MalaysiaAdditionalInfo) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.taxsettings.model.transform.MalaysiaAdditionalInfoMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
