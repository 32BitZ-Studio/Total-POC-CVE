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
 * The jurisdiction details of the TRN information of the customers. This doesn't contain full legal address, and
 * contains only country code and state/region/province.
 * </p>
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/taxsettings-2018-05-10/Jurisdiction" target="_top">AWS API
 *      Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class Jurisdiction implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * The country code of the jurisdiction.
     * </p>
     */
    private String countryCode;
    /**
     * <p>
     * The state, region, or province associated with the country of the jurisdiction, if applicable.
     * </p>
     */
    private String stateOrRegion;

    /**
     * <p>
     * The country code of the jurisdiction.
     * </p>
     * 
     * @param countryCode
     *        The country code of the jurisdiction.
     */

    public void setCountryCode(String countryCode) {
        this.countryCode = countryCode;
    }

    /**
     * <p>
     * The country code of the jurisdiction.
     * </p>
     * 
     * @return The country code of the jurisdiction.
     */

    public String getCountryCode() {
        return this.countryCode;
    }

    /**
     * <p>
     * The country code of the jurisdiction.
     * </p>
     * 
     * @param countryCode
     *        The country code of the jurisdiction.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public Jurisdiction withCountryCode(String countryCode) {
        setCountryCode(countryCode);
        return this;
    }

    /**
     * <p>
     * The state, region, or province associated with the country of the jurisdiction, if applicable.
     * </p>
     * 
     * @param stateOrRegion
     *        The state, region, or province associated with the country of the jurisdiction, if applicable.
     */

    public void setStateOrRegion(String stateOrRegion) {
        this.stateOrRegion = stateOrRegion;
    }

    /**
     * <p>
     * The state, region, or province associated with the country of the jurisdiction, if applicable.
     * </p>
     * 
     * @return The state, region, or province associated with the country of the jurisdiction, if applicable.
     */

    public String getStateOrRegion() {
        return this.stateOrRegion;
    }

    /**
     * <p>
     * The state, region, or province associated with the country of the jurisdiction, if applicable.
     * </p>
     * 
     * @param stateOrRegion
     *        The state, region, or province associated with the country of the jurisdiction, if applicable.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public Jurisdiction withStateOrRegion(String stateOrRegion) {
        setStateOrRegion(stateOrRegion);
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
        if (getCountryCode() != null)
            sb.append("CountryCode: ").append(getCountryCode()).append(",");
        if (getStateOrRegion() != null)
            sb.append("StateOrRegion: ").append(getStateOrRegion());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof Jurisdiction == false)
            return false;
        Jurisdiction other = (Jurisdiction) obj;
        if (other.getCountryCode() == null ^ this.getCountryCode() == null)
            return false;
        if (other.getCountryCode() != null && other.getCountryCode().equals(this.getCountryCode()) == false)
            return false;
        if (other.getStateOrRegion() == null ^ this.getStateOrRegion() == null)
            return false;
        if (other.getStateOrRegion() != null && other.getStateOrRegion().equals(this.getStateOrRegion()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getCountryCode() == null) ? 0 : getCountryCode().hashCode());
        hashCode = prime * hashCode + ((getStateOrRegion() == null) ? 0 : getStateOrRegion().hashCode());
        return hashCode;
    }

    @Override
    public Jurisdiction clone() {
        try {
            return (Jurisdiction) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.taxsettings.model.transform.JurisdictionMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
