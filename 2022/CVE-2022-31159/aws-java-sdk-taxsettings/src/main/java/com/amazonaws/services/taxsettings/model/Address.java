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
 * The details of the address associated with the TRN information.
 * </p>
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/taxsettings-2018-05-10/Address" target="_top">AWS API
 *      Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class Address implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * The first line of the address.
     * </p>
     */
    private String addressLine1;
    /**
     * <p>
     * The second line of the address, if applicable.
     * </p>
     */
    private String addressLine2;
    /**
     * <p>
     * The third line of the address, if applicable. Currently, the Tax Settings API accepts the
     * <code>addressLine3</code> parameter only for Saudi Arabia. When you specify a TRN in Saudi Arabia, you must enter
     * the <code>addressLine3</code> and specify the building number for the address. For example, you might enter
     * <code>1234</code>.
     * </p>
     */
    private String addressLine3;
    /**
     * <p>
     * The city that the address is in.
     * </p>
     */
    private String city;
    /**
     * <p>
     * The country code for the country that the address is in.
     * </p>
     */
    private String countryCode;
    /**
     * <p>
     * The district or county the address is located.
     * </p>
     * <note>
     * <p>
     * For addresses in Brazil, this parameter uses the name of the neighborhood. When you set a TRN in Brazil, use
     * <code>districtOrCounty</code> for the neighborhood name.
     * </p>
     * </note>
     */
    private String districtOrCounty;
    /**
     * <p>
     * The postal code associated with the address.
     * </p>
     */
    private String postalCode;
    /**
     * <p>
     * The state, region, or province that the address is located.
     * </p>
     * <p>
     * If this is required for tax settings, use the same name as shown on the <b>Tax Settings</b> page.
     * </p>
     */
    private String stateOrRegion;

    /**
     * <p>
     * The first line of the address.
     * </p>
     * 
     * @param addressLine1
     *        The first line of the address.
     */

    public void setAddressLine1(String addressLine1) {
        this.addressLine1 = addressLine1;
    }

    /**
     * <p>
     * The first line of the address.
     * </p>
     * 
     * @return The first line of the address.
     */

    public String getAddressLine1() {
        return this.addressLine1;
    }

    /**
     * <p>
     * The first line of the address.
     * </p>
     * 
     * @param addressLine1
     *        The first line of the address.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public Address withAddressLine1(String addressLine1) {
        setAddressLine1(addressLine1);
        return this;
    }

    /**
     * <p>
     * The second line of the address, if applicable.
     * </p>
     * 
     * @param addressLine2
     *        The second line of the address, if applicable.
     */

    public void setAddressLine2(String addressLine2) {
        this.addressLine2 = addressLine2;
    }

    /**
     * <p>
     * The second line of the address, if applicable.
     * </p>
     * 
     * @return The second line of the address, if applicable.
     */

    public String getAddressLine2() {
        return this.addressLine2;
    }

    /**
     * <p>
     * The second line of the address, if applicable.
     * </p>
     * 
     * @param addressLine2
     *        The second line of the address, if applicable.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public Address withAddressLine2(String addressLine2) {
        setAddressLine2(addressLine2);
        return this;
    }

    /**
     * <p>
     * The third line of the address, if applicable. Currently, the Tax Settings API accepts the
     * <code>addressLine3</code> parameter only for Saudi Arabia. When you specify a TRN in Saudi Arabia, you must enter
     * the <code>addressLine3</code> and specify the building number for the address. For example, you might enter
     * <code>1234</code>.
     * </p>
     * 
     * @param addressLine3
     *        The third line of the address, if applicable. Currently, the Tax Settings API accepts the
     *        <code>addressLine3</code> parameter only for Saudi Arabia. When you specify a TRN in Saudi Arabia, you
     *        must enter the <code>addressLine3</code> and specify the building number for the address. For example, you
     *        might enter <code>1234</code>.
     */

    public void setAddressLine3(String addressLine3) {
        this.addressLine3 = addressLine3;
    }

    /**
     * <p>
     * The third line of the address, if applicable. Currently, the Tax Settings API accepts the
     * <code>addressLine3</code> parameter only for Saudi Arabia. When you specify a TRN in Saudi Arabia, you must enter
     * the <code>addressLine3</code> and specify the building number for the address. For example, you might enter
     * <code>1234</code>.
     * </p>
     * 
     * @return The third line of the address, if applicable. Currently, the Tax Settings API accepts the
     *         <code>addressLine3</code> parameter only for Saudi Arabia. When you specify a TRN in Saudi Arabia, you
     *         must enter the <code>addressLine3</code> and specify the building number for the address. For example,
     *         you might enter <code>1234</code>.
     */

    public String getAddressLine3() {
        return this.addressLine3;
    }

    /**
     * <p>
     * The third line of the address, if applicable. Currently, the Tax Settings API accepts the
     * <code>addressLine3</code> parameter only for Saudi Arabia. When you specify a TRN in Saudi Arabia, you must enter
     * the <code>addressLine3</code> and specify the building number for the address. For example, you might enter
     * <code>1234</code>.
     * </p>
     * 
     * @param addressLine3
     *        The third line of the address, if applicable. Currently, the Tax Settings API accepts the
     *        <code>addressLine3</code> parameter only for Saudi Arabia. When you specify a TRN in Saudi Arabia, you
     *        must enter the <code>addressLine3</code> and specify the building number for the address. For example, you
     *        might enter <code>1234</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public Address withAddressLine3(String addressLine3) {
        setAddressLine3(addressLine3);
        return this;
    }

    /**
     * <p>
     * The city that the address is in.
     * </p>
     * 
     * @param city
     *        The city that the address is in.
     */

    public void setCity(String city) {
        this.city = city;
    }

    /**
     * <p>
     * The city that the address is in.
     * </p>
     * 
     * @return The city that the address is in.
     */

    public String getCity() {
        return this.city;
    }

    /**
     * <p>
     * The city that the address is in.
     * </p>
     * 
     * @param city
     *        The city that the address is in.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public Address withCity(String city) {
        setCity(city);
        return this;
    }

    /**
     * <p>
     * The country code for the country that the address is in.
     * </p>
     * 
     * @param countryCode
     *        The country code for the country that the address is in.
     */

    public void setCountryCode(String countryCode) {
        this.countryCode = countryCode;
    }

    /**
     * <p>
     * The country code for the country that the address is in.
     * </p>
     * 
     * @return The country code for the country that the address is in.
     */

    public String getCountryCode() {
        return this.countryCode;
    }

    /**
     * <p>
     * The country code for the country that the address is in.
     * </p>
     * 
     * @param countryCode
     *        The country code for the country that the address is in.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public Address withCountryCode(String countryCode) {
        setCountryCode(countryCode);
        return this;
    }

    /**
     * <p>
     * The district or county the address is located.
     * </p>
     * <note>
     * <p>
     * For addresses in Brazil, this parameter uses the name of the neighborhood. When you set a TRN in Brazil, use
     * <code>districtOrCounty</code> for the neighborhood name.
     * </p>
     * </note>
     * 
     * @param districtOrCounty
     *        The district or county the address is located. </p> <note>
     *        <p>
     *        For addresses in Brazil, this parameter uses the name of the neighborhood. When you set a TRN in Brazil,
     *        use <code>districtOrCounty</code> for the neighborhood name.
     *        </p>
     */

    public void setDistrictOrCounty(String districtOrCounty) {
        this.districtOrCounty = districtOrCounty;
    }

    /**
     * <p>
     * The district or county the address is located.
     * </p>
     * <note>
     * <p>
     * For addresses in Brazil, this parameter uses the name of the neighborhood. When you set a TRN in Brazil, use
     * <code>districtOrCounty</code> for the neighborhood name.
     * </p>
     * </note>
     * 
     * @return The district or county the address is located. </p> <note>
     *         <p>
     *         For addresses in Brazil, this parameter uses the name of the neighborhood. When you set a TRN in Brazil,
     *         use <code>districtOrCounty</code> for the neighborhood name.
     *         </p>
     */

    public String getDistrictOrCounty() {
        return this.districtOrCounty;
    }

    /**
     * <p>
     * The district or county the address is located.
     * </p>
     * <note>
     * <p>
     * For addresses in Brazil, this parameter uses the name of the neighborhood. When you set a TRN in Brazil, use
     * <code>districtOrCounty</code> for the neighborhood name.
     * </p>
     * </note>
     * 
     * @param districtOrCounty
     *        The district or county the address is located. </p> <note>
     *        <p>
     *        For addresses in Brazil, this parameter uses the name of the neighborhood. When you set a TRN in Brazil,
     *        use <code>districtOrCounty</code> for the neighborhood name.
     *        </p>
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public Address withDistrictOrCounty(String districtOrCounty) {
        setDistrictOrCounty(districtOrCounty);
        return this;
    }

    /**
     * <p>
     * The postal code associated with the address.
     * </p>
     * 
     * @param postalCode
     *        The postal code associated with the address.
     */

    public void setPostalCode(String postalCode) {
        this.postalCode = postalCode;
    }

    /**
     * <p>
     * The postal code associated with the address.
     * </p>
     * 
     * @return The postal code associated with the address.
     */

    public String getPostalCode() {
        return this.postalCode;
    }

    /**
     * <p>
     * The postal code associated with the address.
     * </p>
     * 
     * @param postalCode
     *        The postal code associated with the address.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public Address withPostalCode(String postalCode) {
        setPostalCode(postalCode);
        return this;
    }

    /**
     * <p>
     * The state, region, or province that the address is located.
     * </p>
     * <p>
     * If this is required for tax settings, use the same name as shown on the <b>Tax Settings</b> page.
     * </p>
     * 
     * @param stateOrRegion
     *        The state, region, or province that the address is located.</p>
     *        <p>
     *        If this is required for tax settings, use the same name as shown on the <b>Tax Settings</b> page.
     */

    public void setStateOrRegion(String stateOrRegion) {
        this.stateOrRegion = stateOrRegion;
    }

    /**
     * <p>
     * The state, region, or province that the address is located.
     * </p>
     * <p>
     * If this is required for tax settings, use the same name as shown on the <b>Tax Settings</b> page.
     * </p>
     * 
     * @return The state, region, or province that the address is located.</p>
     *         <p>
     *         If this is required for tax settings, use the same name as shown on the <b>Tax Settings</b> page.
     */

    public String getStateOrRegion() {
        return this.stateOrRegion;
    }

    /**
     * <p>
     * The state, region, or province that the address is located.
     * </p>
     * <p>
     * If this is required for tax settings, use the same name as shown on the <b>Tax Settings</b> page.
     * </p>
     * 
     * @param stateOrRegion
     *        The state, region, or province that the address is located.</p>
     *        <p>
     *        If this is required for tax settings, use the same name as shown on the <b>Tax Settings</b> page.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public Address withStateOrRegion(String stateOrRegion) {
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
        if (getAddressLine1() != null)
            sb.append("AddressLine1: ").append(getAddressLine1()).append(",");
        if (getAddressLine2() != null)
            sb.append("AddressLine2: ").append(getAddressLine2()).append(",");
        if (getAddressLine3() != null)
            sb.append("AddressLine3: ").append(getAddressLine3()).append(",");
        if (getCity() != null)
            sb.append("City: ").append(getCity()).append(",");
        if (getCountryCode() != null)
            sb.append("CountryCode: ").append(getCountryCode()).append(",");
        if (getDistrictOrCounty() != null)
            sb.append("DistrictOrCounty: ").append(getDistrictOrCounty()).append(",");
        if (getPostalCode() != null)
            sb.append("PostalCode: ").append(getPostalCode()).append(",");
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

        if (obj instanceof Address == false)
            return false;
        Address other = (Address) obj;
        if (other.getAddressLine1() == null ^ this.getAddressLine1() == null)
            return false;
        if (other.getAddressLine1() != null && other.getAddressLine1().equals(this.getAddressLine1()) == false)
            return false;
        if (other.getAddressLine2() == null ^ this.getAddressLine2() == null)
            return false;
        if (other.getAddressLine2() != null && other.getAddressLine2().equals(this.getAddressLine2()) == false)
            return false;
        if (other.getAddressLine3() == null ^ this.getAddressLine3() == null)
            return false;
        if (other.getAddressLine3() != null && other.getAddressLine3().equals(this.getAddressLine3()) == false)
            return false;
        if (other.getCity() == null ^ this.getCity() == null)
            return false;
        if (other.getCity() != null && other.getCity().equals(this.getCity()) == false)
            return false;
        if (other.getCountryCode() == null ^ this.getCountryCode() == null)
            return false;
        if (other.getCountryCode() != null && other.getCountryCode().equals(this.getCountryCode()) == false)
            return false;
        if (other.getDistrictOrCounty() == null ^ this.getDistrictOrCounty() == null)
            return false;
        if (other.getDistrictOrCounty() != null && other.getDistrictOrCounty().equals(this.getDistrictOrCounty()) == false)
            return false;
        if (other.getPostalCode() == null ^ this.getPostalCode() == null)
            return false;
        if (other.getPostalCode() != null && other.getPostalCode().equals(this.getPostalCode()) == false)
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

        hashCode = prime * hashCode + ((getAddressLine1() == null) ? 0 : getAddressLine1().hashCode());
        hashCode = prime * hashCode + ((getAddressLine2() == null) ? 0 : getAddressLine2().hashCode());
        hashCode = prime * hashCode + ((getAddressLine3() == null) ? 0 : getAddressLine3().hashCode());
        hashCode = prime * hashCode + ((getCity() == null) ? 0 : getCity().hashCode());
        hashCode = prime * hashCode + ((getCountryCode() == null) ? 0 : getCountryCode().hashCode());
        hashCode = prime * hashCode + ((getDistrictOrCounty() == null) ? 0 : getDistrictOrCounty().hashCode());
        hashCode = prime * hashCode + ((getPostalCode() == null) ? 0 : getPostalCode().hashCode());
        hashCode = prime * hashCode + ((getStateOrRegion() == null) ? 0 : getStateOrRegion().hashCode());
        return hashCode;
    }

    @Override
    public Address clone() {
        try {
            return (Address) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.taxsettings.model.transform.AddressMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
