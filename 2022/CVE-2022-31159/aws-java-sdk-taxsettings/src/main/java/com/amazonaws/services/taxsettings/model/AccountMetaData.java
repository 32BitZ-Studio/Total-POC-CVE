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
 * The meta data information associated with the account.
 * </p>
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/taxsettings-2018-05-10/AccountMetaData" target="_top">AWS API
 *      Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class AccountMetaData implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * The Amazon Web Services accounts name.
     * </p>
     */
    private String accountName;

    private Address address;
    /**
     * <p>
     * Address roles associated with the account containing country code information.
     * </p>
     */
    private java.util.Map<String, Jurisdiction> addressRoleMap;
    /**
     * <p>
     * The type of address associated with the legal profile.
     * </p>
     */
    private String addressType;
    /**
     * <p>
     * Seller information associated with the account.
     * </p>
     */
    private String seller;

    /**
     * <p>
     * The Amazon Web Services accounts name.
     * </p>
     * 
     * @param accountName
     *        The Amazon Web Services accounts name.
     */

    public void setAccountName(String accountName) {
        this.accountName = accountName;
    }

    /**
     * <p>
     * The Amazon Web Services accounts name.
     * </p>
     * 
     * @return The Amazon Web Services accounts name.
     */

    public String getAccountName() {
        return this.accountName;
    }

    /**
     * <p>
     * The Amazon Web Services accounts name.
     * </p>
     * 
     * @param accountName
     *        The Amazon Web Services accounts name.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public AccountMetaData withAccountName(String accountName) {
        setAccountName(accountName);
        return this;
    }

    /**
     * @param address
     */

    public void setAddress(Address address) {
        this.address = address;
    }

    /**
     * @return
     */

    public Address getAddress() {
        return this.address;
    }

    /**
     * @param address
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public AccountMetaData withAddress(Address address) {
        setAddress(address);
        return this;
    }

    /**
     * <p>
     * Address roles associated with the account containing country code information.
     * </p>
     * 
     * @return Address roles associated with the account containing country code information.
     */

    public java.util.Map<String, Jurisdiction> getAddressRoleMap() {
        return addressRoleMap;
    }

    /**
     * <p>
     * Address roles associated with the account containing country code information.
     * </p>
     * 
     * @param addressRoleMap
     *        Address roles associated with the account containing country code information.
     */

    public void setAddressRoleMap(java.util.Map<String, Jurisdiction> addressRoleMap) {
        this.addressRoleMap = addressRoleMap;
    }

    /**
     * <p>
     * Address roles associated with the account containing country code information.
     * </p>
     * 
     * @param addressRoleMap
     *        Address roles associated with the account containing country code information.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public AccountMetaData withAddressRoleMap(java.util.Map<String, Jurisdiction> addressRoleMap) {
        setAddressRoleMap(addressRoleMap);
        return this;
    }

    /**
     * Add a single AddressRoleMap entry
     *
     * @see AccountMetaData#withAddressRoleMap
     * @returns a reference to this object so that method calls can be chained together.
     */

    public AccountMetaData addAddressRoleMapEntry(String key, Jurisdiction value) {
        if (null == this.addressRoleMap) {
            this.addressRoleMap = new java.util.HashMap<String, Jurisdiction>();
        }
        if (this.addressRoleMap.containsKey(key))
            throw new IllegalArgumentException("Duplicated keys (" + key.toString() + ") are provided.");
        this.addressRoleMap.put(key, value);
        return this;
    }

    /**
     * Removes all the entries added into AddressRoleMap.
     *
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public AccountMetaData clearAddressRoleMapEntries() {
        this.addressRoleMap = null;
        return this;
    }

    /**
     * <p>
     * The type of address associated with the legal profile.
     * </p>
     * 
     * @param addressType
     *        The type of address associated with the legal profile.
     * @see AddressRoleType
     */

    public void setAddressType(String addressType) {
        this.addressType = addressType;
    }

    /**
     * <p>
     * The type of address associated with the legal profile.
     * </p>
     * 
     * @return The type of address associated with the legal profile.
     * @see AddressRoleType
     */

    public String getAddressType() {
        return this.addressType;
    }

    /**
     * <p>
     * The type of address associated with the legal profile.
     * </p>
     * 
     * @param addressType
     *        The type of address associated with the legal profile.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see AddressRoleType
     */

    public AccountMetaData withAddressType(String addressType) {
        setAddressType(addressType);
        return this;
    }

    /**
     * <p>
     * The type of address associated with the legal profile.
     * </p>
     * 
     * @param addressType
     *        The type of address associated with the legal profile.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see AddressRoleType
     */

    public AccountMetaData withAddressType(AddressRoleType addressType) {
        this.addressType = addressType.toString();
        return this;
    }

    /**
     * <p>
     * Seller information associated with the account.
     * </p>
     * 
     * @param seller
     *        Seller information associated with the account.
     */

    public void setSeller(String seller) {
        this.seller = seller;
    }

    /**
     * <p>
     * Seller information associated with the account.
     * </p>
     * 
     * @return Seller information associated with the account.
     */

    public String getSeller() {
        return this.seller;
    }

    /**
     * <p>
     * Seller information associated with the account.
     * </p>
     * 
     * @param seller
     *        Seller information associated with the account.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public AccountMetaData withSeller(String seller) {
        setSeller(seller);
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
        if (getAccountName() != null)
            sb.append("AccountName: ").append(getAccountName()).append(",");
        if (getAddress() != null)
            sb.append("Address: ").append(getAddress()).append(",");
        if (getAddressRoleMap() != null)
            sb.append("AddressRoleMap: ").append(getAddressRoleMap()).append(",");
        if (getAddressType() != null)
            sb.append("AddressType: ").append(getAddressType()).append(",");
        if (getSeller() != null)
            sb.append("Seller: ").append(getSeller());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof AccountMetaData == false)
            return false;
        AccountMetaData other = (AccountMetaData) obj;
        if (other.getAccountName() == null ^ this.getAccountName() == null)
            return false;
        if (other.getAccountName() != null && other.getAccountName().equals(this.getAccountName()) == false)
            return false;
        if (other.getAddress() == null ^ this.getAddress() == null)
            return false;
        if (other.getAddress() != null && other.getAddress().equals(this.getAddress()) == false)
            return false;
        if (other.getAddressRoleMap() == null ^ this.getAddressRoleMap() == null)
            return false;
        if (other.getAddressRoleMap() != null && other.getAddressRoleMap().equals(this.getAddressRoleMap()) == false)
            return false;
        if (other.getAddressType() == null ^ this.getAddressType() == null)
            return false;
        if (other.getAddressType() != null && other.getAddressType().equals(this.getAddressType()) == false)
            return false;
        if (other.getSeller() == null ^ this.getSeller() == null)
            return false;
        if (other.getSeller() != null && other.getSeller().equals(this.getSeller()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getAccountName() == null) ? 0 : getAccountName().hashCode());
        hashCode = prime * hashCode + ((getAddress() == null) ? 0 : getAddress().hashCode());
        hashCode = prime * hashCode + ((getAddressRoleMap() == null) ? 0 : getAddressRoleMap().hashCode());
        hashCode = prime * hashCode + ((getAddressType() == null) ? 0 : getAddressType().hashCode());
        hashCode = prime * hashCode + ((getSeller() == null) ? 0 : getSeller().hashCode());
        return hashCode;
    }

    @Override
    public AccountMetaData clone() {
        try {
            return (AccountMetaData) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.taxsettings.model.transform.AccountMetaDataMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
