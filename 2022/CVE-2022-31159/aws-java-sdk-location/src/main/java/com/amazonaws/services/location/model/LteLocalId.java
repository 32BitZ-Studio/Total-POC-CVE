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
package com.amazonaws.services.location.model;

import java.io.Serializable;
import javax.annotation.Generated;
import com.amazonaws.protocol.StructuredPojo;
import com.amazonaws.protocol.ProtocolMarshaller;

/**
 * <p>
 * LTE local identification information (local ID).
 * </p>
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/location-2020-11-19/LteLocalId" target="_top">AWS API
 *      Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class LteLocalId implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * E-UTRA (Evolved Universal Terrestrial Radio Access) absolute radio frequency channel number (EARFCN).
     * </p>
     */
    private Integer earfcn;
    /**
     * <p>
     * Physical Cell ID (PCI).
     * </p>
     */
    private Integer pci;

    /**
     * <p>
     * E-UTRA (Evolved Universal Terrestrial Radio Access) absolute radio frequency channel number (EARFCN).
     * </p>
     * 
     * @param earfcn
     *        E-UTRA (Evolved Universal Terrestrial Radio Access) absolute radio frequency channel number (EARFCN).
     */

    public void setEarfcn(Integer earfcn) {
        this.earfcn = earfcn;
    }

    /**
     * <p>
     * E-UTRA (Evolved Universal Terrestrial Radio Access) absolute radio frequency channel number (EARFCN).
     * </p>
     * 
     * @return E-UTRA (Evolved Universal Terrestrial Radio Access) absolute radio frequency channel number (EARFCN).
     */

    public Integer getEarfcn() {
        return this.earfcn;
    }

    /**
     * <p>
     * E-UTRA (Evolved Universal Terrestrial Radio Access) absolute radio frequency channel number (EARFCN).
     * </p>
     * 
     * @param earfcn
     *        E-UTRA (Evolved Universal Terrestrial Radio Access) absolute radio frequency channel number (EARFCN).
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public LteLocalId withEarfcn(Integer earfcn) {
        setEarfcn(earfcn);
        return this;
    }

    /**
     * <p>
     * Physical Cell ID (PCI).
     * </p>
     * 
     * @param pci
     *        Physical Cell ID (PCI).
     */

    public void setPci(Integer pci) {
        this.pci = pci;
    }

    /**
     * <p>
     * Physical Cell ID (PCI).
     * </p>
     * 
     * @return Physical Cell ID (PCI).
     */

    public Integer getPci() {
        return this.pci;
    }

    /**
     * <p>
     * Physical Cell ID (PCI).
     * </p>
     * 
     * @param pci
     *        Physical Cell ID (PCI).
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public LteLocalId withPci(Integer pci) {
        setPci(pci);
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
        if (getEarfcn() != null)
            sb.append("Earfcn: ").append(getEarfcn()).append(",");
        if (getPci() != null)
            sb.append("Pci: ").append(getPci());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof LteLocalId == false)
            return false;
        LteLocalId other = (LteLocalId) obj;
        if (other.getEarfcn() == null ^ this.getEarfcn() == null)
            return false;
        if (other.getEarfcn() != null && other.getEarfcn().equals(this.getEarfcn()) == false)
            return false;
        if (other.getPci() == null ^ this.getPci() == null)
            return false;
        if (other.getPci() != null && other.getPci().equals(this.getPci()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getEarfcn() == null) ? 0 : getEarfcn().hashCode());
        hashCode = prime * hashCode + ((getPci() == null) ? 0 : getPci().hashCode());
        return hashCode;
    }

    @Override
    public LteLocalId clone() {
        try {
            return (LteLocalId) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.location.model.transform.LteLocalIdMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
