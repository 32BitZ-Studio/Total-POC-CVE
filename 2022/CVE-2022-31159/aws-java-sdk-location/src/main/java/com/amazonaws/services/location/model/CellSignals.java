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
 * The cellular network communication infrastructure that the device uses.
 * </p>
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/location-2020-11-19/CellSignals" target="_top">AWS API
 *      Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class CellSignals implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * Information about the Long-Term Evolution (LTE) network the device is connected to.
     * </p>
     */
    private java.util.List<LteCellDetails> lteCellDetails;

    /**
     * <p>
     * Information about the Long-Term Evolution (LTE) network the device is connected to.
     * </p>
     * 
     * @return Information about the Long-Term Evolution (LTE) network the device is connected to.
     */

    public java.util.List<LteCellDetails> getLteCellDetails() {
        return lteCellDetails;
    }

    /**
     * <p>
     * Information about the Long-Term Evolution (LTE) network the device is connected to.
     * </p>
     * 
     * @param lteCellDetails
     *        Information about the Long-Term Evolution (LTE) network the device is connected to.
     */

    public void setLteCellDetails(java.util.Collection<LteCellDetails> lteCellDetails) {
        if (lteCellDetails == null) {
            this.lteCellDetails = null;
            return;
        }

        this.lteCellDetails = new java.util.ArrayList<LteCellDetails>(lteCellDetails);
    }

    /**
     * <p>
     * Information about the Long-Term Evolution (LTE) network the device is connected to.
     * </p>
     * <p>
     * <b>NOTE:</b> This method appends the values to the existing list (if any). Use
     * {@link #setLteCellDetails(java.util.Collection)} or {@link #withLteCellDetails(java.util.Collection)} if you want
     * to override the existing values.
     * </p>
     * 
     * @param lteCellDetails
     *        Information about the Long-Term Evolution (LTE) network the device is connected to.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public CellSignals withLteCellDetails(LteCellDetails... lteCellDetails) {
        if (this.lteCellDetails == null) {
            setLteCellDetails(new java.util.ArrayList<LteCellDetails>(lteCellDetails.length));
        }
        for (LteCellDetails ele : lteCellDetails) {
            this.lteCellDetails.add(ele);
        }
        return this;
    }

    /**
     * <p>
     * Information about the Long-Term Evolution (LTE) network the device is connected to.
     * </p>
     * 
     * @param lteCellDetails
     *        Information about the Long-Term Evolution (LTE) network the device is connected to.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public CellSignals withLteCellDetails(java.util.Collection<LteCellDetails> lteCellDetails) {
        setLteCellDetails(lteCellDetails);
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
        if (getLteCellDetails() != null)
            sb.append("LteCellDetails: ").append(getLteCellDetails());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof CellSignals == false)
            return false;
        CellSignals other = (CellSignals) obj;
        if (other.getLteCellDetails() == null ^ this.getLteCellDetails() == null)
            return false;
        if (other.getLteCellDetails() != null && other.getLteCellDetails().equals(this.getLteCellDetails()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getLteCellDetails() == null) ? 0 : getLteCellDetails().hashCode());
        return hashCode;
    }

    @Override
    public CellSignals clone() {
        try {
            return (CellSignals) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.location.model.transform.CellSignalsMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
