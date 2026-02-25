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
package com.amazonaws.services.quicksight.model;

import java.io.Serializable;
import javax.annotation.Generated;
import com.amazonaws.protocol.StructuredPojo;
import com.amazonaws.protocol.ProtocolMarshaller;

/**
 * <p>
 * The definition for the slot.
 * </p>
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/quicksight-2018-04-01/Slot" target="_top">AWS API
 *      Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class Slot implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * The slot ID of the slot.
     * </p>
     */
    private String slotId;
    /**
     * <p>
     * The visual ID for the slot.
     * </p>
     */
    private String visualId;

    /**
     * <p>
     * The slot ID of the slot.
     * </p>
     * 
     * @param slotId
     *        The slot ID of the slot.
     */

    public void setSlotId(String slotId) {
        this.slotId = slotId;
    }

    /**
     * <p>
     * The slot ID of the slot.
     * </p>
     * 
     * @return The slot ID of the slot.
     */

    public String getSlotId() {
        return this.slotId;
    }

    /**
     * <p>
     * The slot ID of the slot.
     * </p>
     * 
     * @param slotId
     *        The slot ID of the slot.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public Slot withSlotId(String slotId) {
        setSlotId(slotId);
        return this;
    }

    /**
     * <p>
     * The visual ID for the slot.
     * </p>
     * 
     * @param visualId
     *        The visual ID for the slot.
     */

    public void setVisualId(String visualId) {
        this.visualId = visualId;
    }

    /**
     * <p>
     * The visual ID for the slot.
     * </p>
     * 
     * @return The visual ID for the slot.
     */

    public String getVisualId() {
        return this.visualId;
    }

    /**
     * <p>
     * The visual ID for the slot.
     * </p>
     * 
     * @param visualId
     *        The visual ID for the slot.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public Slot withVisualId(String visualId) {
        setVisualId(visualId);
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
        if (getSlotId() != null)
            sb.append("SlotId: ").append(getSlotId()).append(",");
        if (getVisualId() != null)
            sb.append("VisualId: ").append(getVisualId());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof Slot == false)
            return false;
        Slot other = (Slot) obj;
        if (other.getSlotId() == null ^ this.getSlotId() == null)
            return false;
        if (other.getSlotId() != null && other.getSlotId().equals(this.getSlotId()) == false)
            return false;
        if (other.getVisualId() == null ^ this.getVisualId() == null)
            return false;
        if (other.getVisualId() != null && other.getVisualId().equals(this.getVisualId()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getSlotId() == null) ? 0 : getSlotId().hashCode());
        hashCode = prime * hashCode + ((getVisualId() == null) ? 0 : getVisualId().hashCode());
        return hashCode;
    }

    @Override
    public Slot clone() {
        try {
            return (Slot) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.quicksight.model.transform.SlotMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
