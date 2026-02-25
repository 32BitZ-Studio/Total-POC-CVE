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
 * The definition for a <code>TopicTemplate</code>.
 * </p>
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/quicksight-2018-04-01/TopicTemplate" target="_top">AWS API
 *      Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class TopicTemplate implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * The template type for the <code>TopicTemplate</code>.
     * </p>
     */
    private String templateType;
    /**
     * <p>
     * The slots for the <code>TopicTemplate</code>.
     * </p>
     */
    private java.util.List<Slot> slots;

    /**
     * <p>
     * The template type for the <code>TopicTemplate</code>.
     * </p>
     * 
     * @param templateType
     *        The template type for the <code>TopicTemplate</code>.
     */

    public void setTemplateType(String templateType) {
        this.templateType = templateType;
    }

    /**
     * <p>
     * The template type for the <code>TopicTemplate</code>.
     * </p>
     * 
     * @return The template type for the <code>TopicTemplate</code>.
     */

    public String getTemplateType() {
        return this.templateType;
    }

    /**
     * <p>
     * The template type for the <code>TopicTemplate</code>.
     * </p>
     * 
     * @param templateType
     *        The template type for the <code>TopicTemplate</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public TopicTemplate withTemplateType(String templateType) {
        setTemplateType(templateType);
        return this;
    }

    /**
     * <p>
     * The slots for the <code>TopicTemplate</code>.
     * </p>
     * 
     * @return The slots for the <code>TopicTemplate</code>.
     */

    public java.util.List<Slot> getSlots() {
        return slots;
    }

    /**
     * <p>
     * The slots for the <code>TopicTemplate</code>.
     * </p>
     * 
     * @param slots
     *        The slots for the <code>TopicTemplate</code>.
     */

    public void setSlots(java.util.Collection<Slot> slots) {
        if (slots == null) {
            this.slots = null;
            return;
        }

        this.slots = new java.util.ArrayList<Slot>(slots);
    }

    /**
     * <p>
     * The slots for the <code>TopicTemplate</code>.
     * </p>
     * <p>
     * <b>NOTE:</b> This method appends the values to the existing list (if any). Use
     * {@link #setSlots(java.util.Collection)} or {@link #withSlots(java.util.Collection)} if you want to override the
     * existing values.
     * </p>
     * 
     * @param slots
     *        The slots for the <code>TopicTemplate</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public TopicTemplate withSlots(Slot... slots) {
        if (this.slots == null) {
            setSlots(new java.util.ArrayList<Slot>(slots.length));
        }
        for (Slot ele : slots) {
            this.slots.add(ele);
        }
        return this;
    }

    /**
     * <p>
     * The slots for the <code>TopicTemplate</code>.
     * </p>
     * 
     * @param slots
     *        The slots for the <code>TopicTemplate</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public TopicTemplate withSlots(java.util.Collection<Slot> slots) {
        setSlots(slots);
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
        if (getTemplateType() != null)
            sb.append("TemplateType: ").append(getTemplateType()).append(",");
        if (getSlots() != null)
            sb.append("Slots: ").append(getSlots());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof TopicTemplate == false)
            return false;
        TopicTemplate other = (TopicTemplate) obj;
        if (other.getTemplateType() == null ^ this.getTemplateType() == null)
            return false;
        if (other.getTemplateType() != null && other.getTemplateType().equals(this.getTemplateType()) == false)
            return false;
        if (other.getSlots() == null ^ this.getSlots() == null)
            return false;
        if (other.getSlots() != null && other.getSlots().equals(this.getSlots()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getTemplateType() == null) ? 0 : getTemplateType().hashCode());
        hashCode = prime * hashCode + ((getSlots() == null) ? 0 : getSlots().hashCode());
        return hashCode;
    }

    @Override
    public TopicTemplate clone() {
        try {
            return (TopicTemplate) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.quicksight.model.transform.TopicTemplateMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
