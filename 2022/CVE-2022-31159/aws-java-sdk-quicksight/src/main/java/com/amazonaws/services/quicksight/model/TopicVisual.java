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
 * The definition for a <code>TopicVisual</code>.
 * </p>
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/quicksight-2018-04-01/TopicVisual" target="_top">AWS API
 *      Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class TopicVisual implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * The visual ID for the <code>TopicVisual</code>.
     * </p>
     */
    private String visualId;
    /**
     * <p>
     * The role for the <code>TopicVisual</code>.
     * </p>
     */
    private String role;
    /**
     * <p>
     * The ir for the <code>TopicVisual</code>.
     * </p>
     */
    private TopicIR ir;
    /**
     * <p>
     * The supporting visuals for the <code>TopicVisual</code>.
     * </p>
     */
    private java.util.List<TopicVisual> supportingVisuals;

    /**
     * <p>
     * The visual ID for the <code>TopicVisual</code>.
     * </p>
     * 
     * @param visualId
     *        The visual ID for the <code>TopicVisual</code>.
     */

    public void setVisualId(String visualId) {
        this.visualId = visualId;
    }

    /**
     * <p>
     * The visual ID for the <code>TopicVisual</code>.
     * </p>
     * 
     * @return The visual ID for the <code>TopicVisual</code>.
     */

    public String getVisualId() {
        return this.visualId;
    }

    /**
     * <p>
     * The visual ID for the <code>TopicVisual</code>.
     * </p>
     * 
     * @param visualId
     *        The visual ID for the <code>TopicVisual</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public TopicVisual withVisualId(String visualId) {
        setVisualId(visualId);
        return this;
    }

    /**
     * <p>
     * The role for the <code>TopicVisual</code>.
     * </p>
     * 
     * @param role
     *        The role for the <code>TopicVisual</code>.
     * @see VisualRole
     */

    public void setRole(String role) {
        this.role = role;
    }

    /**
     * <p>
     * The role for the <code>TopicVisual</code>.
     * </p>
     * 
     * @return The role for the <code>TopicVisual</code>.
     * @see VisualRole
     */

    public String getRole() {
        return this.role;
    }

    /**
     * <p>
     * The role for the <code>TopicVisual</code>.
     * </p>
     * 
     * @param role
     *        The role for the <code>TopicVisual</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see VisualRole
     */

    public TopicVisual withRole(String role) {
        setRole(role);
        return this;
    }

    /**
     * <p>
     * The role for the <code>TopicVisual</code>.
     * </p>
     * 
     * @param role
     *        The role for the <code>TopicVisual</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see VisualRole
     */

    public TopicVisual withRole(VisualRole role) {
        this.role = role.toString();
        return this;
    }

    /**
     * <p>
     * The ir for the <code>TopicVisual</code>.
     * </p>
     * 
     * @param ir
     *        The ir for the <code>TopicVisual</code>.
     */

    public void setIr(TopicIR ir) {
        this.ir = ir;
    }

    /**
     * <p>
     * The ir for the <code>TopicVisual</code>.
     * </p>
     * 
     * @return The ir for the <code>TopicVisual</code>.
     */

    public TopicIR getIr() {
        return this.ir;
    }

    /**
     * <p>
     * The ir for the <code>TopicVisual</code>.
     * </p>
     * 
     * @param ir
     *        The ir for the <code>TopicVisual</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public TopicVisual withIr(TopicIR ir) {
        setIr(ir);
        return this;
    }

    /**
     * <p>
     * The supporting visuals for the <code>TopicVisual</code>.
     * </p>
     * 
     * @return The supporting visuals for the <code>TopicVisual</code>.
     */

    public java.util.List<TopicVisual> getSupportingVisuals() {
        return supportingVisuals;
    }

    /**
     * <p>
     * The supporting visuals for the <code>TopicVisual</code>.
     * </p>
     * 
     * @param supportingVisuals
     *        The supporting visuals for the <code>TopicVisual</code>.
     */

    public void setSupportingVisuals(java.util.Collection<TopicVisual> supportingVisuals) {
        if (supportingVisuals == null) {
            this.supportingVisuals = null;
            return;
        }

        this.supportingVisuals = new java.util.ArrayList<TopicVisual>(supportingVisuals);
    }

    /**
     * <p>
     * The supporting visuals for the <code>TopicVisual</code>.
     * </p>
     * <p>
     * <b>NOTE:</b> This method appends the values to the existing list (if any). Use
     * {@link #setSupportingVisuals(java.util.Collection)} or {@link #withSupportingVisuals(java.util.Collection)} if
     * you want to override the existing values.
     * </p>
     * 
     * @param supportingVisuals
     *        The supporting visuals for the <code>TopicVisual</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public TopicVisual withSupportingVisuals(TopicVisual... supportingVisuals) {
        if (this.supportingVisuals == null) {
            setSupportingVisuals(new java.util.ArrayList<TopicVisual>(supportingVisuals.length));
        }
        for (TopicVisual ele : supportingVisuals) {
            this.supportingVisuals.add(ele);
        }
        return this;
    }

    /**
     * <p>
     * The supporting visuals for the <code>TopicVisual</code>.
     * </p>
     * 
     * @param supportingVisuals
     *        The supporting visuals for the <code>TopicVisual</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public TopicVisual withSupportingVisuals(java.util.Collection<TopicVisual> supportingVisuals) {
        setSupportingVisuals(supportingVisuals);
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
        if (getVisualId() != null)
            sb.append("VisualId: ").append(getVisualId()).append(",");
        if (getRole() != null)
            sb.append("Role: ").append(getRole()).append(",");
        if (getIr() != null)
            sb.append("Ir: ").append(getIr()).append(",");
        if (getSupportingVisuals() != null)
            sb.append("SupportingVisuals: ").append(getSupportingVisuals());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof TopicVisual == false)
            return false;
        TopicVisual other = (TopicVisual) obj;
        if (other.getVisualId() == null ^ this.getVisualId() == null)
            return false;
        if (other.getVisualId() != null && other.getVisualId().equals(this.getVisualId()) == false)
            return false;
        if (other.getRole() == null ^ this.getRole() == null)
            return false;
        if (other.getRole() != null && other.getRole().equals(this.getRole()) == false)
            return false;
        if (other.getIr() == null ^ this.getIr() == null)
            return false;
        if (other.getIr() != null && other.getIr().equals(this.getIr()) == false)
            return false;
        if (other.getSupportingVisuals() == null ^ this.getSupportingVisuals() == null)
            return false;
        if (other.getSupportingVisuals() != null && other.getSupportingVisuals().equals(this.getSupportingVisuals()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getVisualId() == null) ? 0 : getVisualId().hashCode());
        hashCode = prime * hashCode + ((getRole() == null) ? 0 : getRole().hashCode());
        hashCode = prime * hashCode + ((getIr() == null) ? 0 : getIr().hashCode());
        hashCode = prime * hashCode + ((getSupportingVisuals() == null) ? 0 : getSupportingVisuals().hashCode());
        return hashCode;
    }

    @Override
    public TopicVisual clone() {
        try {
            return (TopicVisual) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.quicksight.model.transform.TopicVisualMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
