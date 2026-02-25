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
 * The definition for a <code>TopicConstantValue</code>.
 * </p>
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/quicksight-2018-04-01/TopicConstantValue" target="_top">AWS API
 *      Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class TopicConstantValue implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * The constant type of a <code>TopicConstantValue</code>.
     * </p>
     */
    private String constantType;
    /**
     * <p>
     * The value of the <code>TopicConstantValue</code>.
     * </p>
     */
    private String value;
    /**
     * <p>
     * The minimum for the <code>TopicConstantValue</code>.
     * </p>
     */
    private String minimum;
    /**
     * <p>
     * The maximum for the <code>TopicConstantValue</code>.
     * </p>
     */
    private String maximum;
    /**
     * <p>
     * The value list of the <code>TopicConstantValue</code>.
     * </p>
     */
    private java.util.List<CollectiveConstantEntry> valueList;

    /**
     * <p>
     * The constant type of a <code>TopicConstantValue</code>.
     * </p>
     * 
     * @param constantType
     *        The constant type of a <code>TopicConstantValue</code>.
     * @see ConstantType
     */

    public void setConstantType(String constantType) {
        this.constantType = constantType;
    }

    /**
     * <p>
     * The constant type of a <code>TopicConstantValue</code>.
     * </p>
     * 
     * @return The constant type of a <code>TopicConstantValue</code>.
     * @see ConstantType
     */

    public String getConstantType() {
        return this.constantType;
    }

    /**
     * <p>
     * The constant type of a <code>TopicConstantValue</code>.
     * </p>
     * 
     * @param constantType
     *        The constant type of a <code>TopicConstantValue</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see ConstantType
     */

    public TopicConstantValue withConstantType(String constantType) {
        setConstantType(constantType);
        return this;
    }

    /**
     * <p>
     * The constant type of a <code>TopicConstantValue</code>.
     * </p>
     * 
     * @param constantType
     *        The constant type of a <code>TopicConstantValue</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see ConstantType
     */

    public TopicConstantValue withConstantType(ConstantType constantType) {
        this.constantType = constantType.toString();
        return this;
    }

    /**
     * <p>
     * The value of the <code>TopicConstantValue</code>.
     * </p>
     * 
     * @param value
     *        The value of the <code>TopicConstantValue</code>.
     */

    public void setValue(String value) {
        this.value = value;
    }

    /**
     * <p>
     * The value of the <code>TopicConstantValue</code>.
     * </p>
     * 
     * @return The value of the <code>TopicConstantValue</code>.
     */

    public String getValue() {
        return this.value;
    }

    /**
     * <p>
     * The value of the <code>TopicConstantValue</code>.
     * </p>
     * 
     * @param value
     *        The value of the <code>TopicConstantValue</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public TopicConstantValue withValue(String value) {
        setValue(value);
        return this;
    }

    /**
     * <p>
     * The minimum for the <code>TopicConstantValue</code>.
     * </p>
     * 
     * @param minimum
     *        The minimum for the <code>TopicConstantValue</code>.
     */

    public void setMinimum(String minimum) {
        this.minimum = minimum;
    }

    /**
     * <p>
     * The minimum for the <code>TopicConstantValue</code>.
     * </p>
     * 
     * @return The minimum for the <code>TopicConstantValue</code>.
     */

    public String getMinimum() {
        return this.minimum;
    }

    /**
     * <p>
     * The minimum for the <code>TopicConstantValue</code>.
     * </p>
     * 
     * @param minimum
     *        The minimum for the <code>TopicConstantValue</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public TopicConstantValue withMinimum(String minimum) {
        setMinimum(minimum);
        return this;
    }

    /**
     * <p>
     * The maximum for the <code>TopicConstantValue</code>.
     * </p>
     * 
     * @param maximum
     *        The maximum for the <code>TopicConstantValue</code>.
     */

    public void setMaximum(String maximum) {
        this.maximum = maximum;
    }

    /**
     * <p>
     * The maximum for the <code>TopicConstantValue</code>.
     * </p>
     * 
     * @return The maximum for the <code>TopicConstantValue</code>.
     */

    public String getMaximum() {
        return this.maximum;
    }

    /**
     * <p>
     * The maximum for the <code>TopicConstantValue</code>.
     * </p>
     * 
     * @param maximum
     *        The maximum for the <code>TopicConstantValue</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public TopicConstantValue withMaximum(String maximum) {
        setMaximum(maximum);
        return this;
    }

    /**
     * <p>
     * The value list of the <code>TopicConstantValue</code>.
     * </p>
     * 
     * @return The value list of the <code>TopicConstantValue</code>.
     */

    public java.util.List<CollectiveConstantEntry> getValueList() {
        return valueList;
    }

    /**
     * <p>
     * The value list of the <code>TopicConstantValue</code>.
     * </p>
     * 
     * @param valueList
     *        The value list of the <code>TopicConstantValue</code>.
     */

    public void setValueList(java.util.Collection<CollectiveConstantEntry> valueList) {
        if (valueList == null) {
            this.valueList = null;
            return;
        }

        this.valueList = new java.util.ArrayList<CollectiveConstantEntry>(valueList);
    }

    /**
     * <p>
     * The value list of the <code>TopicConstantValue</code>.
     * </p>
     * <p>
     * <b>NOTE:</b> This method appends the values to the existing list (if any). Use
     * {@link #setValueList(java.util.Collection)} or {@link #withValueList(java.util.Collection)} if you want to
     * override the existing values.
     * </p>
     * 
     * @param valueList
     *        The value list of the <code>TopicConstantValue</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public TopicConstantValue withValueList(CollectiveConstantEntry... valueList) {
        if (this.valueList == null) {
            setValueList(new java.util.ArrayList<CollectiveConstantEntry>(valueList.length));
        }
        for (CollectiveConstantEntry ele : valueList) {
            this.valueList.add(ele);
        }
        return this;
    }

    /**
     * <p>
     * The value list of the <code>TopicConstantValue</code>.
     * </p>
     * 
     * @param valueList
     *        The value list of the <code>TopicConstantValue</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public TopicConstantValue withValueList(java.util.Collection<CollectiveConstantEntry> valueList) {
        setValueList(valueList);
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
        if (getConstantType() != null)
            sb.append("ConstantType: ").append(getConstantType()).append(",");
        if (getValue() != null)
            sb.append("Value: ").append(getValue()).append(",");
        if (getMinimum() != null)
            sb.append("Minimum: ").append(getMinimum()).append(",");
        if (getMaximum() != null)
            sb.append("Maximum: ").append(getMaximum()).append(",");
        if (getValueList() != null)
            sb.append("ValueList: ").append(getValueList());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof TopicConstantValue == false)
            return false;
        TopicConstantValue other = (TopicConstantValue) obj;
        if (other.getConstantType() == null ^ this.getConstantType() == null)
            return false;
        if (other.getConstantType() != null && other.getConstantType().equals(this.getConstantType()) == false)
            return false;
        if (other.getValue() == null ^ this.getValue() == null)
            return false;
        if (other.getValue() != null && other.getValue().equals(this.getValue()) == false)
            return false;
        if (other.getMinimum() == null ^ this.getMinimum() == null)
            return false;
        if (other.getMinimum() != null && other.getMinimum().equals(this.getMinimum()) == false)
            return false;
        if (other.getMaximum() == null ^ this.getMaximum() == null)
            return false;
        if (other.getMaximum() != null && other.getMaximum().equals(this.getMaximum()) == false)
            return false;
        if (other.getValueList() == null ^ this.getValueList() == null)
            return false;
        if (other.getValueList() != null && other.getValueList().equals(this.getValueList()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getConstantType() == null) ? 0 : getConstantType().hashCode());
        hashCode = prime * hashCode + ((getValue() == null) ? 0 : getValue().hashCode());
        hashCode = prime * hashCode + ((getMinimum() == null) ? 0 : getMinimum().hashCode());
        hashCode = prime * hashCode + ((getMaximum() == null) ? 0 : getMaximum().hashCode());
        hashCode = prime * hashCode + ((getValueList() == null) ? 0 : getValueList().hashCode());
        return hashCode;
    }

    @Override
    public TopicConstantValue clone() {
        try {
            return (TopicConstantValue) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.quicksight.model.transform.TopicConstantValueMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
