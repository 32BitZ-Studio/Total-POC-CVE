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
 * The definition for a <code>CollectiveConstantEntry</code>.
 * </p>
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/quicksight-2018-04-01/CollectiveConstantEntry" target="_top">AWS
 *      API Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class CollectiveConstantEntry implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * The <code>ConstantType</code> of a <code>CollectiveConstantEntry</code>.
     * </p>
     */
    private String constantType;
    /**
     * <p>
     * The value of a <code>CollectiveConstantEntry</code>.
     * </p>
     */
    private String value;

    /**
     * <p>
     * The <code>ConstantType</code> of a <code>CollectiveConstantEntry</code>.
     * </p>
     * 
     * @param constantType
     *        The <code>ConstantType</code> of a <code>CollectiveConstantEntry</code>.
     * @see ConstantType
     */

    public void setConstantType(String constantType) {
        this.constantType = constantType;
    }

    /**
     * <p>
     * The <code>ConstantType</code> of a <code>CollectiveConstantEntry</code>.
     * </p>
     * 
     * @return The <code>ConstantType</code> of a <code>CollectiveConstantEntry</code>.
     * @see ConstantType
     */

    public String getConstantType() {
        return this.constantType;
    }

    /**
     * <p>
     * The <code>ConstantType</code> of a <code>CollectiveConstantEntry</code>.
     * </p>
     * 
     * @param constantType
     *        The <code>ConstantType</code> of a <code>CollectiveConstantEntry</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see ConstantType
     */

    public CollectiveConstantEntry withConstantType(String constantType) {
        setConstantType(constantType);
        return this;
    }

    /**
     * <p>
     * The <code>ConstantType</code> of a <code>CollectiveConstantEntry</code>.
     * </p>
     * 
     * @param constantType
     *        The <code>ConstantType</code> of a <code>CollectiveConstantEntry</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see ConstantType
     */

    public CollectiveConstantEntry withConstantType(ConstantType constantType) {
        this.constantType = constantType.toString();
        return this;
    }

    /**
     * <p>
     * The value of a <code>CollectiveConstantEntry</code>.
     * </p>
     * 
     * @param value
     *        The value of a <code>CollectiveConstantEntry</code>.
     */

    public void setValue(String value) {
        this.value = value;
    }

    /**
     * <p>
     * The value of a <code>CollectiveConstantEntry</code>.
     * </p>
     * 
     * @return The value of a <code>CollectiveConstantEntry</code>.
     */

    public String getValue() {
        return this.value;
    }

    /**
     * <p>
     * The value of a <code>CollectiveConstantEntry</code>.
     * </p>
     * 
     * @param value
     *        The value of a <code>CollectiveConstantEntry</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public CollectiveConstantEntry withValue(String value) {
        setValue(value);
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
            sb.append("Value: ").append(getValue());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof CollectiveConstantEntry == false)
            return false;
        CollectiveConstantEntry other = (CollectiveConstantEntry) obj;
        if (other.getConstantType() == null ^ this.getConstantType() == null)
            return false;
        if (other.getConstantType() != null && other.getConstantType().equals(this.getConstantType()) == false)
            return false;
        if (other.getValue() == null ^ this.getValue() == null)
            return false;
        if (other.getValue() != null && other.getValue().equals(this.getValue()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getConstantType() == null) ? 0 : getConstantType().hashCode());
        hashCode = prime * hashCode + ((getValue() == null) ? 0 : getValue().hashCode());
        return hashCode;
    }

    @Override
    public CollectiveConstantEntry clone() {
        try {
            return (CollectiveConstantEntry) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.quicksight.model.transform.CollectiveConstantEntryMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
