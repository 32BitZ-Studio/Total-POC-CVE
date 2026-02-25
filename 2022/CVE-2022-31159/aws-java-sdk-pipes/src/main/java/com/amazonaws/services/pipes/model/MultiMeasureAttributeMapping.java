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
package com.amazonaws.services.pipes.model;

import java.io.Serializable;
import javax.annotation.Generated;
import com.amazonaws.protocol.StructuredPojo;
import com.amazonaws.protocol.ProtocolMarshaller;

/**
 * <p>
 * A mapping of a source event data field to a measure in a Timestream for LiveAnalytics record.
 * </p>
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/pipes-2015-10-07/MultiMeasureAttributeMapping" target="_top">AWS
 *      API Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class MultiMeasureAttributeMapping implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * Dynamic path to the measurement attribute in the source event.
     * </p>
     */
    private String measureValue;
    /**
     * <p>
     * Data type of the measurement attribute in the source event.
     * </p>
     */
    private String measureValueType;
    /**
     * <p>
     * Target measure name to be used.
     * </p>
     */
    private String multiMeasureAttributeName;

    /**
     * <p>
     * Dynamic path to the measurement attribute in the source event.
     * </p>
     * 
     * @param measureValue
     *        Dynamic path to the measurement attribute in the source event.
     */

    public void setMeasureValue(String measureValue) {
        this.measureValue = measureValue;
    }

    /**
     * <p>
     * Dynamic path to the measurement attribute in the source event.
     * </p>
     * 
     * @return Dynamic path to the measurement attribute in the source event.
     */

    public String getMeasureValue() {
        return this.measureValue;
    }

    /**
     * <p>
     * Dynamic path to the measurement attribute in the source event.
     * </p>
     * 
     * @param measureValue
     *        Dynamic path to the measurement attribute in the source event.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public MultiMeasureAttributeMapping withMeasureValue(String measureValue) {
        setMeasureValue(measureValue);
        return this;
    }

    /**
     * <p>
     * Data type of the measurement attribute in the source event.
     * </p>
     * 
     * @param measureValueType
     *        Data type of the measurement attribute in the source event.
     * @see MeasureValueType
     */

    public void setMeasureValueType(String measureValueType) {
        this.measureValueType = measureValueType;
    }

    /**
     * <p>
     * Data type of the measurement attribute in the source event.
     * </p>
     * 
     * @return Data type of the measurement attribute in the source event.
     * @see MeasureValueType
     */

    public String getMeasureValueType() {
        return this.measureValueType;
    }

    /**
     * <p>
     * Data type of the measurement attribute in the source event.
     * </p>
     * 
     * @param measureValueType
     *        Data type of the measurement attribute in the source event.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see MeasureValueType
     */

    public MultiMeasureAttributeMapping withMeasureValueType(String measureValueType) {
        setMeasureValueType(measureValueType);
        return this;
    }

    /**
     * <p>
     * Data type of the measurement attribute in the source event.
     * </p>
     * 
     * @param measureValueType
     *        Data type of the measurement attribute in the source event.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see MeasureValueType
     */

    public MultiMeasureAttributeMapping withMeasureValueType(MeasureValueType measureValueType) {
        this.measureValueType = measureValueType.toString();
        return this;
    }

    /**
     * <p>
     * Target measure name to be used.
     * </p>
     * 
     * @param multiMeasureAttributeName
     *        Target measure name to be used.
     */

    public void setMultiMeasureAttributeName(String multiMeasureAttributeName) {
        this.multiMeasureAttributeName = multiMeasureAttributeName;
    }

    /**
     * <p>
     * Target measure name to be used.
     * </p>
     * 
     * @return Target measure name to be used.
     */

    public String getMultiMeasureAttributeName() {
        return this.multiMeasureAttributeName;
    }

    /**
     * <p>
     * Target measure name to be used.
     * </p>
     * 
     * @param multiMeasureAttributeName
     *        Target measure name to be used.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public MultiMeasureAttributeMapping withMultiMeasureAttributeName(String multiMeasureAttributeName) {
        setMultiMeasureAttributeName(multiMeasureAttributeName);
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
        if (getMeasureValue() != null)
            sb.append("MeasureValue: ").append(getMeasureValue()).append(",");
        if (getMeasureValueType() != null)
            sb.append("MeasureValueType: ").append(getMeasureValueType()).append(",");
        if (getMultiMeasureAttributeName() != null)
            sb.append("MultiMeasureAttributeName: ").append(getMultiMeasureAttributeName());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof MultiMeasureAttributeMapping == false)
            return false;
        MultiMeasureAttributeMapping other = (MultiMeasureAttributeMapping) obj;
        if (other.getMeasureValue() == null ^ this.getMeasureValue() == null)
            return false;
        if (other.getMeasureValue() != null && other.getMeasureValue().equals(this.getMeasureValue()) == false)
            return false;
        if (other.getMeasureValueType() == null ^ this.getMeasureValueType() == null)
            return false;
        if (other.getMeasureValueType() != null && other.getMeasureValueType().equals(this.getMeasureValueType()) == false)
            return false;
        if (other.getMultiMeasureAttributeName() == null ^ this.getMultiMeasureAttributeName() == null)
            return false;
        if (other.getMultiMeasureAttributeName() != null && other.getMultiMeasureAttributeName().equals(this.getMultiMeasureAttributeName()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getMeasureValue() == null) ? 0 : getMeasureValue().hashCode());
        hashCode = prime * hashCode + ((getMeasureValueType() == null) ? 0 : getMeasureValueType().hashCode());
        hashCode = prime * hashCode + ((getMultiMeasureAttributeName() == null) ? 0 : getMultiMeasureAttributeName().hashCode());
        return hashCode;
    }

    @Override
    public MultiMeasureAttributeMapping clone() {
        try {
            return (MultiMeasureAttributeMapping) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.pipes.model.transform.MultiMeasureAttributeMappingMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
