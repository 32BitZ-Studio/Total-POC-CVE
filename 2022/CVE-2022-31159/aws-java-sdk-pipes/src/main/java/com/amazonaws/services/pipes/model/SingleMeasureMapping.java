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
 * Maps a single source data field to a single record in the specified Timestream for LiveAnalytics table.
 * </p>
 * <p>
 * For more information, see <a href="https://docs.aws.amazon.com/timestream/latest/developerguide/concepts.html">Amazon
 * Timestream for LiveAnalytics concepts</a>
 * </p>
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/pipes-2015-10-07/SingleMeasureMapping" target="_top">AWS API
 *      Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class SingleMeasureMapping implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * Dynamic path of the source field to map to the measure in the record.
     * </p>
     */
    private String measureValue;
    /**
     * <p>
     * Data type of the source field.
     * </p>
     */
    private String measureValueType;
    /**
     * <p>
     * Target measure name for the measurement attribute in the Timestream table.
     * </p>
     */
    private String measureName;

    /**
     * <p>
     * Dynamic path of the source field to map to the measure in the record.
     * </p>
     * 
     * @param measureValue
     *        Dynamic path of the source field to map to the measure in the record.
     */

    public void setMeasureValue(String measureValue) {
        this.measureValue = measureValue;
    }

    /**
     * <p>
     * Dynamic path of the source field to map to the measure in the record.
     * </p>
     * 
     * @return Dynamic path of the source field to map to the measure in the record.
     */

    public String getMeasureValue() {
        return this.measureValue;
    }

    /**
     * <p>
     * Dynamic path of the source field to map to the measure in the record.
     * </p>
     * 
     * @param measureValue
     *        Dynamic path of the source field to map to the measure in the record.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public SingleMeasureMapping withMeasureValue(String measureValue) {
        setMeasureValue(measureValue);
        return this;
    }

    /**
     * <p>
     * Data type of the source field.
     * </p>
     * 
     * @param measureValueType
     *        Data type of the source field.
     * @see MeasureValueType
     */

    public void setMeasureValueType(String measureValueType) {
        this.measureValueType = measureValueType;
    }

    /**
     * <p>
     * Data type of the source field.
     * </p>
     * 
     * @return Data type of the source field.
     * @see MeasureValueType
     */

    public String getMeasureValueType() {
        return this.measureValueType;
    }

    /**
     * <p>
     * Data type of the source field.
     * </p>
     * 
     * @param measureValueType
     *        Data type of the source field.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see MeasureValueType
     */

    public SingleMeasureMapping withMeasureValueType(String measureValueType) {
        setMeasureValueType(measureValueType);
        return this;
    }

    /**
     * <p>
     * Data type of the source field.
     * </p>
     * 
     * @param measureValueType
     *        Data type of the source field.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see MeasureValueType
     */

    public SingleMeasureMapping withMeasureValueType(MeasureValueType measureValueType) {
        this.measureValueType = measureValueType.toString();
        return this;
    }

    /**
     * <p>
     * Target measure name for the measurement attribute in the Timestream table.
     * </p>
     * 
     * @param measureName
     *        Target measure name for the measurement attribute in the Timestream table.
     */

    public void setMeasureName(String measureName) {
        this.measureName = measureName;
    }

    /**
     * <p>
     * Target measure name for the measurement attribute in the Timestream table.
     * </p>
     * 
     * @return Target measure name for the measurement attribute in the Timestream table.
     */

    public String getMeasureName() {
        return this.measureName;
    }

    /**
     * <p>
     * Target measure name for the measurement attribute in the Timestream table.
     * </p>
     * 
     * @param measureName
     *        Target measure name for the measurement attribute in the Timestream table.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public SingleMeasureMapping withMeasureName(String measureName) {
        setMeasureName(measureName);
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
        if (getMeasureName() != null)
            sb.append("MeasureName: ").append(getMeasureName());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof SingleMeasureMapping == false)
            return false;
        SingleMeasureMapping other = (SingleMeasureMapping) obj;
        if (other.getMeasureValue() == null ^ this.getMeasureValue() == null)
            return false;
        if (other.getMeasureValue() != null && other.getMeasureValue().equals(this.getMeasureValue()) == false)
            return false;
        if (other.getMeasureValueType() == null ^ this.getMeasureValueType() == null)
            return false;
        if (other.getMeasureValueType() != null && other.getMeasureValueType().equals(this.getMeasureValueType()) == false)
            return false;
        if (other.getMeasureName() == null ^ this.getMeasureName() == null)
            return false;
        if (other.getMeasureName() != null && other.getMeasureName().equals(this.getMeasureName()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getMeasureValue() == null) ? 0 : getMeasureValue().hashCode());
        hashCode = prime * hashCode + ((getMeasureValueType() == null) ? 0 : getMeasureValueType().hashCode());
        hashCode = prime * hashCode + ((getMeasureName() == null) ? 0 : getMeasureName().hashCode());
        return hashCode;
    }

    @Override
    public SingleMeasureMapping clone() {
        try {
            return (SingleMeasureMapping) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.pipes.model.transform.SingleMeasureMappingMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
