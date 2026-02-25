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
 * Maps source data to a dimension in the target Timestream for LiveAnalytics table.
 * </p>
 * <p>
 * For more information, see <a href="https://docs.aws.amazon.com/timestream/latest/developerguide/concepts.html">Amazon
 * Timestream for LiveAnalytics concepts</a>
 * </p>
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/pipes-2015-10-07/DimensionMapping" target="_top">AWS API
 *      Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class DimensionMapping implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * Dynamic path to the dimension value in the source event.
     * </p>
     */
    private String dimensionValue;
    /**
     * <p>
     * The data type of the dimension for the time-series data.
     * </p>
     */
    private String dimensionValueType;
    /**
     * <p>
     * The metadata attributes of the time series. For example, the name and Availability Zone of an Amazon EC2 instance
     * or the name of the manufacturer of a wind turbine are dimensions.
     * </p>
     */
    private String dimensionName;

    /**
     * <p>
     * Dynamic path to the dimension value in the source event.
     * </p>
     * 
     * @param dimensionValue
     *        Dynamic path to the dimension value in the source event.
     */

    public void setDimensionValue(String dimensionValue) {
        this.dimensionValue = dimensionValue;
    }

    /**
     * <p>
     * Dynamic path to the dimension value in the source event.
     * </p>
     * 
     * @return Dynamic path to the dimension value in the source event.
     */

    public String getDimensionValue() {
        return this.dimensionValue;
    }

    /**
     * <p>
     * Dynamic path to the dimension value in the source event.
     * </p>
     * 
     * @param dimensionValue
     *        Dynamic path to the dimension value in the source event.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public DimensionMapping withDimensionValue(String dimensionValue) {
        setDimensionValue(dimensionValue);
        return this;
    }

    /**
     * <p>
     * The data type of the dimension for the time-series data.
     * </p>
     * 
     * @param dimensionValueType
     *        The data type of the dimension for the time-series data.
     * @see DimensionValueType
     */

    public void setDimensionValueType(String dimensionValueType) {
        this.dimensionValueType = dimensionValueType;
    }

    /**
     * <p>
     * The data type of the dimension for the time-series data.
     * </p>
     * 
     * @return The data type of the dimension for the time-series data.
     * @see DimensionValueType
     */

    public String getDimensionValueType() {
        return this.dimensionValueType;
    }

    /**
     * <p>
     * The data type of the dimension for the time-series data.
     * </p>
     * 
     * @param dimensionValueType
     *        The data type of the dimension for the time-series data.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see DimensionValueType
     */

    public DimensionMapping withDimensionValueType(String dimensionValueType) {
        setDimensionValueType(dimensionValueType);
        return this;
    }

    /**
     * <p>
     * The data type of the dimension for the time-series data.
     * </p>
     * 
     * @param dimensionValueType
     *        The data type of the dimension for the time-series data.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see DimensionValueType
     */

    public DimensionMapping withDimensionValueType(DimensionValueType dimensionValueType) {
        this.dimensionValueType = dimensionValueType.toString();
        return this;
    }

    /**
     * <p>
     * The metadata attributes of the time series. For example, the name and Availability Zone of an Amazon EC2 instance
     * or the name of the manufacturer of a wind turbine are dimensions.
     * </p>
     * 
     * @param dimensionName
     *        The metadata attributes of the time series. For example, the name and Availability Zone of an Amazon EC2
     *        instance or the name of the manufacturer of a wind turbine are dimensions.
     */

    public void setDimensionName(String dimensionName) {
        this.dimensionName = dimensionName;
    }

    /**
     * <p>
     * The metadata attributes of the time series. For example, the name and Availability Zone of an Amazon EC2 instance
     * or the name of the manufacturer of a wind turbine are dimensions.
     * </p>
     * 
     * @return The metadata attributes of the time series. For example, the name and Availability Zone of an Amazon EC2
     *         instance or the name of the manufacturer of a wind turbine are dimensions.
     */

    public String getDimensionName() {
        return this.dimensionName;
    }

    /**
     * <p>
     * The metadata attributes of the time series. For example, the name and Availability Zone of an Amazon EC2 instance
     * or the name of the manufacturer of a wind turbine are dimensions.
     * </p>
     * 
     * @param dimensionName
     *        The metadata attributes of the time series. For example, the name and Availability Zone of an Amazon EC2
     *        instance or the name of the manufacturer of a wind turbine are dimensions.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public DimensionMapping withDimensionName(String dimensionName) {
        setDimensionName(dimensionName);
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
        if (getDimensionValue() != null)
            sb.append("DimensionValue: ").append(getDimensionValue()).append(",");
        if (getDimensionValueType() != null)
            sb.append("DimensionValueType: ").append(getDimensionValueType()).append(",");
        if (getDimensionName() != null)
            sb.append("DimensionName: ").append(getDimensionName());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof DimensionMapping == false)
            return false;
        DimensionMapping other = (DimensionMapping) obj;
        if (other.getDimensionValue() == null ^ this.getDimensionValue() == null)
            return false;
        if (other.getDimensionValue() != null && other.getDimensionValue().equals(this.getDimensionValue()) == false)
            return false;
        if (other.getDimensionValueType() == null ^ this.getDimensionValueType() == null)
            return false;
        if (other.getDimensionValueType() != null && other.getDimensionValueType().equals(this.getDimensionValueType()) == false)
            return false;
        if (other.getDimensionName() == null ^ this.getDimensionName() == null)
            return false;
        if (other.getDimensionName() != null && other.getDimensionName().equals(this.getDimensionName()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getDimensionValue() == null) ? 0 : getDimensionValue().hashCode());
        hashCode = prime * hashCode + ((getDimensionValueType() == null) ? 0 : getDimensionValueType().hashCode());
        hashCode = prime * hashCode + ((getDimensionName() == null) ? 0 : getDimensionName().hashCode());
        return hashCode;
    }

    @Override
    public DimensionMapping clone() {
        try {
            return (DimensionMapping) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.pipes.model.transform.DimensionMappingMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
