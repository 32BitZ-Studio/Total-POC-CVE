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
 * The definition of an <code>AggregationPartitionBy</code>.
 * </p>
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/quicksight-2018-04-01/AggregationPartitionBy" target="_top">AWS
 *      API Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class AggregationPartitionBy implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * The field Name for an <code>AggregationPartitionBy</code>.
     * </p>
     */
    private String fieldName;
    /**
     * <p>
     * The <code>TimeGranularity</code> for an <code>AggregationPartitionBy</code>.
     * </p>
     */
    private String timeGranularity;

    /**
     * <p>
     * The field Name for an <code>AggregationPartitionBy</code>.
     * </p>
     * 
     * @param fieldName
     *        The field Name for an <code>AggregationPartitionBy</code>.
     */

    public void setFieldName(String fieldName) {
        this.fieldName = fieldName;
    }

    /**
     * <p>
     * The field Name for an <code>AggregationPartitionBy</code>.
     * </p>
     * 
     * @return The field Name for an <code>AggregationPartitionBy</code>.
     */

    public String getFieldName() {
        return this.fieldName;
    }

    /**
     * <p>
     * The field Name for an <code>AggregationPartitionBy</code>.
     * </p>
     * 
     * @param fieldName
     *        The field Name for an <code>AggregationPartitionBy</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public AggregationPartitionBy withFieldName(String fieldName) {
        setFieldName(fieldName);
        return this;
    }

    /**
     * <p>
     * The <code>TimeGranularity</code> for an <code>AggregationPartitionBy</code>.
     * </p>
     * 
     * @param timeGranularity
     *        The <code>TimeGranularity</code> for an <code>AggregationPartitionBy</code>.
     * @see TimeGranularity
     */

    public void setTimeGranularity(String timeGranularity) {
        this.timeGranularity = timeGranularity;
    }

    /**
     * <p>
     * The <code>TimeGranularity</code> for an <code>AggregationPartitionBy</code>.
     * </p>
     * 
     * @return The <code>TimeGranularity</code> for an <code>AggregationPartitionBy</code>.
     * @see TimeGranularity
     */

    public String getTimeGranularity() {
        return this.timeGranularity;
    }

    /**
     * <p>
     * The <code>TimeGranularity</code> for an <code>AggregationPartitionBy</code>.
     * </p>
     * 
     * @param timeGranularity
     *        The <code>TimeGranularity</code> for an <code>AggregationPartitionBy</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see TimeGranularity
     */

    public AggregationPartitionBy withTimeGranularity(String timeGranularity) {
        setTimeGranularity(timeGranularity);
        return this;
    }

    /**
     * <p>
     * The <code>TimeGranularity</code> for an <code>AggregationPartitionBy</code>.
     * </p>
     * 
     * @param timeGranularity
     *        The <code>TimeGranularity</code> for an <code>AggregationPartitionBy</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see TimeGranularity
     */

    public AggregationPartitionBy withTimeGranularity(TimeGranularity timeGranularity) {
        this.timeGranularity = timeGranularity.toString();
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
        if (getFieldName() != null)
            sb.append("FieldName: ").append(getFieldName()).append(",");
        if (getTimeGranularity() != null)
            sb.append("TimeGranularity: ").append(getTimeGranularity());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof AggregationPartitionBy == false)
            return false;
        AggregationPartitionBy other = (AggregationPartitionBy) obj;
        if (other.getFieldName() == null ^ this.getFieldName() == null)
            return false;
        if (other.getFieldName() != null && other.getFieldName().equals(this.getFieldName()) == false)
            return false;
        if (other.getTimeGranularity() == null ^ this.getTimeGranularity() == null)
            return false;
        if (other.getTimeGranularity() != null && other.getTimeGranularity().equals(this.getTimeGranularity()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getFieldName() == null) ? 0 : getFieldName().hashCode());
        hashCode = prime * hashCode + ((getTimeGranularity() == null) ? 0 : getTimeGranularity().hashCode());
        return hashCode;
    }

    @Override
    public AggregationPartitionBy clone() {
        try {
            return (AggregationPartitionBy) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.quicksight.model.transform.AggregationPartitionByMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
