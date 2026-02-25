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
 * The definition for the <code>FilterAggMetrics</code>.
 * </p>
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/quicksight-2018-04-01/FilterAggMetrics" target="_top">AWS API
 *      Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class FilterAggMetrics implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * The metric operand of the <code>FilterAggMetrics</code>.
     * </p>
     */
    private Identifier metricOperand;
    /**
     * <p>
     * The function for the <code>FilterAggMetrics</code>.
     * </p>
     */
    private String function;
    /**
     * <p>
     * The sort direction for <code>FilterAggMetrics</code>.
     * </p>
     */
    private String sortDirection;

    /**
     * <p>
     * The metric operand of the <code>FilterAggMetrics</code>.
     * </p>
     * 
     * @param metricOperand
     *        The metric operand of the <code>FilterAggMetrics</code>.
     */

    public void setMetricOperand(Identifier metricOperand) {
        this.metricOperand = metricOperand;
    }

    /**
     * <p>
     * The metric operand of the <code>FilterAggMetrics</code>.
     * </p>
     * 
     * @return The metric operand of the <code>FilterAggMetrics</code>.
     */

    public Identifier getMetricOperand() {
        return this.metricOperand;
    }

    /**
     * <p>
     * The metric operand of the <code>FilterAggMetrics</code>.
     * </p>
     * 
     * @param metricOperand
     *        The metric operand of the <code>FilterAggMetrics</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public FilterAggMetrics withMetricOperand(Identifier metricOperand) {
        setMetricOperand(metricOperand);
        return this;
    }

    /**
     * <p>
     * The function for the <code>FilterAggMetrics</code>.
     * </p>
     * 
     * @param function
     *        The function for the <code>FilterAggMetrics</code>.
     * @see AggType
     */

    public void setFunction(String function) {
        this.function = function;
    }

    /**
     * <p>
     * The function for the <code>FilterAggMetrics</code>.
     * </p>
     * 
     * @return The function for the <code>FilterAggMetrics</code>.
     * @see AggType
     */

    public String getFunction() {
        return this.function;
    }

    /**
     * <p>
     * The function for the <code>FilterAggMetrics</code>.
     * </p>
     * 
     * @param function
     *        The function for the <code>FilterAggMetrics</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see AggType
     */

    public FilterAggMetrics withFunction(String function) {
        setFunction(function);
        return this;
    }

    /**
     * <p>
     * The function for the <code>FilterAggMetrics</code>.
     * </p>
     * 
     * @param function
     *        The function for the <code>FilterAggMetrics</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see AggType
     */

    public FilterAggMetrics withFunction(AggType function) {
        this.function = function.toString();
        return this;
    }

    /**
     * <p>
     * The sort direction for <code>FilterAggMetrics</code>.
     * </p>
     * 
     * @param sortDirection
     *        The sort direction for <code>FilterAggMetrics</code>.
     * @see TopicSortDirection
     */

    public void setSortDirection(String sortDirection) {
        this.sortDirection = sortDirection;
    }

    /**
     * <p>
     * The sort direction for <code>FilterAggMetrics</code>.
     * </p>
     * 
     * @return The sort direction for <code>FilterAggMetrics</code>.
     * @see TopicSortDirection
     */

    public String getSortDirection() {
        return this.sortDirection;
    }

    /**
     * <p>
     * The sort direction for <code>FilterAggMetrics</code>.
     * </p>
     * 
     * @param sortDirection
     *        The sort direction for <code>FilterAggMetrics</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see TopicSortDirection
     */

    public FilterAggMetrics withSortDirection(String sortDirection) {
        setSortDirection(sortDirection);
        return this;
    }

    /**
     * <p>
     * The sort direction for <code>FilterAggMetrics</code>.
     * </p>
     * 
     * @param sortDirection
     *        The sort direction for <code>FilterAggMetrics</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see TopicSortDirection
     */

    public FilterAggMetrics withSortDirection(TopicSortDirection sortDirection) {
        this.sortDirection = sortDirection.toString();
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
        if (getMetricOperand() != null)
            sb.append("MetricOperand: ").append(getMetricOperand()).append(",");
        if (getFunction() != null)
            sb.append("Function: ").append(getFunction()).append(",");
        if (getSortDirection() != null)
            sb.append("SortDirection: ").append(getSortDirection());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof FilterAggMetrics == false)
            return false;
        FilterAggMetrics other = (FilterAggMetrics) obj;
        if (other.getMetricOperand() == null ^ this.getMetricOperand() == null)
            return false;
        if (other.getMetricOperand() != null && other.getMetricOperand().equals(this.getMetricOperand()) == false)
            return false;
        if (other.getFunction() == null ^ this.getFunction() == null)
            return false;
        if (other.getFunction() != null && other.getFunction().equals(this.getFunction()) == false)
            return false;
        if (other.getSortDirection() == null ^ this.getSortDirection() == null)
            return false;
        if (other.getSortDirection() != null && other.getSortDirection().equals(this.getSortDirection()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getMetricOperand() == null) ? 0 : getMetricOperand().hashCode());
        hashCode = prime * hashCode + ((getFunction() == null) ? 0 : getFunction().hashCode());
        hashCode = prime * hashCode + ((getSortDirection() == null) ? 0 : getSortDirection().hashCode());
        return hashCode;
    }

    @Override
    public FilterAggMetrics clone() {
        try {
            return (FilterAggMetrics) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.quicksight.model.transform.FilterAggMetricsMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
