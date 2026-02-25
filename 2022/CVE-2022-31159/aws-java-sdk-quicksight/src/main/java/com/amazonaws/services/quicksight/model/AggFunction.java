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
 * The definition of an Agg function.
 * </p>
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/quicksight-2018-04-01/AggFunction" target="_top">AWS API
 *      Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class AggFunction implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * The aggregation of an Agg function.
     * </p>
     */
    private String aggregation;
    /**
     * <p>
     * The aggregation parameters for an Agg function.
     * </p>
     */
    private java.util.Map<String, String> aggregationFunctionParameters;
    /**
     * <p>
     * The period of an Agg function.
     * </p>
     */
    private String period;
    /**
     * <p>
     * The period field for an Agg function.
     * </p>
     */
    private String periodField;

    /**
     * <p>
     * The aggregation of an Agg function.
     * </p>
     * 
     * @param aggregation
     *        The aggregation of an Agg function.
     * @see AggType
     */

    public void setAggregation(String aggregation) {
        this.aggregation = aggregation;
    }

    /**
     * <p>
     * The aggregation of an Agg function.
     * </p>
     * 
     * @return The aggregation of an Agg function.
     * @see AggType
     */

    public String getAggregation() {
        return this.aggregation;
    }

    /**
     * <p>
     * The aggregation of an Agg function.
     * </p>
     * 
     * @param aggregation
     *        The aggregation of an Agg function.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see AggType
     */

    public AggFunction withAggregation(String aggregation) {
        setAggregation(aggregation);
        return this;
    }

    /**
     * <p>
     * The aggregation of an Agg function.
     * </p>
     * 
     * @param aggregation
     *        The aggregation of an Agg function.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see AggType
     */

    public AggFunction withAggregation(AggType aggregation) {
        this.aggregation = aggregation.toString();
        return this;
    }

    /**
     * <p>
     * The aggregation parameters for an Agg function.
     * </p>
     * 
     * @return The aggregation parameters for an Agg function.
     */

    public java.util.Map<String, String> getAggregationFunctionParameters() {
        return aggregationFunctionParameters;
    }

    /**
     * <p>
     * The aggregation parameters for an Agg function.
     * </p>
     * 
     * @param aggregationFunctionParameters
     *        The aggregation parameters for an Agg function.
     */

    public void setAggregationFunctionParameters(java.util.Map<String, String> aggregationFunctionParameters) {
        this.aggregationFunctionParameters = aggregationFunctionParameters;
    }

    /**
     * <p>
     * The aggregation parameters for an Agg function.
     * </p>
     * 
     * @param aggregationFunctionParameters
     *        The aggregation parameters for an Agg function.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public AggFunction withAggregationFunctionParameters(java.util.Map<String, String> aggregationFunctionParameters) {
        setAggregationFunctionParameters(aggregationFunctionParameters);
        return this;
    }

    /**
     * Add a single AggregationFunctionParameters entry
     *
     * @see AggFunction#withAggregationFunctionParameters
     * @returns a reference to this object so that method calls can be chained together.
     */

    public AggFunction addAggregationFunctionParametersEntry(String key, String value) {
        if (null == this.aggregationFunctionParameters) {
            this.aggregationFunctionParameters = new java.util.HashMap<String, String>();
        }
        if (this.aggregationFunctionParameters.containsKey(key))
            throw new IllegalArgumentException("Duplicated keys (" + key.toString() + ") are provided.");
        this.aggregationFunctionParameters.put(key, value);
        return this;
    }

    /**
     * Removes all the entries added into AggregationFunctionParameters.
     *
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public AggFunction clearAggregationFunctionParametersEntries() {
        this.aggregationFunctionParameters = null;
        return this;
    }

    /**
     * <p>
     * The period of an Agg function.
     * </p>
     * 
     * @param period
     *        The period of an Agg function.
     * @see TopicTimeGranularity
     */

    public void setPeriod(String period) {
        this.period = period;
    }

    /**
     * <p>
     * The period of an Agg function.
     * </p>
     * 
     * @return The period of an Agg function.
     * @see TopicTimeGranularity
     */

    public String getPeriod() {
        return this.period;
    }

    /**
     * <p>
     * The period of an Agg function.
     * </p>
     * 
     * @param period
     *        The period of an Agg function.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see TopicTimeGranularity
     */

    public AggFunction withPeriod(String period) {
        setPeriod(period);
        return this;
    }

    /**
     * <p>
     * The period of an Agg function.
     * </p>
     * 
     * @param period
     *        The period of an Agg function.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see TopicTimeGranularity
     */

    public AggFunction withPeriod(TopicTimeGranularity period) {
        this.period = period.toString();
        return this;
    }

    /**
     * <p>
     * The period field for an Agg function.
     * </p>
     * 
     * @param periodField
     *        The period field for an Agg function.
     */

    public void setPeriodField(String periodField) {
        this.periodField = periodField;
    }

    /**
     * <p>
     * The period field for an Agg function.
     * </p>
     * 
     * @return The period field for an Agg function.
     */

    public String getPeriodField() {
        return this.periodField;
    }

    /**
     * <p>
     * The period field for an Agg function.
     * </p>
     * 
     * @param periodField
     *        The period field for an Agg function.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public AggFunction withPeriodField(String periodField) {
        setPeriodField(periodField);
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
        if (getAggregation() != null)
            sb.append("Aggregation: ").append(getAggregation()).append(",");
        if (getAggregationFunctionParameters() != null)
            sb.append("AggregationFunctionParameters: ").append(getAggregationFunctionParameters()).append(",");
        if (getPeriod() != null)
            sb.append("Period: ").append(getPeriod()).append(",");
        if (getPeriodField() != null)
            sb.append("PeriodField: ").append(getPeriodField());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof AggFunction == false)
            return false;
        AggFunction other = (AggFunction) obj;
        if (other.getAggregation() == null ^ this.getAggregation() == null)
            return false;
        if (other.getAggregation() != null && other.getAggregation().equals(this.getAggregation()) == false)
            return false;
        if (other.getAggregationFunctionParameters() == null ^ this.getAggregationFunctionParameters() == null)
            return false;
        if (other.getAggregationFunctionParameters() != null
                && other.getAggregationFunctionParameters().equals(this.getAggregationFunctionParameters()) == false)
            return false;
        if (other.getPeriod() == null ^ this.getPeriod() == null)
            return false;
        if (other.getPeriod() != null && other.getPeriod().equals(this.getPeriod()) == false)
            return false;
        if (other.getPeriodField() == null ^ this.getPeriodField() == null)
            return false;
        if (other.getPeriodField() != null && other.getPeriodField().equals(this.getPeriodField()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getAggregation() == null) ? 0 : getAggregation().hashCode());
        hashCode = prime * hashCode + ((getAggregationFunctionParameters() == null) ? 0 : getAggregationFunctionParameters().hashCode());
        hashCode = prime * hashCode + ((getPeriod() == null) ? 0 : getPeriod().hashCode());
        hashCode = prime * hashCode + ((getPeriodField() == null) ? 0 : getPeriodField().hashCode());
        return hashCode;
    }

    @Override
    public AggFunction clone() {
        try {
            return (AggFunction) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.quicksight.model.transform.AggFunctionMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
