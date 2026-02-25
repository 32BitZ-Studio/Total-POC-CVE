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
 * The definition for a <code>TopicIRFilterOption</code>.
 * </p>
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/quicksight-2018-04-01/TopicIRFilterOption" target="_top">AWS API
 *      Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class TopicIRFilterOption implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * The filter type for the <code>TopicIRFilterOption</code>.
     * </p>
     */
    private String filterType;
    /**
     * <p>
     * The filter class for the <code>TopicIRFilterOption</code>.
     * </p>
     */
    private String filterClass;
    /**
     * <p>
     * The operand field for the <code>TopicIRFilterOption</code>.
     * </p>
     */
    private Identifier operandField;
    /**
     * <p>
     * The function for the <code>TopicIRFilterOption</code>.
     * </p>
     */
    private String function;
    /**
     * <p>
     * The constant for the <code>TopicIRFilterOption</code>.
     * </p>
     */
    private TopicConstantValue constant;
    /**
     * <p>
     * The inverse for the <code>TopicIRFilterOption</code>.
     * </p>
     */
    private Boolean inverse;
    /**
     * <p>
     * The null filter for the <code>TopicIRFilterOption</code>.
     * </p>
     */
    private String nullFilter;
    /**
     * <p>
     * The aggregation for the <code>TopicIRFilterOption</code>.
     * </p>
     */
    private String aggregation;
    /**
     * <p>
     * The aggregation function parameters for the <code>TopicIRFilterOption</code>.
     * </p>
     */
    private java.util.Map<String, String> aggregationFunctionParameters;
    /**
     * <p>
     * The <code>AggregationPartitionBy</code> for the <code>TopicIRFilterOption</code>.
     * </p>
     */
    private java.util.List<AggregationPartitionBy> aggregationPartitionBy;
    /**
     * <p>
     * The range for the <code>TopicIRFilterOption</code>.
     * </p>
     */
    private TopicConstantValue range;
    /**
     * <p>
     * The inclusive for the <code>TopicIRFilterOption</code>.
     * </p>
     */
    private Boolean inclusive;
    /**
     * <p>
     * The time granularity for the <code>TopicIRFilterOption</code>.
     * </p>
     */
    private String timeGranularity;
    /**
     * <p>
     * The last next offset for the <code>TopicIRFilterOption</code>.
     * </p>
     */
    private TopicConstantValue lastNextOffset;
    /**
     * <p>
     * The agg metrics for the <code>TopicIRFilterOption</code>.
     * </p>
     */
    private java.util.List<FilterAggMetrics> aggMetrics;
    /**
     * <p>
     * The <code>TopBottomLimit</code> for the <code>TopicIRFilterOption</code>.
     * </p>
     */
    private TopicConstantValue topBottomLimit;
    /**
     * <p>
     * The sort direction for the <code>TopicIRFilterOption</code>.
     * </p>
     */
    private String sortDirection;
    /**
     * <p>
     * The anchor for the <code>TopicIRFilterOption</code>.
     * </p>
     */
    private Anchor anchor;

    /**
     * <p>
     * The filter type for the <code>TopicIRFilterOption</code>.
     * </p>
     * 
     * @param filterType
     *        The filter type for the <code>TopicIRFilterOption</code>.
     * @see TopicIRFilterType
     */

    public void setFilterType(String filterType) {
        this.filterType = filterType;
    }

    /**
     * <p>
     * The filter type for the <code>TopicIRFilterOption</code>.
     * </p>
     * 
     * @return The filter type for the <code>TopicIRFilterOption</code>.
     * @see TopicIRFilterType
     */

    public String getFilterType() {
        return this.filterType;
    }

    /**
     * <p>
     * The filter type for the <code>TopicIRFilterOption</code>.
     * </p>
     * 
     * @param filterType
     *        The filter type for the <code>TopicIRFilterOption</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see TopicIRFilterType
     */

    public TopicIRFilterOption withFilterType(String filterType) {
        setFilterType(filterType);
        return this;
    }

    /**
     * <p>
     * The filter type for the <code>TopicIRFilterOption</code>.
     * </p>
     * 
     * @param filterType
     *        The filter type for the <code>TopicIRFilterOption</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see TopicIRFilterType
     */

    public TopicIRFilterOption withFilterType(TopicIRFilterType filterType) {
        this.filterType = filterType.toString();
        return this;
    }

    /**
     * <p>
     * The filter class for the <code>TopicIRFilterOption</code>.
     * </p>
     * 
     * @param filterClass
     *        The filter class for the <code>TopicIRFilterOption</code>.
     * @see FilterClass
     */

    public void setFilterClass(String filterClass) {
        this.filterClass = filterClass;
    }

    /**
     * <p>
     * The filter class for the <code>TopicIRFilterOption</code>.
     * </p>
     * 
     * @return The filter class for the <code>TopicIRFilterOption</code>.
     * @see FilterClass
     */

    public String getFilterClass() {
        return this.filterClass;
    }

    /**
     * <p>
     * The filter class for the <code>TopicIRFilterOption</code>.
     * </p>
     * 
     * @param filterClass
     *        The filter class for the <code>TopicIRFilterOption</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see FilterClass
     */

    public TopicIRFilterOption withFilterClass(String filterClass) {
        setFilterClass(filterClass);
        return this;
    }

    /**
     * <p>
     * The filter class for the <code>TopicIRFilterOption</code>.
     * </p>
     * 
     * @param filterClass
     *        The filter class for the <code>TopicIRFilterOption</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see FilterClass
     */

    public TopicIRFilterOption withFilterClass(FilterClass filterClass) {
        this.filterClass = filterClass.toString();
        return this;
    }

    /**
     * <p>
     * The operand field for the <code>TopicIRFilterOption</code>.
     * </p>
     * 
     * @param operandField
     *        The operand field for the <code>TopicIRFilterOption</code>.
     */

    public void setOperandField(Identifier operandField) {
        this.operandField = operandField;
    }

    /**
     * <p>
     * The operand field for the <code>TopicIRFilterOption</code>.
     * </p>
     * 
     * @return The operand field for the <code>TopicIRFilterOption</code>.
     */

    public Identifier getOperandField() {
        return this.operandField;
    }

    /**
     * <p>
     * The operand field for the <code>TopicIRFilterOption</code>.
     * </p>
     * 
     * @param operandField
     *        The operand field for the <code>TopicIRFilterOption</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public TopicIRFilterOption withOperandField(Identifier operandField) {
        setOperandField(operandField);
        return this;
    }

    /**
     * <p>
     * The function for the <code>TopicIRFilterOption</code>.
     * </p>
     * 
     * @param function
     *        The function for the <code>TopicIRFilterOption</code>.
     * @see TopicIRFilterFunction
     */

    public void setFunction(String function) {
        this.function = function;
    }

    /**
     * <p>
     * The function for the <code>TopicIRFilterOption</code>.
     * </p>
     * 
     * @return The function for the <code>TopicIRFilterOption</code>.
     * @see TopicIRFilterFunction
     */

    public String getFunction() {
        return this.function;
    }

    /**
     * <p>
     * The function for the <code>TopicIRFilterOption</code>.
     * </p>
     * 
     * @param function
     *        The function for the <code>TopicIRFilterOption</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see TopicIRFilterFunction
     */

    public TopicIRFilterOption withFunction(String function) {
        setFunction(function);
        return this;
    }

    /**
     * <p>
     * The function for the <code>TopicIRFilterOption</code>.
     * </p>
     * 
     * @param function
     *        The function for the <code>TopicIRFilterOption</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see TopicIRFilterFunction
     */

    public TopicIRFilterOption withFunction(TopicIRFilterFunction function) {
        this.function = function.toString();
        return this;
    }

    /**
     * <p>
     * The constant for the <code>TopicIRFilterOption</code>.
     * </p>
     * 
     * @param constant
     *        The constant for the <code>TopicIRFilterOption</code>.
     */

    public void setConstant(TopicConstantValue constant) {
        this.constant = constant;
    }

    /**
     * <p>
     * The constant for the <code>TopicIRFilterOption</code>.
     * </p>
     * 
     * @return The constant for the <code>TopicIRFilterOption</code>.
     */

    public TopicConstantValue getConstant() {
        return this.constant;
    }

    /**
     * <p>
     * The constant for the <code>TopicIRFilterOption</code>.
     * </p>
     * 
     * @param constant
     *        The constant for the <code>TopicIRFilterOption</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public TopicIRFilterOption withConstant(TopicConstantValue constant) {
        setConstant(constant);
        return this;
    }

    /**
     * <p>
     * The inverse for the <code>TopicIRFilterOption</code>.
     * </p>
     * 
     * @param inverse
     *        The inverse for the <code>TopicIRFilterOption</code>.
     */

    public void setInverse(Boolean inverse) {
        this.inverse = inverse;
    }

    /**
     * <p>
     * The inverse for the <code>TopicIRFilterOption</code>.
     * </p>
     * 
     * @return The inverse for the <code>TopicIRFilterOption</code>.
     */

    public Boolean getInverse() {
        return this.inverse;
    }

    /**
     * <p>
     * The inverse for the <code>TopicIRFilterOption</code>.
     * </p>
     * 
     * @param inverse
     *        The inverse for the <code>TopicIRFilterOption</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public TopicIRFilterOption withInverse(Boolean inverse) {
        setInverse(inverse);
        return this;
    }

    /**
     * <p>
     * The inverse for the <code>TopicIRFilterOption</code>.
     * </p>
     * 
     * @return The inverse for the <code>TopicIRFilterOption</code>.
     */

    public Boolean isInverse() {
        return this.inverse;
    }

    /**
     * <p>
     * The null filter for the <code>TopicIRFilterOption</code>.
     * </p>
     * 
     * @param nullFilter
     *        The null filter for the <code>TopicIRFilterOption</code>.
     * @see NullFilterOption
     */

    public void setNullFilter(String nullFilter) {
        this.nullFilter = nullFilter;
    }

    /**
     * <p>
     * The null filter for the <code>TopicIRFilterOption</code>.
     * </p>
     * 
     * @return The null filter for the <code>TopicIRFilterOption</code>.
     * @see NullFilterOption
     */

    public String getNullFilter() {
        return this.nullFilter;
    }

    /**
     * <p>
     * The null filter for the <code>TopicIRFilterOption</code>.
     * </p>
     * 
     * @param nullFilter
     *        The null filter for the <code>TopicIRFilterOption</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see NullFilterOption
     */

    public TopicIRFilterOption withNullFilter(String nullFilter) {
        setNullFilter(nullFilter);
        return this;
    }

    /**
     * <p>
     * The null filter for the <code>TopicIRFilterOption</code>.
     * </p>
     * 
     * @param nullFilter
     *        The null filter for the <code>TopicIRFilterOption</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see NullFilterOption
     */

    public TopicIRFilterOption withNullFilter(NullFilterOption nullFilter) {
        this.nullFilter = nullFilter.toString();
        return this;
    }

    /**
     * <p>
     * The aggregation for the <code>TopicIRFilterOption</code>.
     * </p>
     * 
     * @param aggregation
     *        The aggregation for the <code>TopicIRFilterOption</code>.
     * @see AggType
     */

    public void setAggregation(String aggregation) {
        this.aggregation = aggregation;
    }

    /**
     * <p>
     * The aggregation for the <code>TopicIRFilterOption</code>.
     * </p>
     * 
     * @return The aggregation for the <code>TopicIRFilterOption</code>.
     * @see AggType
     */

    public String getAggregation() {
        return this.aggregation;
    }

    /**
     * <p>
     * The aggregation for the <code>TopicIRFilterOption</code>.
     * </p>
     * 
     * @param aggregation
     *        The aggregation for the <code>TopicIRFilterOption</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see AggType
     */

    public TopicIRFilterOption withAggregation(String aggregation) {
        setAggregation(aggregation);
        return this;
    }

    /**
     * <p>
     * The aggregation for the <code>TopicIRFilterOption</code>.
     * </p>
     * 
     * @param aggregation
     *        The aggregation for the <code>TopicIRFilterOption</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see AggType
     */

    public TopicIRFilterOption withAggregation(AggType aggregation) {
        this.aggregation = aggregation.toString();
        return this;
    }

    /**
     * <p>
     * The aggregation function parameters for the <code>TopicIRFilterOption</code>.
     * </p>
     * 
     * @return The aggregation function parameters for the <code>TopicIRFilterOption</code>.
     */

    public java.util.Map<String, String> getAggregationFunctionParameters() {
        return aggregationFunctionParameters;
    }

    /**
     * <p>
     * The aggregation function parameters for the <code>TopicIRFilterOption</code>.
     * </p>
     * 
     * @param aggregationFunctionParameters
     *        The aggregation function parameters for the <code>TopicIRFilterOption</code>.
     */

    public void setAggregationFunctionParameters(java.util.Map<String, String> aggregationFunctionParameters) {
        this.aggregationFunctionParameters = aggregationFunctionParameters;
    }

    /**
     * <p>
     * The aggregation function parameters for the <code>TopicIRFilterOption</code>.
     * </p>
     * 
     * @param aggregationFunctionParameters
     *        The aggregation function parameters for the <code>TopicIRFilterOption</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public TopicIRFilterOption withAggregationFunctionParameters(java.util.Map<String, String> aggregationFunctionParameters) {
        setAggregationFunctionParameters(aggregationFunctionParameters);
        return this;
    }

    /**
     * Add a single AggregationFunctionParameters entry
     *
     * @see TopicIRFilterOption#withAggregationFunctionParameters
     * @returns a reference to this object so that method calls can be chained together.
     */

    public TopicIRFilterOption addAggregationFunctionParametersEntry(String key, String value) {
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

    public TopicIRFilterOption clearAggregationFunctionParametersEntries() {
        this.aggregationFunctionParameters = null;
        return this;
    }

    /**
     * <p>
     * The <code>AggregationPartitionBy</code> for the <code>TopicIRFilterOption</code>.
     * </p>
     * 
     * @return The <code>AggregationPartitionBy</code> for the <code>TopicIRFilterOption</code>.
     */

    public java.util.List<AggregationPartitionBy> getAggregationPartitionBy() {
        return aggregationPartitionBy;
    }

    /**
     * <p>
     * The <code>AggregationPartitionBy</code> for the <code>TopicIRFilterOption</code>.
     * </p>
     * 
     * @param aggregationPartitionBy
     *        The <code>AggregationPartitionBy</code> for the <code>TopicIRFilterOption</code>.
     */

    public void setAggregationPartitionBy(java.util.Collection<AggregationPartitionBy> aggregationPartitionBy) {
        if (aggregationPartitionBy == null) {
            this.aggregationPartitionBy = null;
            return;
        }

        this.aggregationPartitionBy = new java.util.ArrayList<AggregationPartitionBy>(aggregationPartitionBy);
    }

    /**
     * <p>
     * The <code>AggregationPartitionBy</code> for the <code>TopicIRFilterOption</code>.
     * </p>
     * <p>
     * <b>NOTE:</b> This method appends the values to the existing list (if any). Use
     * {@link #setAggregationPartitionBy(java.util.Collection)} or
     * {@link #withAggregationPartitionBy(java.util.Collection)} if you want to override the existing values.
     * </p>
     * 
     * @param aggregationPartitionBy
     *        The <code>AggregationPartitionBy</code> for the <code>TopicIRFilterOption</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public TopicIRFilterOption withAggregationPartitionBy(AggregationPartitionBy... aggregationPartitionBy) {
        if (this.aggregationPartitionBy == null) {
            setAggregationPartitionBy(new java.util.ArrayList<AggregationPartitionBy>(aggregationPartitionBy.length));
        }
        for (AggregationPartitionBy ele : aggregationPartitionBy) {
            this.aggregationPartitionBy.add(ele);
        }
        return this;
    }

    /**
     * <p>
     * The <code>AggregationPartitionBy</code> for the <code>TopicIRFilterOption</code>.
     * </p>
     * 
     * @param aggregationPartitionBy
     *        The <code>AggregationPartitionBy</code> for the <code>TopicIRFilterOption</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public TopicIRFilterOption withAggregationPartitionBy(java.util.Collection<AggregationPartitionBy> aggregationPartitionBy) {
        setAggregationPartitionBy(aggregationPartitionBy);
        return this;
    }

    /**
     * <p>
     * The range for the <code>TopicIRFilterOption</code>.
     * </p>
     * 
     * @param range
     *        The range for the <code>TopicIRFilterOption</code>.
     */

    public void setRange(TopicConstantValue range) {
        this.range = range;
    }

    /**
     * <p>
     * The range for the <code>TopicIRFilterOption</code>.
     * </p>
     * 
     * @return The range for the <code>TopicIRFilterOption</code>.
     */

    public TopicConstantValue getRange() {
        return this.range;
    }

    /**
     * <p>
     * The range for the <code>TopicIRFilterOption</code>.
     * </p>
     * 
     * @param range
     *        The range for the <code>TopicIRFilterOption</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public TopicIRFilterOption withRange(TopicConstantValue range) {
        setRange(range);
        return this;
    }

    /**
     * <p>
     * The inclusive for the <code>TopicIRFilterOption</code>.
     * </p>
     * 
     * @param inclusive
     *        The inclusive for the <code>TopicIRFilterOption</code>.
     */

    public void setInclusive(Boolean inclusive) {
        this.inclusive = inclusive;
    }

    /**
     * <p>
     * The inclusive for the <code>TopicIRFilterOption</code>.
     * </p>
     * 
     * @return The inclusive for the <code>TopicIRFilterOption</code>.
     */

    public Boolean getInclusive() {
        return this.inclusive;
    }

    /**
     * <p>
     * The inclusive for the <code>TopicIRFilterOption</code>.
     * </p>
     * 
     * @param inclusive
     *        The inclusive for the <code>TopicIRFilterOption</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public TopicIRFilterOption withInclusive(Boolean inclusive) {
        setInclusive(inclusive);
        return this;
    }

    /**
     * <p>
     * The inclusive for the <code>TopicIRFilterOption</code>.
     * </p>
     * 
     * @return The inclusive for the <code>TopicIRFilterOption</code>.
     */

    public Boolean isInclusive() {
        return this.inclusive;
    }

    /**
     * <p>
     * The time granularity for the <code>TopicIRFilterOption</code>.
     * </p>
     * 
     * @param timeGranularity
     *        The time granularity for the <code>TopicIRFilterOption</code>.
     * @see TimeGranularity
     */

    public void setTimeGranularity(String timeGranularity) {
        this.timeGranularity = timeGranularity;
    }

    /**
     * <p>
     * The time granularity for the <code>TopicIRFilterOption</code>.
     * </p>
     * 
     * @return The time granularity for the <code>TopicIRFilterOption</code>.
     * @see TimeGranularity
     */

    public String getTimeGranularity() {
        return this.timeGranularity;
    }

    /**
     * <p>
     * The time granularity for the <code>TopicIRFilterOption</code>.
     * </p>
     * 
     * @param timeGranularity
     *        The time granularity for the <code>TopicIRFilterOption</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see TimeGranularity
     */

    public TopicIRFilterOption withTimeGranularity(String timeGranularity) {
        setTimeGranularity(timeGranularity);
        return this;
    }

    /**
     * <p>
     * The time granularity for the <code>TopicIRFilterOption</code>.
     * </p>
     * 
     * @param timeGranularity
     *        The time granularity for the <code>TopicIRFilterOption</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see TimeGranularity
     */

    public TopicIRFilterOption withTimeGranularity(TimeGranularity timeGranularity) {
        this.timeGranularity = timeGranularity.toString();
        return this;
    }

    /**
     * <p>
     * The last next offset for the <code>TopicIRFilterOption</code>.
     * </p>
     * 
     * @param lastNextOffset
     *        The last next offset for the <code>TopicIRFilterOption</code>.
     */

    public void setLastNextOffset(TopicConstantValue lastNextOffset) {
        this.lastNextOffset = lastNextOffset;
    }

    /**
     * <p>
     * The last next offset for the <code>TopicIRFilterOption</code>.
     * </p>
     * 
     * @return The last next offset for the <code>TopicIRFilterOption</code>.
     */

    public TopicConstantValue getLastNextOffset() {
        return this.lastNextOffset;
    }

    /**
     * <p>
     * The last next offset for the <code>TopicIRFilterOption</code>.
     * </p>
     * 
     * @param lastNextOffset
     *        The last next offset for the <code>TopicIRFilterOption</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public TopicIRFilterOption withLastNextOffset(TopicConstantValue lastNextOffset) {
        setLastNextOffset(lastNextOffset);
        return this;
    }

    /**
     * <p>
     * The agg metrics for the <code>TopicIRFilterOption</code>.
     * </p>
     * 
     * @return The agg metrics for the <code>TopicIRFilterOption</code>.
     */

    public java.util.List<FilterAggMetrics> getAggMetrics() {
        return aggMetrics;
    }

    /**
     * <p>
     * The agg metrics for the <code>TopicIRFilterOption</code>.
     * </p>
     * 
     * @param aggMetrics
     *        The agg metrics for the <code>TopicIRFilterOption</code>.
     */

    public void setAggMetrics(java.util.Collection<FilterAggMetrics> aggMetrics) {
        if (aggMetrics == null) {
            this.aggMetrics = null;
            return;
        }

        this.aggMetrics = new java.util.ArrayList<FilterAggMetrics>(aggMetrics);
    }

    /**
     * <p>
     * The agg metrics for the <code>TopicIRFilterOption</code>.
     * </p>
     * <p>
     * <b>NOTE:</b> This method appends the values to the existing list (if any). Use
     * {@link #setAggMetrics(java.util.Collection)} or {@link #withAggMetrics(java.util.Collection)} if you want to
     * override the existing values.
     * </p>
     * 
     * @param aggMetrics
     *        The agg metrics for the <code>TopicIRFilterOption</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public TopicIRFilterOption withAggMetrics(FilterAggMetrics... aggMetrics) {
        if (this.aggMetrics == null) {
            setAggMetrics(new java.util.ArrayList<FilterAggMetrics>(aggMetrics.length));
        }
        for (FilterAggMetrics ele : aggMetrics) {
            this.aggMetrics.add(ele);
        }
        return this;
    }

    /**
     * <p>
     * The agg metrics for the <code>TopicIRFilterOption</code>.
     * </p>
     * 
     * @param aggMetrics
     *        The agg metrics for the <code>TopicIRFilterOption</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public TopicIRFilterOption withAggMetrics(java.util.Collection<FilterAggMetrics> aggMetrics) {
        setAggMetrics(aggMetrics);
        return this;
    }

    /**
     * <p>
     * The <code>TopBottomLimit</code> for the <code>TopicIRFilterOption</code>.
     * </p>
     * 
     * @param topBottomLimit
     *        The <code>TopBottomLimit</code> for the <code>TopicIRFilterOption</code>.
     */

    public void setTopBottomLimit(TopicConstantValue topBottomLimit) {
        this.topBottomLimit = topBottomLimit;
    }

    /**
     * <p>
     * The <code>TopBottomLimit</code> for the <code>TopicIRFilterOption</code>.
     * </p>
     * 
     * @return The <code>TopBottomLimit</code> for the <code>TopicIRFilterOption</code>.
     */

    public TopicConstantValue getTopBottomLimit() {
        return this.topBottomLimit;
    }

    /**
     * <p>
     * The <code>TopBottomLimit</code> for the <code>TopicIRFilterOption</code>.
     * </p>
     * 
     * @param topBottomLimit
     *        The <code>TopBottomLimit</code> for the <code>TopicIRFilterOption</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public TopicIRFilterOption withTopBottomLimit(TopicConstantValue topBottomLimit) {
        setTopBottomLimit(topBottomLimit);
        return this;
    }

    /**
     * <p>
     * The sort direction for the <code>TopicIRFilterOption</code>.
     * </p>
     * 
     * @param sortDirection
     *        The sort direction for the <code>TopicIRFilterOption</code>.
     * @see TopicSortDirection
     */

    public void setSortDirection(String sortDirection) {
        this.sortDirection = sortDirection;
    }

    /**
     * <p>
     * The sort direction for the <code>TopicIRFilterOption</code>.
     * </p>
     * 
     * @return The sort direction for the <code>TopicIRFilterOption</code>.
     * @see TopicSortDirection
     */

    public String getSortDirection() {
        return this.sortDirection;
    }

    /**
     * <p>
     * The sort direction for the <code>TopicIRFilterOption</code>.
     * </p>
     * 
     * @param sortDirection
     *        The sort direction for the <code>TopicIRFilterOption</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see TopicSortDirection
     */

    public TopicIRFilterOption withSortDirection(String sortDirection) {
        setSortDirection(sortDirection);
        return this;
    }

    /**
     * <p>
     * The sort direction for the <code>TopicIRFilterOption</code>.
     * </p>
     * 
     * @param sortDirection
     *        The sort direction for the <code>TopicIRFilterOption</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see TopicSortDirection
     */

    public TopicIRFilterOption withSortDirection(TopicSortDirection sortDirection) {
        this.sortDirection = sortDirection.toString();
        return this;
    }

    /**
     * <p>
     * The anchor for the <code>TopicIRFilterOption</code>.
     * </p>
     * 
     * @param anchor
     *        The anchor for the <code>TopicIRFilterOption</code>.
     */

    public void setAnchor(Anchor anchor) {
        this.anchor = anchor;
    }

    /**
     * <p>
     * The anchor for the <code>TopicIRFilterOption</code>.
     * </p>
     * 
     * @return The anchor for the <code>TopicIRFilterOption</code>.
     */

    public Anchor getAnchor() {
        return this.anchor;
    }

    /**
     * <p>
     * The anchor for the <code>TopicIRFilterOption</code>.
     * </p>
     * 
     * @param anchor
     *        The anchor for the <code>TopicIRFilterOption</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public TopicIRFilterOption withAnchor(Anchor anchor) {
        setAnchor(anchor);
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
        if (getFilterType() != null)
            sb.append("FilterType: ").append(getFilterType()).append(",");
        if (getFilterClass() != null)
            sb.append("FilterClass: ").append(getFilterClass()).append(",");
        if (getOperandField() != null)
            sb.append("OperandField: ").append(getOperandField()).append(",");
        if (getFunction() != null)
            sb.append("Function: ").append(getFunction()).append(",");
        if (getConstant() != null)
            sb.append("Constant: ").append(getConstant()).append(",");
        if (getInverse() != null)
            sb.append("Inverse: ").append(getInverse()).append(",");
        if (getNullFilter() != null)
            sb.append("NullFilter: ").append(getNullFilter()).append(",");
        if (getAggregation() != null)
            sb.append("Aggregation: ").append(getAggregation()).append(",");
        if (getAggregationFunctionParameters() != null)
            sb.append("AggregationFunctionParameters: ").append(getAggregationFunctionParameters()).append(",");
        if (getAggregationPartitionBy() != null)
            sb.append("AggregationPartitionBy: ").append(getAggregationPartitionBy()).append(",");
        if (getRange() != null)
            sb.append("Range: ").append(getRange()).append(",");
        if (getInclusive() != null)
            sb.append("Inclusive: ").append(getInclusive()).append(",");
        if (getTimeGranularity() != null)
            sb.append("TimeGranularity: ").append(getTimeGranularity()).append(",");
        if (getLastNextOffset() != null)
            sb.append("LastNextOffset: ").append(getLastNextOffset()).append(",");
        if (getAggMetrics() != null)
            sb.append("AggMetrics: ").append(getAggMetrics()).append(",");
        if (getTopBottomLimit() != null)
            sb.append("TopBottomLimit: ").append(getTopBottomLimit()).append(",");
        if (getSortDirection() != null)
            sb.append("SortDirection: ").append(getSortDirection()).append(",");
        if (getAnchor() != null)
            sb.append("Anchor: ").append(getAnchor());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof TopicIRFilterOption == false)
            return false;
        TopicIRFilterOption other = (TopicIRFilterOption) obj;
        if (other.getFilterType() == null ^ this.getFilterType() == null)
            return false;
        if (other.getFilterType() != null && other.getFilterType().equals(this.getFilterType()) == false)
            return false;
        if (other.getFilterClass() == null ^ this.getFilterClass() == null)
            return false;
        if (other.getFilterClass() != null && other.getFilterClass().equals(this.getFilterClass()) == false)
            return false;
        if (other.getOperandField() == null ^ this.getOperandField() == null)
            return false;
        if (other.getOperandField() != null && other.getOperandField().equals(this.getOperandField()) == false)
            return false;
        if (other.getFunction() == null ^ this.getFunction() == null)
            return false;
        if (other.getFunction() != null && other.getFunction().equals(this.getFunction()) == false)
            return false;
        if (other.getConstant() == null ^ this.getConstant() == null)
            return false;
        if (other.getConstant() != null && other.getConstant().equals(this.getConstant()) == false)
            return false;
        if (other.getInverse() == null ^ this.getInverse() == null)
            return false;
        if (other.getInverse() != null && other.getInverse().equals(this.getInverse()) == false)
            return false;
        if (other.getNullFilter() == null ^ this.getNullFilter() == null)
            return false;
        if (other.getNullFilter() != null && other.getNullFilter().equals(this.getNullFilter()) == false)
            return false;
        if (other.getAggregation() == null ^ this.getAggregation() == null)
            return false;
        if (other.getAggregation() != null && other.getAggregation().equals(this.getAggregation()) == false)
            return false;
        if (other.getAggregationFunctionParameters() == null ^ this.getAggregationFunctionParameters() == null)
            return false;
        if (other.getAggregationFunctionParameters() != null
                && other.getAggregationFunctionParameters().equals(this.getAggregationFunctionParameters()) == false)
            return false;
        if (other.getAggregationPartitionBy() == null ^ this.getAggregationPartitionBy() == null)
            return false;
        if (other.getAggregationPartitionBy() != null && other.getAggregationPartitionBy().equals(this.getAggregationPartitionBy()) == false)
            return false;
        if (other.getRange() == null ^ this.getRange() == null)
            return false;
        if (other.getRange() != null && other.getRange().equals(this.getRange()) == false)
            return false;
        if (other.getInclusive() == null ^ this.getInclusive() == null)
            return false;
        if (other.getInclusive() != null && other.getInclusive().equals(this.getInclusive()) == false)
            return false;
        if (other.getTimeGranularity() == null ^ this.getTimeGranularity() == null)
            return false;
        if (other.getTimeGranularity() != null && other.getTimeGranularity().equals(this.getTimeGranularity()) == false)
            return false;
        if (other.getLastNextOffset() == null ^ this.getLastNextOffset() == null)
            return false;
        if (other.getLastNextOffset() != null && other.getLastNextOffset().equals(this.getLastNextOffset()) == false)
            return false;
        if (other.getAggMetrics() == null ^ this.getAggMetrics() == null)
            return false;
        if (other.getAggMetrics() != null && other.getAggMetrics().equals(this.getAggMetrics()) == false)
            return false;
        if (other.getTopBottomLimit() == null ^ this.getTopBottomLimit() == null)
            return false;
        if (other.getTopBottomLimit() != null && other.getTopBottomLimit().equals(this.getTopBottomLimit()) == false)
            return false;
        if (other.getSortDirection() == null ^ this.getSortDirection() == null)
            return false;
        if (other.getSortDirection() != null && other.getSortDirection().equals(this.getSortDirection()) == false)
            return false;
        if (other.getAnchor() == null ^ this.getAnchor() == null)
            return false;
        if (other.getAnchor() != null && other.getAnchor().equals(this.getAnchor()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getFilterType() == null) ? 0 : getFilterType().hashCode());
        hashCode = prime * hashCode + ((getFilterClass() == null) ? 0 : getFilterClass().hashCode());
        hashCode = prime * hashCode + ((getOperandField() == null) ? 0 : getOperandField().hashCode());
        hashCode = prime * hashCode + ((getFunction() == null) ? 0 : getFunction().hashCode());
        hashCode = prime * hashCode + ((getConstant() == null) ? 0 : getConstant().hashCode());
        hashCode = prime * hashCode + ((getInverse() == null) ? 0 : getInverse().hashCode());
        hashCode = prime * hashCode + ((getNullFilter() == null) ? 0 : getNullFilter().hashCode());
        hashCode = prime * hashCode + ((getAggregation() == null) ? 0 : getAggregation().hashCode());
        hashCode = prime * hashCode + ((getAggregationFunctionParameters() == null) ? 0 : getAggregationFunctionParameters().hashCode());
        hashCode = prime * hashCode + ((getAggregationPartitionBy() == null) ? 0 : getAggregationPartitionBy().hashCode());
        hashCode = prime * hashCode + ((getRange() == null) ? 0 : getRange().hashCode());
        hashCode = prime * hashCode + ((getInclusive() == null) ? 0 : getInclusive().hashCode());
        hashCode = prime * hashCode + ((getTimeGranularity() == null) ? 0 : getTimeGranularity().hashCode());
        hashCode = prime * hashCode + ((getLastNextOffset() == null) ? 0 : getLastNextOffset().hashCode());
        hashCode = prime * hashCode + ((getAggMetrics() == null) ? 0 : getAggMetrics().hashCode());
        hashCode = prime * hashCode + ((getTopBottomLimit() == null) ? 0 : getTopBottomLimit().hashCode());
        hashCode = prime * hashCode + ((getSortDirection() == null) ? 0 : getSortDirection().hashCode());
        hashCode = prime * hashCode + ((getAnchor() == null) ? 0 : getAnchor().hashCode());
        return hashCode;
    }

    @Override
    public TopicIRFilterOption clone() {
        try {
            return (TopicIRFilterOption) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.quicksight.model.transform.TopicIRFilterOptionMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
