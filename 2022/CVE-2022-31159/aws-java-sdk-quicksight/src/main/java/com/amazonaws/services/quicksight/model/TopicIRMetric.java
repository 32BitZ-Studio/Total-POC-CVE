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
 * The definition for a <code>TopicIRMetric</code>.
 * </p>
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/quicksight-2018-04-01/TopicIRMetric" target="_top">AWS API
 *      Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class TopicIRMetric implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * The metric ID for the <code>TopicIRMetric</code>.
     * </p>
     */
    private Identifier metricId;
    /**
     * <p>
     * The function for the <code>TopicIRMetric</code>.
     * </p>
     */
    private AggFunction function;
    /**
     * <p>
     * The operands for the <code>TopicIRMetric</code>.
     * </p>
     */
    private java.util.List<Identifier> operands;
    /**
     * <p>
     * The comparison method for the <code>TopicIRMetric</code>.
     * </p>
     */
    private TopicIRComparisonMethod comparisonMethod;
    /**
     * <p>
     * The expression for the <code>TopicIRMetric</code>.
     * </p>
     */
    private String expression;
    /**
     * <p>
     * The calculated field references for the <code>TopicIRMetric</code>.
     * </p>
     */
    private java.util.List<Identifier> calculatedFieldReferences;
    /**
     * <p>
     * The display format for the <code>TopicIRMetric</code>.
     * </p>
     */
    private String displayFormat;

    private DisplayFormatOptions displayFormatOptions;
    /**
     * <p>
     * The named entity for the <code>TopicIRMetric</code>.
     * </p>
     */
    private NamedEntityRef namedEntity;

    /**
     * <p>
     * The metric ID for the <code>TopicIRMetric</code>.
     * </p>
     * 
     * @param metricId
     *        The metric ID for the <code>TopicIRMetric</code>.
     */

    public void setMetricId(Identifier metricId) {
        this.metricId = metricId;
    }

    /**
     * <p>
     * The metric ID for the <code>TopicIRMetric</code>.
     * </p>
     * 
     * @return The metric ID for the <code>TopicIRMetric</code>.
     */

    public Identifier getMetricId() {
        return this.metricId;
    }

    /**
     * <p>
     * The metric ID for the <code>TopicIRMetric</code>.
     * </p>
     * 
     * @param metricId
     *        The metric ID for the <code>TopicIRMetric</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public TopicIRMetric withMetricId(Identifier metricId) {
        setMetricId(metricId);
        return this;
    }

    /**
     * <p>
     * The function for the <code>TopicIRMetric</code>.
     * </p>
     * 
     * @param function
     *        The function for the <code>TopicIRMetric</code>.
     */

    public void setFunction(AggFunction function) {
        this.function = function;
    }

    /**
     * <p>
     * The function for the <code>TopicIRMetric</code>.
     * </p>
     * 
     * @return The function for the <code>TopicIRMetric</code>.
     */

    public AggFunction getFunction() {
        return this.function;
    }

    /**
     * <p>
     * The function for the <code>TopicIRMetric</code>.
     * </p>
     * 
     * @param function
     *        The function for the <code>TopicIRMetric</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public TopicIRMetric withFunction(AggFunction function) {
        setFunction(function);
        return this;
    }

    /**
     * <p>
     * The operands for the <code>TopicIRMetric</code>.
     * </p>
     * 
     * @return The operands for the <code>TopicIRMetric</code>.
     */

    public java.util.List<Identifier> getOperands() {
        return operands;
    }

    /**
     * <p>
     * The operands for the <code>TopicIRMetric</code>.
     * </p>
     * 
     * @param operands
     *        The operands for the <code>TopicIRMetric</code>.
     */

    public void setOperands(java.util.Collection<Identifier> operands) {
        if (operands == null) {
            this.operands = null;
            return;
        }

        this.operands = new java.util.ArrayList<Identifier>(operands);
    }

    /**
     * <p>
     * The operands for the <code>TopicIRMetric</code>.
     * </p>
     * <p>
     * <b>NOTE:</b> This method appends the values to the existing list (if any). Use
     * {@link #setOperands(java.util.Collection)} or {@link #withOperands(java.util.Collection)} if you want to override
     * the existing values.
     * </p>
     * 
     * @param operands
     *        The operands for the <code>TopicIRMetric</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public TopicIRMetric withOperands(Identifier... operands) {
        if (this.operands == null) {
            setOperands(new java.util.ArrayList<Identifier>(operands.length));
        }
        for (Identifier ele : operands) {
            this.operands.add(ele);
        }
        return this;
    }

    /**
     * <p>
     * The operands for the <code>TopicIRMetric</code>.
     * </p>
     * 
     * @param operands
     *        The operands for the <code>TopicIRMetric</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public TopicIRMetric withOperands(java.util.Collection<Identifier> operands) {
        setOperands(operands);
        return this;
    }

    /**
     * <p>
     * The comparison method for the <code>TopicIRMetric</code>.
     * </p>
     * 
     * @param comparisonMethod
     *        The comparison method for the <code>TopicIRMetric</code>.
     */

    public void setComparisonMethod(TopicIRComparisonMethod comparisonMethod) {
        this.comparisonMethod = comparisonMethod;
    }

    /**
     * <p>
     * The comparison method for the <code>TopicIRMetric</code>.
     * </p>
     * 
     * @return The comparison method for the <code>TopicIRMetric</code>.
     */

    public TopicIRComparisonMethod getComparisonMethod() {
        return this.comparisonMethod;
    }

    /**
     * <p>
     * The comparison method for the <code>TopicIRMetric</code>.
     * </p>
     * 
     * @param comparisonMethod
     *        The comparison method for the <code>TopicIRMetric</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public TopicIRMetric withComparisonMethod(TopicIRComparisonMethod comparisonMethod) {
        setComparisonMethod(comparisonMethod);
        return this;
    }

    /**
     * <p>
     * The expression for the <code>TopicIRMetric</code>.
     * </p>
     * 
     * @param expression
     *        The expression for the <code>TopicIRMetric</code>.
     */

    public void setExpression(String expression) {
        this.expression = expression;
    }

    /**
     * <p>
     * The expression for the <code>TopicIRMetric</code>.
     * </p>
     * 
     * @return The expression for the <code>TopicIRMetric</code>.
     */

    public String getExpression() {
        return this.expression;
    }

    /**
     * <p>
     * The expression for the <code>TopicIRMetric</code>.
     * </p>
     * 
     * @param expression
     *        The expression for the <code>TopicIRMetric</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public TopicIRMetric withExpression(String expression) {
        setExpression(expression);
        return this;
    }

    /**
     * <p>
     * The calculated field references for the <code>TopicIRMetric</code>.
     * </p>
     * 
     * @return The calculated field references for the <code>TopicIRMetric</code>.
     */

    public java.util.List<Identifier> getCalculatedFieldReferences() {
        return calculatedFieldReferences;
    }

    /**
     * <p>
     * The calculated field references for the <code>TopicIRMetric</code>.
     * </p>
     * 
     * @param calculatedFieldReferences
     *        The calculated field references for the <code>TopicIRMetric</code>.
     */

    public void setCalculatedFieldReferences(java.util.Collection<Identifier> calculatedFieldReferences) {
        if (calculatedFieldReferences == null) {
            this.calculatedFieldReferences = null;
            return;
        }

        this.calculatedFieldReferences = new java.util.ArrayList<Identifier>(calculatedFieldReferences);
    }

    /**
     * <p>
     * The calculated field references for the <code>TopicIRMetric</code>.
     * </p>
     * <p>
     * <b>NOTE:</b> This method appends the values to the existing list (if any). Use
     * {@link #setCalculatedFieldReferences(java.util.Collection)} or
     * {@link #withCalculatedFieldReferences(java.util.Collection)} if you want to override the existing values.
     * </p>
     * 
     * @param calculatedFieldReferences
     *        The calculated field references for the <code>TopicIRMetric</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public TopicIRMetric withCalculatedFieldReferences(Identifier... calculatedFieldReferences) {
        if (this.calculatedFieldReferences == null) {
            setCalculatedFieldReferences(new java.util.ArrayList<Identifier>(calculatedFieldReferences.length));
        }
        for (Identifier ele : calculatedFieldReferences) {
            this.calculatedFieldReferences.add(ele);
        }
        return this;
    }

    /**
     * <p>
     * The calculated field references for the <code>TopicIRMetric</code>.
     * </p>
     * 
     * @param calculatedFieldReferences
     *        The calculated field references for the <code>TopicIRMetric</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public TopicIRMetric withCalculatedFieldReferences(java.util.Collection<Identifier> calculatedFieldReferences) {
        setCalculatedFieldReferences(calculatedFieldReferences);
        return this;
    }

    /**
     * <p>
     * The display format for the <code>TopicIRMetric</code>.
     * </p>
     * 
     * @param displayFormat
     *        The display format for the <code>TopicIRMetric</code>.
     * @see DisplayFormat
     */

    public void setDisplayFormat(String displayFormat) {
        this.displayFormat = displayFormat;
    }

    /**
     * <p>
     * The display format for the <code>TopicIRMetric</code>.
     * </p>
     * 
     * @return The display format for the <code>TopicIRMetric</code>.
     * @see DisplayFormat
     */

    public String getDisplayFormat() {
        return this.displayFormat;
    }

    /**
     * <p>
     * The display format for the <code>TopicIRMetric</code>.
     * </p>
     * 
     * @param displayFormat
     *        The display format for the <code>TopicIRMetric</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see DisplayFormat
     */

    public TopicIRMetric withDisplayFormat(String displayFormat) {
        setDisplayFormat(displayFormat);
        return this;
    }

    /**
     * <p>
     * The display format for the <code>TopicIRMetric</code>.
     * </p>
     * 
     * @param displayFormat
     *        The display format for the <code>TopicIRMetric</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see DisplayFormat
     */

    public TopicIRMetric withDisplayFormat(DisplayFormat displayFormat) {
        this.displayFormat = displayFormat.toString();
        return this;
    }

    /**
     * @param displayFormatOptions
     */

    public void setDisplayFormatOptions(DisplayFormatOptions displayFormatOptions) {
        this.displayFormatOptions = displayFormatOptions;
    }

    /**
     * @return
     */

    public DisplayFormatOptions getDisplayFormatOptions() {
        return this.displayFormatOptions;
    }

    /**
     * @param displayFormatOptions
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public TopicIRMetric withDisplayFormatOptions(DisplayFormatOptions displayFormatOptions) {
        setDisplayFormatOptions(displayFormatOptions);
        return this;
    }

    /**
     * <p>
     * The named entity for the <code>TopicIRMetric</code>.
     * </p>
     * 
     * @param namedEntity
     *        The named entity for the <code>TopicIRMetric</code>.
     */

    public void setNamedEntity(NamedEntityRef namedEntity) {
        this.namedEntity = namedEntity;
    }

    /**
     * <p>
     * The named entity for the <code>TopicIRMetric</code>.
     * </p>
     * 
     * @return The named entity for the <code>TopicIRMetric</code>.
     */

    public NamedEntityRef getNamedEntity() {
        return this.namedEntity;
    }

    /**
     * <p>
     * The named entity for the <code>TopicIRMetric</code>.
     * </p>
     * 
     * @param namedEntity
     *        The named entity for the <code>TopicIRMetric</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public TopicIRMetric withNamedEntity(NamedEntityRef namedEntity) {
        setNamedEntity(namedEntity);
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
        if (getMetricId() != null)
            sb.append("MetricId: ").append(getMetricId()).append(",");
        if (getFunction() != null)
            sb.append("Function: ").append(getFunction()).append(",");
        if (getOperands() != null)
            sb.append("Operands: ").append(getOperands()).append(",");
        if (getComparisonMethod() != null)
            sb.append("ComparisonMethod: ").append(getComparisonMethod()).append(",");
        if (getExpression() != null)
            sb.append("Expression: ").append("***Sensitive Data Redacted***").append(",");
        if (getCalculatedFieldReferences() != null)
            sb.append("CalculatedFieldReferences: ").append(getCalculatedFieldReferences()).append(",");
        if (getDisplayFormat() != null)
            sb.append("DisplayFormat: ").append(getDisplayFormat()).append(",");
        if (getDisplayFormatOptions() != null)
            sb.append("DisplayFormatOptions: ").append(getDisplayFormatOptions()).append(",");
        if (getNamedEntity() != null)
            sb.append("NamedEntity: ").append(getNamedEntity());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof TopicIRMetric == false)
            return false;
        TopicIRMetric other = (TopicIRMetric) obj;
        if (other.getMetricId() == null ^ this.getMetricId() == null)
            return false;
        if (other.getMetricId() != null && other.getMetricId().equals(this.getMetricId()) == false)
            return false;
        if (other.getFunction() == null ^ this.getFunction() == null)
            return false;
        if (other.getFunction() != null && other.getFunction().equals(this.getFunction()) == false)
            return false;
        if (other.getOperands() == null ^ this.getOperands() == null)
            return false;
        if (other.getOperands() != null && other.getOperands().equals(this.getOperands()) == false)
            return false;
        if (other.getComparisonMethod() == null ^ this.getComparisonMethod() == null)
            return false;
        if (other.getComparisonMethod() != null && other.getComparisonMethod().equals(this.getComparisonMethod()) == false)
            return false;
        if (other.getExpression() == null ^ this.getExpression() == null)
            return false;
        if (other.getExpression() != null && other.getExpression().equals(this.getExpression()) == false)
            return false;
        if (other.getCalculatedFieldReferences() == null ^ this.getCalculatedFieldReferences() == null)
            return false;
        if (other.getCalculatedFieldReferences() != null && other.getCalculatedFieldReferences().equals(this.getCalculatedFieldReferences()) == false)
            return false;
        if (other.getDisplayFormat() == null ^ this.getDisplayFormat() == null)
            return false;
        if (other.getDisplayFormat() != null && other.getDisplayFormat().equals(this.getDisplayFormat()) == false)
            return false;
        if (other.getDisplayFormatOptions() == null ^ this.getDisplayFormatOptions() == null)
            return false;
        if (other.getDisplayFormatOptions() != null && other.getDisplayFormatOptions().equals(this.getDisplayFormatOptions()) == false)
            return false;
        if (other.getNamedEntity() == null ^ this.getNamedEntity() == null)
            return false;
        if (other.getNamedEntity() != null && other.getNamedEntity().equals(this.getNamedEntity()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getMetricId() == null) ? 0 : getMetricId().hashCode());
        hashCode = prime * hashCode + ((getFunction() == null) ? 0 : getFunction().hashCode());
        hashCode = prime * hashCode + ((getOperands() == null) ? 0 : getOperands().hashCode());
        hashCode = prime * hashCode + ((getComparisonMethod() == null) ? 0 : getComparisonMethod().hashCode());
        hashCode = prime * hashCode + ((getExpression() == null) ? 0 : getExpression().hashCode());
        hashCode = prime * hashCode + ((getCalculatedFieldReferences() == null) ? 0 : getCalculatedFieldReferences().hashCode());
        hashCode = prime * hashCode + ((getDisplayFormat() == null) ? 0 : getDisplayFormat().hashCode());
        hashCode = prime * hashCode + ((getDisplayFormatOptions() == null) ? 0 : getDisplayFormatOptions().hashCode());
        hashCode = prime * hashCode + ((getNamedEntity() == null) ? 0 : getNamedEntity().hashCode());
        return hashCode;
    }

    @Override
    public TopicIRMetric clone() {
        try {
            return (TopicIRMetric) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.quicksight.model.transform.TopicIRMetricMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
