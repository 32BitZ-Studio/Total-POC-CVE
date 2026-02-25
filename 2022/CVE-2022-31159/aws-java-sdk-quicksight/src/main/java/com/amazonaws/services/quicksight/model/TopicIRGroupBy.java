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
 * The definition for a <code>TopicIRGroupBy</code>.
 * </p>
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/quicksight-2018-04-01/TopicIRGroupBy" target="_top">AWS API
 *      Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class TopicIRGroupBy implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * The field name for the <code>TopicIRGroupBy</code>.
     * </p>
     */
    private Identifier fieldName;
    /**
     * <p>
     * The time granularity for the <code>TopicIRGroupBy</code>.
     * </p>
     */
    private String timeGranularity;
    /**
     * <p>
     * The sort for the <code>TopicIRGroupBy</code>.
     * </p>
     */
    private TopicSortClause sort;
    /**
     * <p>
     * The display format for the <code>TopicIRGroupBy</code>.
     * </p>
     */
    private String displayFormat;

    private DisplayFormatOptions displayFormatOptions;
    /**
     * <p>
     * The named entity for the <code>TopicIRGroupBy</code>.
     * </p>
     */
    private NamedEntityRef namedEntity;

    /**
     * <p>
     * The field name for the <code>TopicIRGroupBy</code>.
     * </p>
     * 
     * @param fieldName
     *        The field name for the <code>TopicIRGroupBy</code>.
     */

    public void setFieldName(Identifier fieldName) {
        this.fieldName = fieldName;
    }

    /**
     * <p>
     * The field name for the <code>TopicIRGroupBy</code>.
     * </p>
     * 
     * @return The field name for the <code>TopicIRGroupBy</code>.
     */

    public Identifier getFieldName() {
        return this.fieldName;
    }

    /**
     * <p>
     * The field name for the <code>TopicIRGroupBy</code>.
     * </p>
     * 
     * @param fieldName
     *        The field name for the <code>TopicIRGroupBy</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public TopicIRGroupBy withFieldName(Identifier fieldName) {
        setFieldName(fieldName);
        return this;
    }

    /**
     * <p>
     * The time granularity for the <code>TopicIRGroupBy</code>.
     * </p>
     * 
     * @param timeGranularity
     *        The time granularity for the <code>TopicIRGroupBy</code>.
     * @see TopicTimeGranularity
     */

    public void setTimeGranularity(String timeGranularity) {
        this.timeGranularity = timeGranularity;
    }

    /**
     * <p>
     * The time granularity for the <code>TopicIRGroupBy</code>.
     * </p>
     * 
     * @return The time granularity for the <code>TopicIRGroupBy</code>.
     * @see TopicTimeGranularity
     */

    public String getTimeGranularity() {
        return this.timeGranularity;
    }

    /**
     * <p>
     * The time granularity for the <code>TopicIRGroupBy</code>.
     * </p>
     * 
     * @param timeGranularity
     *        The time granularity for the <code>TopicIRGroupBy</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see TopicTimeGranularity
     */

    public TopicIRGroupBy withTimeGranularity(String timeGranularity) {
        setTimeGranularity(timeGranularity);
        return this;
    }

    /**
     * <p>
     * The time granularity for the <code>TopicIRGroupBy</code>.
     * </p>
     * 
     * @param timeGranularity
     *        The time granularity for the <code>TopicIRGroupBy</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see TopicTimeGranularity
     */

    public TopicIRGroupBy withTimeGranularity(TopicTimeGranularity timeGranularity) {
        this.timeGranularity = timeGranularity.toString();
        return this;
    }

    /**
     * <p>
     * The sort for the <code>TopicIRGroupBy</code>.
     * </p>
     * 
     * @param sort
     *        The sort for the <code>TopicIRGroupBy</code>.
     */

    public void setSort(TopicSortClause sort) {
        this.sort = sort;
    }

    /**
     * <p>
     * The sort for the <code>TopicIRGroupBy</code>.
     * </p>
     * 
     * @return The sort for the <code>TopicIRGroupBy</code>.
     */

    public TopicSortClause getSort() {
        return this.sort;
    }

    /**
     * <p>
     * The sort for the <code>TopicIRGroupBy</code>.
     * </p>
     * 
     * @param sort
     *        The sort for the <code>TopicIRGroupBy</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public TopicIRGroupBy withSort(TopicSortClause sort) {
        setSort(sort);
        return this;
    }

    /**
     * <p>
     * The display format for the <code>TopicIRGroupBy</code>.
     * </p>
     * 
     * @param displayFormat
     *        The display format for the <code>TopicIRGroupBy</code>.
     * @see DisplayFormat
     */

    public void setDisplayFormat(String displayFormat) {
        this.displayFormat = displayFormat;
    }

    /**
     * <p>
     * The display format for the <code>TopicIRGroupBy</code>.
     * </p>
     * 
     * @return The display format for the <code>TopicIRGroupBy</code>.
     * @see DisplayFormat
     */

    public String getDisplayFormat() {
        return this.displayFormat;
    }

    /**
     * <p>
     * The display format for the <code>TopicIRGroupBy</code>.
     * </p>
     * 
     * @param displayFormat
     *        The display format for the <code>TopicIRGroupBy</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see DisplayFormat
     */

    public TopicIRGroupBy withDisplayFormat(String displayFormat) {
        setDisplayFormat(displayFormat);
        return this;
    }

    /**
     * <p>
     * The display format for the <code>TopicIRGroupBy</code>.
     * </p>
     * 
     * @param displayFormat
     *        The display format for the <code>TopicIRGroupBy</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see DisplayFormat
     */

    public TopicIRGroupBy withDisplayFormat(DisplayFormat displayFormat) {
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

    public TopicIRGroupBy withDisplayFormatOptions(DisplayFormatOptions displayFormatOptions) {
        setDisplayFormatOptions(displayFormatOptions);
        return this;
    }

    /**
     * <p>
     * The named entity for the <code>TopicIRGroupBy</code>.
     * </p>
     * 
     * @param namedEntity
     *        The named entity for the <code>TopicIRGroupBy</code>.
     */

    public void setNamedEntity(NamedEntityRef namedEntity) {
        this.namedEntity = namedEntity;
    }

    /**
     * <p>
     * The named entity for the <code>TopicIRGroupBy</code>.
     * </p>
     * 
     * @return The named entity for the <code>TopicIRGroupBy</code>.
     */

    public NamedEntityRef getNamedEntity() {
        return this.namedEntity;
    }

    /**
     * <p>
     * The named entity for the <code>TopicIRGroupBy</code>.
     * </p>
     * 
     * @param namedEntity
     *        The named entity for the <code>TopicIRGroupBy</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public TopicIRGroupBy withNamedEntity(NamedEntityRef namedEntity) {
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
        if (getFieldName() != null)
            sb.append("FieldName: ").append(getFieldName()).append(",");
        if (getTimeGranularity() != null)
            sb.append("TimeGranularity: ").append(getTimeGranularity()).append(",");
        if (getSort() != null)
            sb.append("Sort: ").append(getSort()).append(",");
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

        if (obj instanceof TopicIRGroupBy == false)
            return false;
        TopicIRGroupBy other = (TopicIRGroupBy) obj;
        if (other.getFieldName() == null ^ this.getFieldName() == null)
            return false;
        if (other.getFieldName() != null && other.getFieldName().equals(this.getFieldName()) == false)
            return false;
        if (other.getTimeGranularity() == null ^ this.getTimeGranularity() == null)
            return false;
        if (other.getTimeGranularity() != null && other.getTimeGranularity().equals(this.getTimeGranularity()) == false)
            return false;
        if (other.getSort() == null ^ this.getSort() == null)
            return false;
        if (other.getSort() != null && other.getSort().equals(this.getSort()) == false)
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

        hashCode = prime * hashCode + ((getFieldName() == null) ? 0 : getFieldName().hashCode());
        hashCode = prime * hashCode + ((getTimeGranularity() == null) ? 0 : getTimeGranularity().hashCode());
        hashCode = prime * hashCode + ((getSort() == null) ? 0 : getSort().hashCode());
        hashCode = prime * hashCode + ((getDisplayFormat() == null) ? 0 : getDisplayFormat().hashCode());
        hashCode = prime * hashCode + ((getDisplayFormatOptions() == null) ? 0 : getDisplayFormatOptions().hashCode());
        hashCode = prime * hashCode + ((getNamedEntity() == null) ? 0 : getNamedEntity().hashCode());
        return hashCode;
    }

    @Override
    public TopicIRGroupBy clone() {
        try {
            return (TopicIRGroupBy) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.quicksight.model.transform.TopicIRGroupByMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
