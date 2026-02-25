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
 * A <code>NestedFilter</code> filters data with a subset of data that is defined by the nested inner filter.
 * </p>
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/quicksight-2018-04-01/NestedFilter" target="_top">AWS API
 *      Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class NestedFilter implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * An identifier that uniquely identifies a filter within a dashboard, analysis, or template.
     * </p>
     */
    private String filterId;
    /**
     * <p>
     * The column that the filter is applied to.
     * </p>
     */
    private ColumnIdentifier column;
    /**
     * <p>
     * A boolean condition to include or exclude the subset that is defined by the values of the nested inner filter.
     * </p>
     */
    private Boolean includeInnerSet;
    /**
     * <p>
     * The <code>InnerFilter</code> defines the subset of data to be used with the <code>NestedFilter</code>.
     * </p>
     */
    private InnerFilter innerFilter;

    /**
     * <p>
     * An identifier that uniquely identifies a filter within a dashboard, analysis, or template.
     * </p>
     * 
     * @param filterId
     *        An identifier that uniquely identifies a filter within a dashboard, analysis, or template.
     */

    public void setFilterId(String filterId) {
        this.filterId = filterId;
    }

    /**
     * <p>
     * An identifier that uniquely identifies a filter within a dashboard, analysis, or template.
     * </p>
     * 
     * @return An identifier that uniquely identifies a filter within a dashboard, analysis, or template.
     */

    public String getFilterId() {
        return this.filterId;
    }

    /**
     * <p>
     * An identifier that uniquely identifies a filter within a dashboard, analysis, or template.
     * </p>
     * 
     * @param filterId
     *        An identifier that uniquely identifies a filter within a dashboard, analysis, or template.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public NestedFilter withFilterId(String filterId) {
        setFilterId(filterId);
        return this;
    }

    /**
     * <p>
     * The column that the filter is applied to.
     * </p>
     * 
     * @param column
     *        The column that the filter is applied to.
     */

    public void setColumn(ColumnIdentifier column) {
        this.column = column;
    }

    /**
     * <p>
     * The column that the filter is applied to.
     * </p>
     * 
     * @return The column that the filter is applied to.
     */

    public ColumnIdentifier getColumn() {
        return this.column;
    }

    /**
     * <p>
     * The column that the filter is applied to.
     * </p>
     * 
     * @param column
     *        The column that the filter is applied to.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public NestedFilter withColumn(ColumnIdentifier column) {
        setColumn(column);
        return this;
    }

    /**
     * <p>
     * A boolean condition to include or exclude the subset that is defined by the values of the nested inner filter.
     * </p>
     * 
     * @param includeInnerSet
     *        A boolean condition to include or exclude the subset that is defined by the values of the nested inner
     *        filter.
     */

    public void setIncludeInnerSet(Boolean includeInnerSet) {
        this.includeInnerSet = includeInnerSet;
    }

    /**
     * <p>
     * A boolean condition to include or exclude the subset that is defined by the values of the nested inner filter.
     * </p>
     * 
     * @return A boolean condition to include or exclude the subset that is defined by the values of the nested inner
     *         filter.
     */

    public Boolean getIncludeInnerSet() {
        return this.includeInnerSet;
    }

    /**
     * <p>
     * A boolean condition to include or exclude the subset that is defined by the values of the nested inner filter.
     * </p>
     * 
     * @param includeInnerSet
     *        A boolean condition to include or exclude the subset that is defined by the values of the nested inner
     *        filter.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public NestedFilter withIncludeInnerSet(Boolean includeInnerSet) {
        setIncludeInnerSet(includeInnerSet);
        return this;
    }

    /**
     * <p>
     * A boolean condition to include or exclude the subset that is defined by the values of the nested inner filter.
     * </p>
     * 
     * @return A boolean condition to include or exclude the subset that is defined by the values of the nested inner
     *         filter.
     */

    public Boolean isIncludeInnerSet() {
        return this.includeInnerSet;
    }

    /**
     * <p>
     * The <code>InnerFilter</code> defines the subset of data to be used with the <code>NestedFilter</code>.
     * </p>
     * 
     * @param innerFilter
     *        The <code>InnerFilter</code> defines the subset of data to be used with the <code>NestedFilter</code>.
     */

    public void setInnerFilter(InnerFilter innerFilter) {
        this.innerFilter = innerFilter;
    }

    /**
     * <p>
     * The <code>InnerFilter</code> defines the subset of data to be used with the <code>NestedFilter</code>.
     * </p>
     * 
     * @return The <code>InnerFilter</code> defines the subset of data to be used with the <code>NestedFilter</code>.
     */

    public InnerFilter getInnerFilter() {
        return this.innerFilter;
    }

    /**
     * <p>
     * The <code>InnerFilter</code> defines the subset of data to be used with the <code>NestedFilter</code>.
     * </p>
     * 
     * @param innerFilter
     *        The <code>InnerFilter</code> defines the subset of data to be used with the <code>NestedFilter</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public NestedFilter withInnerFilter(InnerFilter innerFilter) {
        setInnerFilter(innerFilter);
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
        if (getFilterId() != null)
            sb.append("FilterId: ").append(getFilterId()).append(",");
        if (getColumn() != null)
            sb.append("Column: ").append(getColumn()).append(",");
        if (getIncludeInnerSet() != null)
            sb.append("IncludeInnerSet: ").append(getIncludeInnerSet()).append(",");
        if (getInnerFilter() != null)
            sb.append("InnerFilter: ").append(getInnerFilter());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof NestedFilter == false)
            return false;
        NestedFilter other = (NestedFilter) obj;
        if (other.getFilterId() == null ^ this.getFilterId() == null)
            return false;
        if (other.getFilterId() != null && other.getFilterId().equals(this.getFilterId()) == false)
            return false;
        if (other.getColumn() == null ^ this.getColumn() == null)
            return false;
        if (other.getColumn() != null && other.getColumn().equals(this.getColumn()) == false)
            return false;
        if (other.getIncludeInnerSet() == null ^ this.getIncludeInnerSet() == null)
            return false;
        if (other.getIncludeInnerSet() != null && other.getIncludeInnerSet().equals(this.getIncludeInnerSet()) == false)
            return false;
        if (other.getInnerFilter() == null ^ this.getInnerFilter() == null)
            return false;
        if (other.getInnerFilter() != null && other.getInnerFilter().equals(this.getInnerFilter()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getFilterId() == null) ? 0 : getFilterId().hashCode());
        hashCode = prime * hashCode + ((getColumn() == null) ? 0 : getColumn().hashCode());
        hashCode = prime * hashCode + ((getIncludeInnerSet() == null) ? 0 : getIncludeInnerSet().hashCode());
        hashCode = prime * hashCode + ((getInnerFilter() == null) ? 0 : getInnerFilter().hashCode());
        return hashCode;
    }

    @Override
    public NestedFilter clone() {
        try {
            return (NestedFilter) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.quicksight.model.transform.NestedFilterMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
