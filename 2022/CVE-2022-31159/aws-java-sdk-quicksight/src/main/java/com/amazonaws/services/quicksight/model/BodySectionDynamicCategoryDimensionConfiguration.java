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
 * Describes the <b>Category</b> dataset column and constraints for the dynamic values used to repeat the contents of a
 * section.
 * </p>
 * 
 * @see <a
 *      href="http://docs.aws.amazon.com/goto/WebAPI/quicksight-2018-04-01/BodySectionDynamicCategoryDimensionConfiguration"
 *      target="_top">AWS API Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class BodySectionDynamicCategoryDimensionConfiguration implements Serializable, Cloneable, StructuredPojo {

    private ColumnIdentifier column;
    /**
     * <p>
     * Number of values to use from the column for repetition.
     * </p>
     */
    private Integer limit;
    /**
     * <p>
     * Sort criteria on the column values that you use for repetition.
     * </p>
     */
    private java.util.List<ColumnSort> sortByMetrics;

    /**
     * @param column
     */

    public void setColumn(ColumnIdentifier column) {
        this.column = column;
    }

    /**
     * @return
     */

    public ColumnIdentifier getColumn() {
        return this.column;
    }

    /**
     * @param column
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public BodySectionDynamicCategoryDimensionConfiguration withColumn(ColumnIdentifier column) {
        setColumn(column);
        return this;
    }

    /**
     * <p>
     * Number of values to use from the column for repetition.
     * </p>
     * 
     * @param limit
     *        Number of values to use from the column for repetition.
     */

    public void setLimit(Integer limit) {
        this.limit = limit;
    }

    /**
     * <p>
     * Number of values to use from the column for repetition.
     * </p>
     * 
     * @return Number of values to use from the column for repetition.
     */

    public Integer getLimit() {
        return this.limit;
    }

    /**
     * <p>
     * Number of values to use from the column for repetition.
     * </p>
     * 
     * @param limit
     *        Number of values to use from the column for repetition.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public BodySectionDynamicCategoryDimensionConfiguration withLimit(Integer limit) {
        setLimit(limit);
        return this;
    }

    /**
     * <p>
     * Sort criteria on the column values that you use for repetition.
     * </p>
     * 
     * @return Sort criteria on the column values that you use for repetition.
     */

    public java.util.List<ColumnSort> getSortByMetrics() {
        return sortByMetrics;
    }

    /**
     * <p>
     * Sort criteria on the column values that you use for repetition.
     * </p>
     * 
     * @param sortByMetrics
     *        Sort criteria on the column values that you use for repetition.
     */

    public void setSortByMetrics(java.util.Collection<ColumnSort> sortByMetrics) {
        if (sortByMetrics == null) {
            this.sortByMetrics = null;
            return;
        }

        this.sortByMetrics = new java.util.ArrayList<ColumnSort>(sortByMetrics);
    }

    /**
     * <p>
     * Sort criteria on the column values that you use for repetition.
     * </p>
     * <p>
     * <b>NOTE:</b> This method appends the values to the existing list (if any). Use
     * {@link #setSortByMetrics(java.util.Collection)} or {@link #withSortByMetrics(java.util.Collection)} if you want
     * to override the existing values.
     * </p>
     * 
     * @param sortByMetrics
     *        Sort criteria on the column values that you use for repetition.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public BodySectionDynamicCategoryDimensionConfiguration withSortByMetrics(ColumnSort... sortByMetrics) {
        if (this.sortByMetrics == null) {
            setSortByMetrics(new java.util.ArrayList<ColumnSort>(sortByMetrics.length));
        }
        for (ColumnSort ele : sortByMetrics) {
            this.sortByMetrics.add(ele);
        }
        return this;
    }

    /**
     * <p>
     * Sort criteria on the column values that you use for repetition.
     * </p>
     * 
     * @param sortByMetrics
     *        Sort criteria on the column values that you use for repetition.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public BodySectionDynamicCategoryDimensionConfiguration withSortByMetrics(java.util.Collection<ColumnSort> sortByMetrics) {
        setSortByMetrics(sortByMetrics);
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
        if (getColumn() != null)
            sb.append("Column: ").append(getColumn()).append(",");
        if (getLimit() != null)
            sb.append("Limit: ").append(getLimit()).append(",");
        if (getSortByMetrics() != null)
            sb.append("SortByMetrics: ").append(getSortByMetrics());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof BodySectionDynamicCategoryDimensionConfiguration == false)
            return false;
        BodySectionDynamicCategoryDimensionConfiguration other = (BodySectionDynamicCategoryDimensionConfiguration) obj;
        if (other.getColumn() == null ^ this.getColumn() == null)
            return false;
        if (other.getColumn() != null && other.getColumn().equals(this.getColumn()) == false)
            return false;
        if (other.getLimit() == null ^ this.getLimit() == null)
            return false;
        if (other.getLimit() != null && other.getLimit().equals(this.getLimit()) == false)
            return false;
        if (other.getSortByMetrics() == null ^ this.getSortByMetrics() == null)
            return false;
        if (other.getSortByMetrics() != null && other.getSortByMetrics().equals(this.getSortByMetrics()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getColumn() == null) ? 0 : getColumn().hashCode());
        hashCode = prime * hashCode + ((getLimit() == null) ? 0 : getLimit().hashCode());
        hashCode = prime * hashCode + ((getSortByMetrics() == null) ? 0 : getSortByMetrics().hashCode());
        return hashCode;
    }

    @Override
    public BodySectionDynamicCategoryDimensionConfiguration clone() {
        try {
            return (BodySectionDynamicCategoryDimensionConfiguration) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.quicksight.model.transform.BodySectionDynamicCategoryDimensionConfigurationMarshaller.getInstance().marshall(this,
                protocolMarshaller);
    }
}
