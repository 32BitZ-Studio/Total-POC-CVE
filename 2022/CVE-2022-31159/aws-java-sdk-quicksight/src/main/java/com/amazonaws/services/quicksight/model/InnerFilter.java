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
 * The <code>InnerFilter</code> defines the subset of data to be used with the <code>NestedFilter</code>.
 * </p>
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/quicksight-2018-04-01/InnerFilter" target="_top">AWS API
 *      Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class InnerFilter implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * A <code>CategoryInnerFilter</code> filters text values for the <code>NestedFilter</code>.
     * </p>
     */
    private CategoryInnerFilter categoryInnerFilter;

    /**
     * <p>
     * A <code>CategoryInnerFilter</code> filters text values for the <code>NestedFilter</code>.
     * </p>
     * 
     * @param categoryInnerFilter
     *        A <code>CategoryInnerFilter</code> filters text values for the <code>NestedFilter</code>.
     */

    public void setCategoryInnerFilter(CategoryInnerFilter categoryInnerFilter) {
        this.categoryInnerFilter = categoryInnerFilter;
    }

    /**
     * <p>
     * A <code>CategoryInnerFilter</code> filters text values for the <code>NestedFilter</code>.
     * </p>
     * 
     * @return A <code>CategoryInnerFilter</code> filters text values for the <code>NestedFilter</code>.
     */

    public CategoryInnerFilter getCategoryInnerFilter() {
        return this.categoryInnerFilter;
    }

    /**
     * <p>
     * A <code>CategoryInnerFilter</code> filters text values for the <code>NestedFilter</code>.
     * </p>
     * 
     * @param categoryInnerFilter
     *        A <code>CategoryInnerFilter</code> filters text values for the <code>NestedFilter</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public InnerFilter withCategoryInnerFilter(CategoryInnerFilter categoryInnerFilter) {
        setCategoryInnerFilter(categoryInnerFilter);
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
        if (getCategoryInnerFilter() != null)
            sb.append("CategoryInnerFilter: ").append(getCategoryInnerFilter());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof InnerFilter == false)
            return false;
        InnerFilter other = (InnerFilter) obj;
        if (other.getCategoryInnerFilter() == null ^ this.getCategoryInnerFilter() == null)
            return false;
        if (other.getCategoryInnerFilter() != null && other.getCategoryInnerFilter().equals(this.getCategoryInnerFilter()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getCategoryInnerFilter() == null) ? 0 : getCategoryInnerFilter().hashCode());
        return hashCode;
    }

    @Override
    public InnerFilter clone() {
        try {
            return (InnerFilter) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.quicksight.model.transform.InnerFilterMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
