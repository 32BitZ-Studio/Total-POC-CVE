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
 * A <code>CategoryInnerFilter</code> filters text values for the <code>NestedFilter</code>.
 * </p>
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/quicksight-2018-04-01/CategoryInnerFilter" target="_top">AWS API
 *      Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class CategoryInnerFilter implements Serializable, Cloneable, StructuredPojo {

    private ColumnIdentifier column;

    private CategoryFilterConfiguration configuration;

    private DefaultFilterControlConfiguration defaultFilterControlConfiguration;

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

    public CategoryInnerFilter withColumn(ColumnIdentifier column) {
        setColumn(column);
        return this;
    }

    /**
     * @param configuration
     */

    public void setConfiguration(CategoryFilterConfiguration configuration) {
        this.configuration = configuration;
    }

    /**
     * @return
     */

    public CategoryFilterConfiguration getConfiguration() {
        return this.configuration;
    }

    /**
     * @param configuration
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public CategoryInnerFilter withConfiguration(CategoryFilterConfiguration configuration) {
        setConfiguration(configuration);
        return this;
    }

    /**
     * @param defaultFilterControlConfiguration
     */

    public void setDefaultFilterControlConfiguration(DefaultFilterControlConfiguration defaultFilterControlConfiguration) {
        this.defaultFilterControlConfiguration = defaultFilterControlConfiguration;
    }

    /**
     * @return
     */

    public DefaultFilterControlConfiguration getDefaultFilterControlConfiguration() {
        return this.defaultFilterControlConfiguration;
    }

    /**
     * @param defaultFilterControlConfiguration
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public CategoryInnerFilter withDefaultFilterControlConfiguration(DefaultFilterControlConfiguration defaultFilterControlConfiguration) {
        setDefaultFilterControlConfiguration(defaultFilterControlConfiguration);
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
        if (getConfiguration() != null)
            sb.append("Configuration: ").append(getConfiguration()).append(",");
        if (getDefaultFilterControlConfiguration() != null)
            sb.append("DefaultFilterControlConfiguration: ").append(getDefaultFilterControlConfiguration());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof CategoryInnerFilter == false)
            return false;
        CategoryInnerFilter other = (CategoryInnerFilter) obj;
        if (other.getColumn() == null ^ this.getColumn() == null)
            return false;
        if (other.getColumn() != null && other.getColumn().equals(this.getColumn()) == false)
            return false;
        if (other.getConfiguration() == null ^ this.getConfiguration() == null)
            return false;
        if (other.getConfiguration() != null && other.getConfiguration().equals(this.getConfiguration()) == false)
            return false;
        if (other.getDefaultFilterControlConfiguration() == null ^ this.getDefaultFilterControlConfiguration() == null)
            return false;
        if (other.getDefaultFilterControlConfiguration() != null
                && other.getDefaultFilterControlConfiguration().equals(this.getDefaultFilterControlConfiguration()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getColumn() == null) ? 0 : getColumn().hashCode());
        hashCode = prime * hashCode + ((getConfiguration() == null) ? 0 : getConfiguration().hashCode());
        hashCode = prime * hashCode + ((getDefaultFilterControlConfiguration() == null) ? 0 : getDefaultFilterControlConfiguration().hashCode());
        return hashCode;
    }

    @Override
    public CategoryInnerFilter clone() {
        try {
            return (CategoryInnerFilter) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.quicksight.model.transform.CategoryInnerFilterMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
