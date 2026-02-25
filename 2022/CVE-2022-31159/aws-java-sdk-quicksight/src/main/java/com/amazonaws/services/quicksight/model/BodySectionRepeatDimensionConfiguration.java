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
 * Describes the dataset column and constraints for the dynamic values used to repeat the contents of a section. The
 * dataset column is either <b>Category</b> or <b>Numeric</b> column configuration
 * </p>
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/quicksight-2018-04-01/BodySectionRepeatDimensionConfiguration"
 *      target="_top">AWS API Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class BodySectionRepeatDimensionConfiguration implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * Describes the <b>Category</b> dataset column and constraints around the dynamic values that will be used in
     * repeating the section contents.
     * </p>
     */
    private BodySectionDynamicCategoryDimensionConfiguration dynamicCategoryDimensionConfiguration;
    /**
     * <p>
     * Describes the <b>Numeric</b> dataset column and constraints around the dynamic values used to repeat the contents
     * of a section.
     * </p>
     */
    private BodySectionDynamicNumericDimensionConfiguration dynamicNumericDimensionConfiguration;

    /**
     * <p>
     * Describes the <b>Category</b> dataset column and constraints around the dynamic values that will be used in
     * repeating the section contents.
     * </p>
     * 
     * @param dynamicCategoryDimensionConfiguration
     *        Describes the <b>Category</b> dataset column and constraints around the dynamic values that will be used
     *        in repeating the section contents.
     */

    public void setDynamicCategoryDimensionConfiguration(BodySectionDynamicCategoryDimensionConfiguration dynamicCategoryDimensionConfiguration) {
        this.dynamicCategoryDimensionConfiguration = dynamicCategoryDimensionConfiguration;
    }

    /**
     * <p>
     * Describes the <b>Category</b> dataset column and constraints around the dynamic values that will be used in
     * repeating the section contents.
     * </p>
     * 
     * @return Describes the <b>Category</b> dataset column and constraints around the dynamic values that will be used
     *         in repeating the section contents.
     */

    public BodySectionDynamicCategoryDimensionConfiguration getDynamicCategoryDimensionConfiguration() {
        return this.dynamicCategoryDimensionConfiguration;
    }

    /**
     * <p>
     * Describes the <b>Category</b> dataset column and constraints around the dynamic values that will be used in
     * repeating the section contents.
     * </p>
     * 
     * @param dynamicCategoryDimensionConfiguration
     *        Describes the <b>Category</b> dataset column and constraints around the dynamic values that will be used
     *        in repeating the section contents.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public BodySectionRepeatDimensionConfiguration withDynamicCategoryDimensionConfiguration(
            BodySectionDynamicCategoryDimensionConfiguration dynamicCategoryDimensionConfiguration) {
        setDynamicCategoryDimensionConfiguration(dynamicCategoryDimensionConfiguration);
        return this;
    }

    /**
     * <p>
     * Describes the <b>Numeric</b> dataset column and constraints around the dynamic values used to repeat the contents
     * of a section.
     * </p>
     * 
     * @param dynamicNumericDimensionConfiguration
     *        Describes the <b>Numeric</b> dataset column and constraints around the dynamic values used to repeat the
     *        contents of a section.
     */

    public void setDynamicNumericDimensionConfiguration(BodySectionDynamicNumericDimensionConfiguration dynamicNumericDimensionConfiguration) {
        this.dynamicNumericDimensionConfiguration = dynamicNumericDimensionConfiguration;
    }

    /**
     * <p>
     * Describes the <b>Numeric</b> dataset column and constraints around the dynamic values used to repeat the contents
     * of a section.
     * </p>
     * 
     * @return Describes the <b>Numeric</b> dataset column and constraints around the dynamic values used to repeat the
     *         contents of a section.
     */

    public BodySectionDynamicNumericDimensionConfiguration getDynamicNumericDimensionConfiguration() {
        return this.dynamicNumericDimensionConfiguration;
    }

    /**
     * <p>
     * Describes the <b>Numeric</b> dataset column and constraints around the dynamic values used to repeat the contents
     * of a section.
     * </p>
     * 
     * @param dynamicNumericDimensionConfiguration
     *        Describes the <b>Numeric</b> dataset column and constraints around the dynamic values used to repeat the
     *        contents of a section.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public BodySectionRepeatDimensionConfiguration withDynamicNumericDimensionConfiguration(
            BodySectionDynamicNumericDimensionConfiguration dynamicNumericDimensionConfiguration) {
        setDynamicNumericDimensionConfiguration(dynamicNumericDimensionConfiguration);
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
        if (getDynamicCategoryDimensionConfiguration() != null)
            sb.append("DynamicCategoryDimensionConfiguration: ").append(getDynamicCategoryDimensionConfiguration()).append(",");
        if (getDynamicNumericDimensionConfiguration() != null)
            sb.append("DynamicNumericDimensionConfiguration: ").append(getDynamicNumericDimensionConfiguration());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof BodySectionRepeatDimensionConfiguration == false)
            return false;
        BodySectionRepeatDimensionConfiguration other = (BodySectionRepeatDimensionConfiguration) obj;
        if (other.getDynamicCategoryDimensionConfiguration() == null ^ this.getDynamicCategoryDimensionConfiguration() == null)
            return false;
        if (other.getDynamicCategoryDimensionConfiguration() != null
                && other.getDynamicCategoryDimensionConfiguration().equals(this.getDynamicCategoryDimensionConfiguration()) == false)
            return false;
        if (other.getDynamicNumericDimensionConfiguration() == null ^ this.getDynamicNumericDimensionConfiguration() == null)
            return false;
        if (other.getDynamicNumericDimensionConfiguration() != null
                && other.getDynamicNumericDimensionConfiguration().equals(this.getDynamicNumericDimensionConfiguration()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getDynamicCategoryDimensionConfiguration() == null) ? 0 : getDynamicCategoryDimensionConfiguration().hashCode());
        hashCode = prime * hashCode + ((getDynamicNumericDimensionConfiguration() == null) ? 0 : getDynamicNumericDimensionConfiguration().hashCode());
        return hashCode;
    }

    @Override
    public BodySectionRepeatDimensionConfiguration clone() {
        try {
            return (BodySectionRepeatDimensionConfiguration) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.quicksight.model.transform.BodySectionRepeatDimensionConfigurationMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
