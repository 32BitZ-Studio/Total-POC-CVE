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
 * Describes the configurations that are required to declare a section as repeating.
 * </p>
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/quicksight-2018-04-01/BodySectionRepeatConfiguration"
 *      target="_top">AWS API Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class BodySectionRepeatConfiguration implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * List of <code>BodySectionRepeatDimensionConfiguration</code> values that describe the dataset column and
     * constraints for the column used to repeat the contents of a section.
     * </p>
     */
    private java.util.List<BodySectionRepeatDimensionConfiguration> dimensionConfigurations;
    /**
     * <p>
     * Page break configuration to apply for each repeating instance.
     * </p>
     */
    private BodySectionRepeatPageBreakConfiguration pageBreakConfiguration;
    /**
     * <p>
     * List of visuals to exclude from repetition in repeating sections. The visuals will render identically, and ignore
     * the repeating configurations in all repeating instances.
     * </p>
     */
    private java.util.List<String> nonRepeatingVisuals;

    /**
     * <p>
     * List of <code>BodySectionRepeatDimensionConfiguration</code> values that describe the dataset column and
     * constraints for the column used to repeat the contents of a section.
     * </p>
     * 
     * @return List of <code>BodySectionRepeatDimensionConfiguration</code> values that describe the dataset column and
     *         constraints for the column used to repeat the contents of a section.
     */

    public java.util.List<BodySectionRepeatDimensionConfiguration> getDimensionConfigurations() {
        return dimensionConfigurations;
    }

    /**
     * <p>
     * List of <code>BodySectionRepeatDimensionConfiguration</code> values that describe the dataset column and
     * constraints for the column used to repeat the contents of a section.
     * </p>
     * 
     * @param dimensionConfigurations
     *        List of <code>BodySectionRepeatDimensionConfiguration</code> values that describe the dataset column and
     *        constraints for the column used to repeat the contents of a section.
     */

    public void setDimensionConfigurations(java.util.Collection<BodySectionRepeatDimensionConfiguration> dimensionConfigurations) {
        if (dimensionConfigurations == null) {
            this.dimensionConfigurations = null;
            return;
        }

        this.dimensionConfigurations = new java.util.ArrayList<BodySectionRepeatDimensionConfiguration>(dimensionConfigurations);
    }

    /**
     * <p>
     * List of <code>BodySectionRepeatDimensionConfiguration</code> values that describe the dataset column and
     * constraints for the column used to repeat the contents of a section.
     * </p>
     * <p>
     * <b>NOTE:</b> This method appends the values to the existing list (if any). Use
     * {@link #setDimensionConfigurations(java.util.Collection)} or
     * {@link #withDimensionConfigurations(java.util.Collection)} if you want to override the existing values.
     * </p>
     * 
     * @param dimensionConfigurations
     *        List of <code>BodySectionRepeatDimensionConfiguration</code> values that describe the dataset column and
     *        constraints for the column used to repeat the contents of a section.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public BodySectionRepeatConfiguration withDimensionConfigurations(BodySectionRepeatDimensionConfiguration... dimensionConfigurations) {
        if (this.dimensionConfigurations == null) {
            setDimensionConfigurations(new java.util.ArrayList<BodySectionRepeatDimensionConfiguration>(dimensionConfigurations.length));
        }
        for (BodySectionRepeatDimensionConfiguration ele : dimensionConfigurations) {
            this.dimensionConfigurations.add(ele);
        }
        return this;
    }

    /**
     * <p>
     * List of <code>BodySectionRepeatDimensionConfiguration</code> values that describe the dataset column and
     * constraints for the column used to repeat the contents of a section.
     * </p>
     * 
     * @param dimensionConfigurations
     *        List of <code>BodySectionRepeatDimensionConfiguration</code> values that describe the dataset column and
     *        constraints for the column used to repeat the contents of a section.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public BodySectionRepeatConfiguration withDimensionConfigurations(java.util.Collection<BodySectionRepeatDimensionConfiguration> dimensionConfigurations) {
        setDimensionConfigurations(dimensionConfigurations);
        return this;
    }

    /**
     * <p>
     * Page break configuration to apply for each repeating instance.
     * </p>
     * 
     * @param pageBreakConfiguration
     *        Page break configuration to apply for each repeating instance.
     */

    public void setPageBreakConfiguration(BodySectionRepeatPageBreakConfiguration pageBreakConfiguration) {
        this.pageBreakConfiguration = pageBreakConfiguration;
    }

    /**
     * <p>
     * Page break configuration to apply for each repeating instance.
     * </p>
     * 
     * @return Page break configuration to apply for each repeating instance.
     */

    public BodySectionRepeatPageBreakConfiguration getPageBreakConfiguration() {
        return this.pageBreakConfiguration;
    }

    /**
     * <p>
     * Page break configuration to apply for each repeating instance.
     * </p>
     * 
     * @param pageBreakConfiguration
     *        Page break configuration to apply for each repeating instance.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public BodySectionRepeatConfiguration withPageBreakConfiguration(BodySectionRepeatPageBreakConfiguration pageBreakConfiguration) {
        setPageBreakConfiguration(pageBreakConfiguration);
        return this;
    }

    /**
     * <p>
     * List of visuals to exclude from repetition in repeating sections. The visuals will render identically, and ignore
     * the repeating configurations in all repeating instances.
     * </p>
     * 
     * @return List of visuals to exclude from repetition in repeating sections. The visuals will render identically,
     *         and ignore the repeating configurations in all repeating instances.
     */

    public java.util.List<String> getNonRepeatingVisuals() {
        return nonRepeatingVisuals;
    }

    /**
     * <p>
     * List of visuals to exclude from repetition in repeating sections. The visuals will render identically, and ignore
     * the repeating configurations in all repeating instances.
     * </p>
     * 
     * @param nonRepeatingVisuals
     *        List of visuals to exclude from repetition in repeating sections. The visuals will render identically, and
     *        ignore the repeating configurations in all repeating instances.
     */

    public void setNonRepeatingVisuals(java.util.Collection<String> nonRepeatingVisuals) {
        if (nonRepeatingVisuals == null) {
            this.nonRepeatingVisuals = null;
            return;
        }

        this.nonRepeatingVisuals = new java.util.ArrayList<String>(nonRepeatingVisuals);
    }

    /**
     * <p>
     * List of visuals to exclude from repetition in repeating sections. The visuals will render identically, and ignore
     * the repeating configurations in all repeating instances.
     * </p>
     * <p>
     * <b>NOTE:</b> This method appends the values to the existing list (if any). Use
     * {@link #setNonRepeatingVisuals(java.util.Collection)} or {@link #withNonRepeatingVisuals(java.util.Collection)}
     * if you want to override the existing values.
     * </p>
     * 
     * @param nonRepeatingVisuals
     *        List of visuals to exclude from repetition in repeating sections. The visuals will render identically, and
     *        ignore the repeating configurations in all repeating instances.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public BodySectionRepeatConfiguration withNonRepeatingVisuals(String... nonRepeatingVisuals) {
        if (this.nonRepeatingVisuals == null) {
            setNonRepeatingVisuals(new java.util.ArrayList<String>(nonRepeatingVisuals.length));
        }
        for (String ele : nonRepeatingVisuals) {
            this.nonRepeatingVisuals.add(ele);
        }
        return this;
    }

    /**
     * <p>
     * List of visuals to exclude from repetition in repeating sections. The visuals will render identically, and ignore
     * the repeating configurations in all repeating instances.
     * </p>
     * 
     * @param nonRepeatingVisuals
     *        List of visuals to exclude from repetition in repeating sections. The visuals will render identically, and
     *        ignore the repeating configurations in all repeating instances.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public BodySectionRepeatConfiguration withNonRepeatingVisuals(java.util.Collection<String> nonRepeatingVisuals) {
        setNonRepeatingVisuals(nonRepeatingVisuals);
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
        if (getDimensionConfigurations() != null)
            sb.append("DimensionConfigurations: ").append(getDimensionConfigurations()).append(",");
        if (getPageBreakConfiguration() != null)
            sb.append("PageBreakConfiguration: ").append(getPageBreakConfiguration()).append(",");
        if (getNonRepeatingVisuals() != null)
            sb.append("NonRepeatingVisuals: ").append(getNonRepeatingVisuals());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof BodySectionRepeatConfiguration == false)
            return false;
        BodySectionRepeatConfiguration other = (BodySectionRepeatConfiguration) obj;
        if (other.getDimensionConfigurations() == null ^ this.getDimensionConfigurations() == null)
            return false;
        if (other.getDimensionConfigurations() != null && other.getDimensionConfigurations().equals(this.getDimensionConfigurations()) == false)
            return false;
        if (other.getPageBreakConfiguration() == null ^ this.getPageBreakConfiguration() == null)
            return false;
        if (other.getPageBreakConfiguration() != null && other.getPageBreakConfiguration().equals(this.getPageBreakConfiguration()) == false)
            return false;
        if (other.getNonRepeatingVisuals() == null ^ this.getNonRepeatingVisuals() == null)
            return false;
        if (other.getNonRepeatingVisuals() != null && other.getNonRepeatingVisuals().equals(this.getNonRepeatingVisuals()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getDimensionConfigurations() == null) ? 0 : getDimensionConfigurations().hashCode());
        hashCode = prime * hashCode + ((getPageBreakConfiguration() == null) ? 0 : getPageBreakConfiguration().hashCode());
        hashCode = prime * hashCode + ((getNonRepeatingVisuals() == null) ? 0 : getNonRepeatingVisuals().hashCode());
        return hashCode;
    }

    @Override
    public BodySectionRepeatConfiguration clone() {
        try {
            return (BodySectionRepeatConfiguration) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.quicksight.model.transform.BodySectionRepeatConfigurationMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
