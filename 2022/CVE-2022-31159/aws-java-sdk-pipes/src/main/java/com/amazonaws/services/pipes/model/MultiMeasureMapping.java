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
package com.amazonaws.services.pipes.model;

import java.io.Serializable;
import javax.annotation.Generated;
import com.amazonaws.protocol.StructuredPojo;
import com.amazonaws.protocol.ProtocolMarshaller;

/**
 * <p>
 * Maps multiple measures from the source event to the same Timestream for LiveAnalytics record.
 * </p>
 * <p>
 * For more information, see <a href="https://docs.aws.amazon.com/timestream/latest/developerguide/concepts.html">Amazon
 * Timestream for LiveAnalytics concepts</a>
 * </p>
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/pipes-2015-10-07/MultiMeasureMapping" target="_top">AWS API
 *      Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class MultiMeasureMapping implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * The name of the multiple measurements per record (multi-measure).
     * </p>
     */
    private String multiMeasureName;
    /**
     * <p>
     * Mappings that represent multiple source event fields mapped to measures in the same Timestream for LiveAnalytics
     * record.
     * </p>
     */
    private java.util.List<MultiMeasureAttributeMapping> multiMeasureAttributeMappings;

    /**
     * <p>
     * The name of the multiple measurements per record (multi-measure).
     * </p>
     * 
     * @param multiMeasureName
     *        The name of the multiple measurements per record (multi-measure).
     */

    public void setMultiMeasureName(String multiMeasureName) {
        this.multiMeasureName = multiMeasureName;
    }

    /**
     * <p>
     * The name of the multiple measurements per record (multi-measure).
     * </p>
     * 
     * @return The name of the multiple measurements per record (multi-measure).
     */

    public String getMultiMeasureName() {
        return this.multiMeasureName;
    }

    /**
     * <p>
     * The name of the multiple measurements per record (multi-measure).
     * </p>
     * 
     * @param multiMeasureName
     *        The name of the multiple measurements per record (multi-measure).
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public MultiMeasureMapping withMultiMeasureName(String multiMeasureName) {
        setMultiMeasureName(multiMeasureName);
        return this;
    }

    /**
     * <p>
     * Mappings that represent multiple source event fields mapped to measures in the same Timestream for LiveAnalytics
     * record.
     * </p>
     * 
     * @return Mappings that represent multiple source event fields mapped to measures in the same Timestream for
     *         LiveAnalytics record.
     */

    public java.util.List<MultiMeasureAttributeMapping> getMultiMeasureAttributeMappings() {
        return multiMeasureAttributeMappings;
    }

    /**
     * <p>
     * Mappings that represent multiple source event fields mapped to measures in the same Timestream for LiveAnalytics
     * record.
     * </p>
     * 
     * @param multiMeasureAttributeMappings
     *        Mappings that represent multiple source event fields mapped to measures in the same Timestream for
     *        LiveAnalytics record.
     */

    public void setMultiMeasureAttributeMappings(java.util.Collection<MultiMeasureAttributeMapping> multiMeasureAttributeMappings) {
        if (multiMeasureAttributeMappings == null) {
            this.multiMeasureAttributeMappings = null;
            return;
        }

        this.multiMeasureAttributeMappings = new java.util.ArrayList<MultiMeasureAttributeMapping>(multiMeasureAttributeMappings);
    }

    /**
     * <p>
     * Mappings that represent multiple source event fields mapped to measures in the same Timestream for LiveAnalytics
     * record.
     * </p>
     * <p>
     * <b>NOTE:</b> This method appends the values to the existing list (if any). Use
     * {@link #setMultiMeasureAttributeMappings(java.util.Collection)} or
     * {@link #withMultiMeasureAttributeMappings(java.util.Collection)} if you want to override the existing values.
     * </p>
     * 
     * @param multiMeasureAttributeMappings
     *        Mappings that represent multiple source event fields mapped to measures in the same Timestream for
     *        LiveAnalytics record.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public MultiMeasureMapping withMultiMeasureAttributeMappings(MultiMeasureAttributeMapping... multiMeasureAttributeMappings) {
        if (this.multiMeasureAttributeMappings == null) {
            setMultiMeasureAttributeMappings(new java.util.ArrayList<MultiMeasureAttributeMapping>(multiMeasureAttributeMappings.length));
        }
        for (MultiMeasureAttributeMapping ele : multiMeasureAttributeMappings) {
            this.multiMeasureAttributeMappings.add(ele);
        }
        return this;
    }

    /**
     * <p>
     * Mappings that represent multiple source event fields mapped to measures in the same Timestream for LiveAnalytics
     * record.
     * </p>
     * 
     * @param multiMeasureAttributeMappings
     *        Mappings that represent multiple source event fields mapped to measures in the same Timestream for
     *        LiveAnalytics record.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public MultiMeasureMapping withMultiMeasureAttributeMappings(java.util.Collection<MultiMeasureAttributeMapping> multiMeasureAttributeMappings) {
        setMultiMeasureAttributeMappings(multiMeasureAttributeMappings);
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
        if (getMultiMeasureName() != null)
            sb.append("MultiMeasureName: ").append(getMultiMeasureName()).append(",");
        if (getMultiMeasureAttributeMappings() != null)
            sb.append("MultiMeasureAttributeMappings: ").append(getMultiMeasureAttributeMappings());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof MultiMeasureMapping == false)
            return false;
        MultiMeasureMapping other = (MultiMeasureMapping) obj;
        if (other.getMultiMeasureName() == null ^ this.getMultiMeasureName() == null)
            return false;
        if (other.getMultiMeasureName() != null && other.getMultiMeasureName().equals(this.getMultiMeasureName()) == false)
            return false;
        if (other.getMultiMeasureAttributeMappings() == null ^ this.getMultiMeasureAttributeMappings() == null)
            return false;
        if (other.getMultiMeasureAttributeMappings() != null
                && other.getMultiMeasureAttributeMappings().equals(this.getMultiMeasureAttributeMappings()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getMultiMeasureName() == null) ? 0 : getMultiMeasureName().hashCode());
        hashCode = prime * hashCode + ((getMultiMeasureAttributeMappings() == null) ? 0 : getMultiMeasureAttributeMappings().hashCode());
        return hashCode;
    }

    @Override
    public MultiMeasureMapping clone() {
        try {
            return (MultiMeasureMapping) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.pipes.model.transform.MultiMeasureMappingMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
