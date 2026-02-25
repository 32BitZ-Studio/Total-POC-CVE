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
 * The definition of a <code>TopicIRComparisonMethod</code>.
 * </p>
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/quicksight-2018-04-01/TopicIRComparisonMethod" target="_top">AWS
 *      API Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class TopicIRComparisonMethod implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * The type for the <code>TopicIRComparisonMethod</code>.
     * </p>
     */
    private String type;
    /**
     * <p>
     * The period for the <code>TopicIRComparisonMethod</code>.
     * </p>
     */
    private String period;
    /**
     * <p>
     * The window size for the <code>TopicIRComparisonMethod</code>.
     * </p>
     */
    private Integer windowSize;

    /**
     * <p>
     * The type for the <code>TopicIRComparisonMethod</code>.
     * </p>
     * 
     * @param type
     *        The type for the <code>TopicIRComparisonMethod</code>.
     * @see ComparisonMethodType
     */

    public void setType(String type) {
        this.type = type;
    }

    /**
     * <p>
     * The type for the <code>TopicIRComparisonMethod</code>.
     * </p>
     * 
     * @return The type for the <code>TopicIRComparisonMethod</code>.
     * @see ComparisonMethodType
     */

    public String getType() {
        return this.type;
    }

    /**
     * <p>
     * The type for the <code>TopicIRComparisonMethod</code>.
     * </p>
     * 
     * @param type
     *        The type for the <code>TopicIRComparisonMethod</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see ComparisonMethodType
     */

    public TopicIRComparisonMethod withType(String type) {
        setType(type);
        return this;
    }

    /**
     * <p>
     * The type for the <code>TopicIRComparisonMethod</code>.
     * </p>
     * 
     * @param type
     *        The type for the <code>TopicIRComparisonMethod</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see ComparisonMethodType
     */

    public TopicIRComparisonMethod withType(ComparisonMethodType type) {
        this.type = type.toString();
        return this;
    }

    /**
     * <p>
     * The period for the <code>TopicIRComparisonMethod</code>.
     * </p>
     * 
     * @param period
     *        The period for the <code>TopicIRComparisonMethod</code>.
     * @see TopicTimeGranularity
     */

    public void setPeriod(String period) {
        this.period = period;
    }

    /**
     * <p>
     * The period for the <code>TopicIRComparisonMethod</code>.
     * </p>
     * 
     * @return The period for the <code>TopicIRComparisonMethod</code>.
     * @see TopicTimeGranularity
     */

    public String getPeriod() {
        return this.period;
    }

    /**
     * <p>
     * The period for the <code>TopicIRComparisonMethod</code>.
     * </p>
     * 
     * @param period
     *        The period for the <code>TopicIRComparisonMethod</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see TopicTimeGranularity
     */

    public TopicIRComparisonMethod withPeriod(String period) {
        setPeriod(period);
        return this;
    }

    /**
     * <p>
     * The period for the <code>TopicIRComparisonMethod</code>.
     * </p>
     * 
     * @param period
     *        The period for the <code>TopicIRComparisonMethod</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see TopicTimeGranularity
     */

    public TopicIRComparisonMethod withPeriod(TopicTimeGranularity period) {
        this.period = period.toString();
        return this;
    }

    /**
     * <p>
     * The window size for the <code>TopicIRComparisonMethod</code>.
     * </p>
     * 
     * @param windowSize
     *        The window size for the <code>TopicIRComparisonMethod</code>.
     */

    public void setWindowSize(Integer windowSize) {
        this.windowSize = windowSize;
    }

    /**
     * <p>
     * The window size for the <code>TopicIRComparisonMethod</code>.
     * </p>
     * 
     * @return The window size for the <code>TopicIRComparisonMethod</code>.
     */

    public Integer getWindowSize() {
        return this.windowSize;
    }

    /**
     * <p>
     * The window size for the <code>TopicIRComparisonMethod</code>.
     * </p>
     * 
     * @param windowSize
     *        The window size for the <code>TopicIRComparisonMethod</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public TopicIRComparisonMethod withWindowSize(Integer windowSize) {
        setWindowSize(windowSize);
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
        if (getType() != null)
            sb.append("Type: ").append(getType()).append(",");
        if (getPeriod() != null)
            sb.append("Period: ").append(getPeriod()).append(",");
        if (getWindowSize() != null)
            sb.append("WindowSize: ").append(getWindowSize());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof TopicIRComparisonMethod == false)
            return false;
        TopicIRComparisonMethod other = (TopicIRComparisonMethod) obj;
        if (other.getType() == null ^ this.getType() == null)
            return false;
        if (other.getType() != null && other.getType().equals(this.getType()) == false)
            return false;
        if (other.getPeriod() == null ^ this.getPeriod() == null)
            return false;
        if (other.getPeriod() != null && other.getPeriod().equals(this.getPeriod()) == false)
            return false;
        if (other.getWindowSize() == null ^ this.getWindowSize() == null)
            return false;
        if (other.getWindowSize() != null && other.getWindowSize().equals(this.getWindowSize()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getType() == null) ? 0 : getType().hashCode());
        hashCode = prime * hashCode + ((getPeriod() == null) ? 0 : getPeriod().hashCode());
        hashCode = prime * hashCode + ((getWindowSize() == null) ? 0 : getWindowSize().hashCode());
        return hashCode;
    }

    @Override
    public TopicIRComparisonMethod clone() {
        try {
            return (TopicIRComparisonMethod) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.quicksight.model.transform.TopicIRComparisonMethodMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
