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
 * The definition for the <code>ContributionAnalysisTimeRanges</code>.
 * </p>
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/quicksight-2018-04-01/ContributionAnalysisTimeRanges"
 *      target="_top">AWS API Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class ContributionAnalysisTimeRanges implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * The start range for the <code>ContributionAnalysisTimeRanges</code>.
     * </p>
     */
    private TopicIRFilterOption startRange;
    /**
     * <p>
     * The end range for the <code>ContributionAnalysisTimeRanges</code>.
     * </p>
     */
    private TopicIRFilterOption endRange;

    /**
     * <p>
     * The start range for the <code>ContributionAnalysisTimeRanges</code>.
     * </p>
     * 
     * @param startRange
     *        The start range for the <code>ContributionAnalysisTimeRanges</code>.
     */

    public void setStartRange(TopicIRFilterOption startRange) {
        this.startRange = startRange;
    }

    /**
     * <p>
     * The start range for the <code>ContributionAnalysisTimeRanges</code>.
     * </p>
     * 
     * @return The start range for the <code>ContributionAnalysisTimeRanges</code>.
     */

    public TopicIRFilterOption getStartRange() {
        return this.startRange;
    }

    /**
     * <p>
     * The start range for the <code>ContributionAnalysisTimeRanges</code>.
     * </p>
     * 
     * @param startRange
     *        The start range for the <code>ContributionAnalysisTimeRanges</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ContributionAnalysisTimeRanges withStartRange(TopicIRFilterOption startRange) {
        setStartRange(startRange);
        return this;
    }

    /**
     * <p>
     * The end range for the <code>ContributionAnalysisTimeRanges</code>.
     * </p>
     * 
     * @param endRange
     *        The end range for the <code>ContributionAnalysisTimeRanges</code>.
     */

    public void setEndRange(TopicIRFilterOption endRange) {
        this.endRange = endRange;
    }

    /**
     * <p>
     * The end range for the <code>ContributionAnalysisTimeRanges</code>.
     * </p>
     * 
     * @return The end range for the <code>ContributionAnalysisTimeRanges</code>.
     */

    public TopicIRFilterOption getEndRange() {
        return this.endRange;
    }

    /**
     * <p>
     * The end range for the <code>ContributionAnalysisTimeRanges</code>.
     * </p>
     * 
     * @param endRange
     *        The end range for the <code>ContributionAnalysisTimeRanges</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ContributionAnalysisTimeRanges withEndRange(TopicIRFilterOption endRange) {
        setEndRange(endRange);
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
        if (getStartRange() != null)
            sb.append("StartRange: ").append(getStartRange()).append(",");
        if (getEndRange() != null)
            sb.append("EndRange: ").append(getEndRange());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof ContributionAnalysisTimeRanges == false)
            return false;
        ContributionAnalysisTimeRanges other = (ContributionAnalysisTimeRanges) obj;
        if (other.getStartRange() == null ^ this.getStartRange() == null)
            return false;
        if (other.getStartRange() != null && other.getStartRange().equals(this.getStartRange()) == false)
            return false;
        if (other.getEndRange() == null ^ this.getEndRange() == null)
            return false;
        if (other.getEndRange() != null && other.getEndRange().equals(this.getEndRange()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getStartRange() == null) ? 0 : getStartRange().hashCode());
        hashCode = prime * hashCode + ((getEndRange() == null) ? 0 : getEndRange().hashCode());
        return hashCode;
    }

    @Override
    public ContributionAnalysisTimeRanges clone() {
        try {
            return (ContributionAnalysisTimeRanges) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.quicksight.model.transform.ContributionAnalysisTimeRangesMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
