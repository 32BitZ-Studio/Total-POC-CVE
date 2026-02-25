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
 * The definition for a <code>TopicIRContributionAnalysis</code>.
 * </p>
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/quicksight-2018-04-01/TopicIRContributionAnalysis"
 *      target="_top">AWS API Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class TopicIRContributionAnalysis implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * The factors for a <code>TopicIRContributionAnalysis</code>.
     * </p>
     */
    private java.util.List<ContributionAnalysisFactor> factors;
    /**
     * <p>
     * The time ranges for the <code>TopicIRContributionAnalysis</code>.
     * </p>
     */
    private ContributionAnalysisTimeRanges timeRanges;
    /**
     * <p>
     * The direction for the <code>TopicIRContributionAnalysis</code>.
     * </p>
     */
    private String direction;
    /**
     * <p>
     * The sort type for the <code>TopicIRContributionAnalysis</code>.
     * </p>
     */
    private String sortType;

    /**
     * <p>
     * The factors for a <code>TopicIRContributionAnalysis</code>.
     * </p>
     * 
     * @return The factors for a <code>TopicIRContributionAnalysis</code>.
     */

    public java.util.List<ContributionAnalysisFactor> getFactors() {
        return factors;
    }

    /**
     * <p>
     * The factors for a <code>TopicIRContributionAnalysis</code>.
     * </p>
     * 
     * @param factors
     *        The factors for a <code>TopicIRContributionAnalysis</code>.
     */

    public void setFactors(java.util.Collection<ContributionAnalysisFactor> factors) {
        if (factors == null) {
            this.factors = null;
            return;
        }

        this.factors = new java.util.ArrayList<ContributionAnalysisFactor>(factors);
    }

    /**
     * <p>
     * The factors for a <code>TopicIRContributionAnalysis</code>.
     * </p>
     * <p>
     * <b>NOTE:</b> This method appends the values to the existing list (if any). Use
     * {@link #setFactors(java.util.Collection)} or {@link #withFactors(java.util.Collection)} if you want to override
     * the existing values.
     * </p>
     * 
     * @param factors
     *        The factors for a <code>TopicIRContributionAnalysis</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public TopicIRContributionAnalysis withFactors(ContributionAnalysisFactor... factors) {
        if (this.factors == null) {
            setFactors(new java.util.ArrayList<ContributionAnalysisFactor>(factors.length));
        }
        for (ContributionAnalysisFactor ele : factors) {
            this.factors.add(ele);
        }
        return this;
    }

    /**
     * <p>
     * The factors for a <code>TopicIRContributionAnalysis</code>.
     * </p>
     * 
     * @param factors
     *        The factors for a <code>TopicIRContributionAnalysis</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public TopicIRContributionAnalysis withFactors(java.util.Collection<ContributionAnalysisFactor> factors) {
        setFactors(factors);
        return this;
    }

    /**
     * <p>
     * The time ranges for the <code>TopicIRContributionAnalysis</code>.
     * </p>
     * 
     * @param timeRanges
     *        The time ranges for the <code>TopicIRContributionAnalysis</code>.
     */

    public void setTimeRanges(ContributionAnalysisTimeRanges timeRanges) {
        this.timeRanges = timeRanges;
    }

    /**
     * <p>
     * The time ranges for the <code>TopicIRContributionAnalysis</code>.
     * </p>
     * 
     * @return The time ranges for the <code>TopicIRContributionAnalysis</code>.
     */

    public ContributionAnalysisTimeRanges getTimeRanges() {
        return this.timeRanges;
    }

    /**
     * <p>
     * The time ranges for the <code>TopicIRContributionAnalysis</code>.
     * </p>
     * 
     * @param timeRanges
     *        The time ranges for the <code>TopicIRContributionAnalysis</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public TopicIRContributionAnalysis withTimeRanges(ContributionAnalysisTimeRanges timeRanges) {
        setTimeRanges(timeRanges);
        return this;
    }

    /**
     * <p>
     * The direction for the <code>TopicIRContributionAnalysis</code>.
     * </p>
     * 
     * @param direction
     *        The direction for the <code>TopicIRContributionAnalysis</code>.
     * @see ContributionAnalysisDirection
     */

    public void setDirection(String direction) {
        this.direction = direction;
    }

    /**
     * <p>
     * The direction for the <code>TopicIRContributionAnalysis</code>.
     * </p>
     * 
     * @return The direction for the <code>TopicIRContributionAnalysis</code>.
     * @see ContributionAnalysisDirection
     */

    public String getDirection() {
        return this.direction;
    }

    /**
     * <p>
     * The direction for the <code>TopicIRContributionAnalysis</code>.
     * </p>
     * 
     * @param direction
     *        The direction for the <code>TopicIRContributionAnalysis</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see ContributionAnalysisDirection
     */

    public TopicIRContributionAnalysis withDirection(String direction) {
        setDirection(direction);
        return this;
    }

    /**
     * <p>
     * The direction for the <code>TopicIRContributionAnalysis</code>.
     * </p>
     * 
     * @param direction
     *        The direction for the <code>TopicIRContributionAnalysis</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see ContributionAnalysisDirection
     */

    public TopicIRContributionAnalysis withDirection(ContributionAnalysisDirection direction) {
        this.direction = direction.toString();
        return this;
    }

    /**
     * <p>
     * The sort type for the <code>TopicIRContributionAnalysis</code>.
     * </p>
     * 
     * @param sortType
     *        The sort type for the <code>TopicIRContributionAnalysis</code>.
     * @see ContributionAnalysisSortType
     */

    public void setSortType(String sortType) {
        this.sortType = sortType;
    }

    /**
     * <p>
     * The sort type for the <code>TopicIRContributionAnalysis</code>.
     * </p>
     * 
     * @return The sort type for the <code>TopicIRContributionAnalysis</code>.
     * @see ContributionAnalysisSortType
     */

    public String getSortType() {
        return this.sortType;
    }

    /**
     * <p>
     * The sort type for the <code>TopicIRContributionAnalysis</code>.
     * </p>
     * 
     * @param sortType
     *        The sort type for the <code>TopicIRContributionAnalysis</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see ContributionAnalysisSortType
     */

    public TopicIRContributionAnalysis withSortType(String sortType) {
        setSortType(sortType);
        return this;
    }

    /**
     * <p>
     * The sort type for the <code>TopicIRContributionAnalysis</code>.
     * </p>
     * 
     * @param sortType
     *        The sort type for the <code>TopicIRContributionAnalysis</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see ContributionAnalysisSortType
     */

    public TopicIRContributionAnalysis withSortType(ContributionAnalysisSortType sortType) {
        this.sortType = sortType.toString();
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
        if (getFactors() != null)
            sb.append("Factors: ").append(getFactors()).append(",");
        if (getTimeRanges() != null)
            sb.append("TimeRanges: ").append(getTimeRanges()).append(",");
        if (getDirection() != null)
            sb.append("Direction: ").append(getDirection()).append(",");
        if (getSortType() != null)
            sb.append("SortType: ").append(getSortType());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof TopicIRContributionAnalysis == false)
            return false;
        TopicIRContributionAnalysis other = (TopicIRContributionAnalysis) obj;
        if (other.getFactors() == null ^ this.getFactors() == null)
            return false;
        if (other.getFactors() != null && other.getFactors().equals(this.getFactors()) == false)
            return false;
        if (other.getTimeRanges() == null ^ this.getTimeRanges() == null)
            return false;
        if (other.getTimeRanges() != null && other.getTimeRanges().equals(this.getTimeRanges()) == false)
            return false;
        if (other.getDirection() == null ^ this.getDirection() == null)
            return false;
        if (other.getDirection() != null && other.getDirection().equals(this.getDirection()) == false)
            return false;
        if (other.getSortType() == null ^ this.getSortType() == null)
            return false;
        if (other.getSortType() != null && other.getSortType().equals(this.getSortType()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getFactors() == null) ? 0 : getFactors().hashCode());
        hashCode = prime * hashCode + ((getTimeRanges() == null) ? 0 : getTimeRanges().hashCode());
        hashCode = prime * hashCode + ((getDirection() == null) ? 0 : getDirection().hashCode());
        hashCode = prime * hashCode + ((getSortType() == null) ? 0 : getSortType().hashCode());
        return hashCode;
    }

    @Override
    public TopicIRContributionAnalysis clone() {
        try {
            return (TopicIRContributionAnalysis) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.quicksight.model.transform.TopicIRContributionAnalysisMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
