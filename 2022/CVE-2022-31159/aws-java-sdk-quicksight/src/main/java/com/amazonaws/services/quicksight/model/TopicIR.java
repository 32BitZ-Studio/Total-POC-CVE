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
 * The definition for a <code>TopicIR</code>.
 * </p>
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/quicksight-2018-04-01/TopicIR" target="_top">AWS API
 *      Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class TopicIR implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * The metrics for the <code>TopicIR</code>.
     * </p>
     */
    private java.util.List<TopicIRMetric> metrics;
    /**
     * <p>
     * The GroupBy list for the <code>TopicIR</code>.
     * </p>
     */
    private java.util.List<TopicIRGroupBy> groupByList;
    /**
     * <p>
     * The filters for the <code>TopicIR</code>.
     * </p>
     */
    private java.util.List<java.util.List<TopicIRFilterOption>> filters;
    /**
     * <p>
     * The sort for the <code>TopicIR</code>.
     * </p>
     */
    private TopicSortClause sort;
    /**
     * <p>
     * The contribution analysis for the <code>TopicIR</code>.
     * </p>
     */
    private TopicIRContributionAnalysis contributionAnalysis;
    /**
     * <p>
     * The visual for the <code>TopicIR</code>.
     * </p>
     */
    private VisualOptions visual;

    /**
     * <p>
     * The metrics for the <code>TopicIR</code>.
     * </p>
     * 
     * @return The metrics for the <code>TopicIR</code>.
     */

    public java.util.List<TopicIRMetric> getMetrics() {
        return metrics;
    }

    /**
     * <p>
     * The metrics for the <code>TopicIR</code>.
     * </p>
     * 
     * @param metrics
     *        The metrics for the <code>TopicIR</code>.
     */

    public void setMetrics(java.util.Collection<TopicIRMetric> metrics) {
        if (metrics == null) {
            this.metrics = null;
            return;
        }

        this.metrics = new java.util.ArrayList<TopicIRMetric>(metrics);
    }

    /**
     * <p>
     * The metrics for the <code>TopicIR</code>.
     * </p>
     * <p>
     * <b>NOTE:</b> This method appends the values to the existing list (if any). Use
     * {@link #setMetrics(java.util.Collection)} or {@link #withMetrics(java.util.Collection)} if you want to override
     * the existing values.
     * </p>
     * 
     * @param metrics
     *        The metrics for the <code>TopicIR</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public TopicIR withMetrics(TopicIRMetric... metrics) {
        if (this.metrics == null) {
            setMetrics(new java.util.ArrayList<TopicIRMetric>(metrics.length));
        }
        for (TopicIRMetric ele : metrics) {
            this.metrics.add(ele);
        }
        return this;
    }

    /**
     * <p>
     * The metrics for the <code>TopicIR</code>.
     * </p>
     * 
     * @param metrics
     *        The metrics for the <code>TopicIR</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public TopicIR withMetrics(java.util.Collection<TopicIRMetric> metrics) {
        setMetrics(metrics);
        return this;
    }

    /**
     * <p>
     * The GroupBy list for the <code>TopicIR</code>.
     * </p>
     * 
     * @return The GroupBy list for the <code>TopicIR</code>.
     */

    public java.util.List<TopicIRGroupBy> getGroupByList() {
        return groupByList;
    }

    /**
     * <p>
     * The GroupBy list for the <code>TopicIR</code>.
     * </p>
     * 
     * @param groupByList
     *        The GroupBy list for the <code>TopicIR</code>.
     */

    public void setGroupByList(java.util.Collection<TopicIRGroupBy> groupByList) {
        if (groupByList == null) {
            this.groupByList = null;
            return;
        }

        this.groupByList = new java.util.ArrayList<TopicIRGroupBy>(groupByList);
    }

    /**
     * <p>
     * The GroupBy list for the <code>TopicIR</code>.
     * </p>
     * <p>
     * <b>NOTE:</b> This method appends the values to the existing list (if any). Use
     * {@link #setGroupByList(java.util.Collection)} or {@link #withGroupByList(java.util.Collection)} if you want to
     * override the existing values.
     * </p>
     * 
     * @param groupByList
     *        The GroupBy list for the <code>TopicIR</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public TopicIR withGroupByList(TopicIRGroupBy... groupByList) {
        if (this.groupByList == null) {
            setGroupByList(new java.util.ArrayList<TopicIRGroupBy>(groupByList.length));
        }
        for (TopicIRGroupBy ele : groupByList) {
            this.groupByList.add(ele);
        }
        return this;
    }

    /**
     * <p>
     * The GroupBy list for the <code>TopicIR</code>.
     * </p>
     * 
     * @param groupByList
     *        The GroupBy list for the <code>TopicIR</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public TopicIR withGroupByList(java.util.Collection<TopicIRGroupBy> groupByList) {
        setGroupByList(groupByList);
        return this;
    }

    /**
     * <p>
     * The filters for the <code>TopicIR</code>.
     * </p>
     * 
     * @return The filters for the <code>TopicIR</code>.
     */

    public java.util.List<java.util.List<TopicIRFilterOption>> getFilters() {
        return filters;
    }

    /**
     * <p>
     * The filters for the <code>TopicIR</code>.
     * </p>
     * 
     * @param filters
     *        The filters for the <code>TopicIR</code>.
     */

    public void setFilters(java.util.Collection<java.util.List<TopicIRFilterOption>> filters) {
        if (filters == null) {
            this.filters = null;
            return;
        }

        this.filters = new java.util.ArrayList<java.util.List<TopicIRFilterOption>>(filters);
    }

    /**
     * <p>
     * The filters for the <code>TopicIR</code>.
     * </p>
     * <p>
     * <b>NOTE:</b> This method appends the values to the existing list (if any). Use
     * {@link #setFilters(java.util.Collection)} or {@link #withFilters(java.util.Collection)} if you want to override
     * the existing values.
     * </p>
     * 
     * @param filters
     *        The filters for the <code>TopicIR</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public TopicIR withFilters(java.util.List<TopicIRFilterOption>... filters) {
        if (this.filters == null) {
            setFilters(new java.util.ArrayList<java.util.List<TopicIRFilterOption>>(filters.length));
        }
        for (java.util.List<TopicIRFilterOption> ele : filters) {
            this.filters.add(ele);
        }
        return this;
    }

    /**
     * <p>
     * The filters for the <code>TopicIR</code>.
     * </p>
     * 
     * @param filters
     *        The filters for the <code>TopicIR</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public TopicIR withFilters(java.util.Collection<java.util.List<TopicIRFilterOption>> filters) {
        setFilters(filters);
        return this;
    }

    /**
     * <p>
     * The sort for the <code>TopicIR</code>.
     * </p>
     * 
     * @param sort
     *        The sort for the <code>TopicIR</code>.
     */

    public void setSort(TopicSortClause sort) {
        this.sort = sort;
    }

    /**
     * <p>
     * The sort for the <code>TopicIR</code>.
     * </p>
     * 
     * @return The sort for the <code>TopicIR</code>.
     */

    public TopicSortClause getSort() {
        return this.sort;
    }

    /**
     * <p>
     * The sort for the <code>TopicIR</code>.
     * </p>
     * 
     * @param sort
     *        The sort for the <code>TopicIR</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public TopicIR withSort(TopicSortClause sort) {
        setSort(sort);
        return this;
    }

    /**
     * <p>
     * The contribution analysis for the <code>TopicIR</code>.
     * </p>
     * 
     * @param contributionAnalysis
     *        The contribution analysis for the <code>TopicIR</code>.
     */

    public void setContributionAnalysis(TopicIRContributionAnalysis contributionAnalysis) {
        this.contributionAnalysis = contributionAnalysis;
    }

    /**
     * <p>
     * The contribution analysis for the <code>TopicIR</code>.
     * </p>
     * 
     * @return The contribution analysis for the <code>TopicIR</code>.
     */

    public TopicIRContributionAnalysis getContributionAnalysis() {
        return this.contributionAnalysis;
    }

    /**
     * <p>
     * The contribution analysis for the <code>TopicIR</code>.
     * </p>
     * 
     * @param contributionAnalysis
     *        The contribution analysis for the <code>TopicIR</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public TopicIR withContributionAnalysis(TopicIRContributionAnalysis contributionAnalysis) {
        setContributionAnalysis(contributionAnalysis);
        return this;
    }

    /**
     * <p>
     * The visual for the <code>TopicIR</code>.
     * </p>
     * 
     * @param visual
     *        The visual for the <code>TopicIR</code>.
     */

    public void setVisual(VisualOptions visual) {
        this.visual = visual;
    }

    /**
     * <p>
     * The visual for the <code>TopicIR</code>.
     * </p>
     * 
     * @return The visual for the <code>TopicIR</code>.
     */

    public VisualOptions getVisual() {
        return this.visual;
    }

    /**
     * <p>
     * The visual for the <code>TopicIR</code>.
     * </p>
     * 
     * @param visual
     *        The visual for the <code>TopicIR</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public TopicIR withVisual(VisualOptions visual) {
        setVisual(visual);
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
        if (getMetrics() != null)
            sb.append("Metrics: ").append(getMetrics()).append(",");
        if (getGroupByList() != null)
            sb.append("GroupByList: ").append(getGroupByList()).append(",");
        if (getFilters() != null)
            sb.append("Filters: ").append(getFilters()).append(",");
        if (getSort() != null)
            sb.append("Sort: ").append(getSort()).append(",");
        if (getContributionAnalysis() != null)
            sb.append("ContributionAnalysis: ").append(getContributionAnalysis()).append(",");
        if (getVisual() != null)
            sb.append("Visual: ").append(getVisual());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof TopicIR == false)
            return false;
        TopicIR other = (TopicIR) obj;
        if (other.getMetrics() == null ^ this.getMetrics() == null)
            return false;
        if (other.getMetrics() != null && other.getMetrics().equals(this.getMetrics()) == false)
            return false;
        if (other.getGroupByList() == null ^ this.getGroupByList() == null)
            return false;
        if (other.getGroupByList() != null && other.getGroupByList().equals(this.getGroupByList()) == false)
            return false;
        if (other.getFilters() == null ^ this.getFilters() == null)
            return false;
        if (other.getFilters() != null && other.getFilters().equals(this.getFilters()) == false)
            return false;
        if (other.getSort() == null ^ this.getSort() == null)
            return false;
        if (other.getSort() != null && other.getSort().equals(this.getSort()) == false)
            return false;
        if (other.getContributionAnalysis() == null ^ this.getContributionAnalysis() == null)
            return false;
        if (other.getContributionAnalysis() != null && other.getContributionAnalysis().equals(this.getContributionAnalysis()) == false)
            return false;
        if (other.getVisual() == null ^ this.getVisual() == null)
            return false;
        if (other.getVisual() != null && other.getVisual().equals(this.getVisual()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getMetrics() == null) ? 0 : getMetrics().hashCode());
        hashCode = prime * hashCode + ((getGroupByList() == null) ? 0 : getGroupByList().hashCode());
        hashCode = prime * hashCode + ((getFilters() == null) ? 0 : getFilters().hashCode());
        hashCode = prime * hashCode + ((getSort() == null) ? 0 : getSort().hashCode());
        hashCode = prime * hashCode + ((getContributionAnalysis() == null) ? 0 : getContributionAnalysis().hashCode());
        hashCode = prime * hashCode + ((getVisual() == null) ? 0 : getVisual().hashCode());
        return hashCode;
    }

    @Override
    public TopicIR clone() {
        try {
            return (TopicIR) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.quicksight.model.transform.TopicIRMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
