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
package com.amazonaws.services.sagemaker.model;

import java.io.Serializable;
import javax.annotation.Generated;

import com.amazonaws.AmazonWebServiceRequest;

/**
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/sagemaker-2017-07-24/ListOptimizationJobs" target="_top">AWS API
 *      Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class ListOptimizationJobsRequest extends com.amazonaws.AmazonWebServiceRequest implements Serializable, Cloneable {

    /**
     * <p>
     * A token that you use to get the next set of results following a truncated response. If the response to the
     * previous request was truncated, that response provides the value for this token.
     * </p>
     */
    private String nextToken;
    /**
     * <p>
     * The maximum number of optimization jobs to return in the response. The default is 50.
     * </p>
     */
    private Integer maxResults;
    /**
     * <p>
     * Filters the results to only those optimization jobs that were created after the specified time.
     * </p>
     */
    private java.util.Date creationTimeAfter;
    /**
     * <p>
     * Filters the results to only those optimization jobs that were created before the specified time.
     * </p>
     */
    private java.util.Date creationTimeBefore;
    /**
     * <p>
     * Filters the results to only those optimization jobs that were updated after the specified time.
     * </p>
     */
    private java.util.Date lastModifiedTimeAfter;
    /**
     * <p>
     * Filters the results to only those optimization jobs that were updated before the specified time.
     * </p>
     */
    private java.util.Date lastModifiedTimeBefore;
    /**
     * <p>
     * Filters the results to only those optimization jobs that apply the specified optimization techniques. You can
     * specify either <code>Quantization</code> or <code>Compilation</code>.
     * </p>
     */
    private String optimizationContains;
    /**
     * <p>
     * Filters the results to only those optimization jobs with a name that contains the specified string.
     * </p>
     */
    private String nameContains;
    /**
     * <p>
     * Filters the results to only those optimization jobs with the specified status.
     * </p>
     */
    private String statusEquals;
    /**
     * <p>
     * The field by which to sort the optimization jobs in the response. The default is <code>CreationTime</code>
     * </p>
     */
    private String sortBy;
    /**
     * <p>
     * The sort order for results. The default is <code>Ascending</code>
     * </p>
     */
    private String sortOrder;

    /**
     * <p>
     * A token that you use to get the next set of results following a truncated response. If the response to the
     * previous request was truncated, that response provides the value for this token.
     * </p>
     * 
     * @param nextToken
     *        A token that you use to get the next set of results following a truncated response. If the response to the
     *        previous request was truncated, that response provides the value for this token.
     */

    public void setNextToken(String nextToken) {
        this.nextToken = nextToken;
    }

    /**
     * <p>
     * A token that you use to get the next set of results following a truncated response. If the response to the
     * previous request was truncated, that response provides the value for this token.
     * </p>
     * 
     * @return A token that you use to get the next set of results following a truncated response. If the response to
     *         the previous request was truncated, that response provides the value for this token.
     */

    public String getNextToken() {
        return this.nextToken;
    }

    /**
     * <p>
     * A token that you use to get the next set of results following a truncated response. If the response to the
     * previous request was truncated, that response provides the value for this token.
     * </p>
     * 
     * @param nextToken
     *        A token that you use to get the next set of results following a truncated response. If the response to the
     *        previous request was truncated, that response provides the value for this token.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ListOptimizationJobsRequest withNextToken(String nextToken) {
        setNextToken(nextToken);
        return this;
    }

    /**
     * <p>
     * The maximum number of optimization jobs to return in the response. The default is 50.
     * </p>
     * 
     * @param maxResults
     *        The maximum number of optimization jobs to return in the response. The default is 50.
     */

    public void setMaxResults(Integer maxResults) {
        this.maxResults = maxResults;
    }

    /**
     * <p>
     * The maximum number of optimization jobs to return in the response. The default is 50.
     * </p>
     * 
     * @return The maximum number of optimization jobs to return in the response. The default is 50.
     */

    public Integer getMaxResults() {
        return this.maxResults;
    }

    /**
     * <p>
     * The maximum number of optimization jobs to return in the response. The default is 50.
     * </p>
     * 
     * @param maxResults
     *        The maximum number of optimization jobs to return in the response. The default is 50.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ListOptimizationJobsRequest withMaxResults(Integer maxResults) {
        setMaxResults(maxResults);
        return this;
    }

    /**
     * <p>
     * Filters the results to only those optimization jobs that were created after the specified time.
     * </p>
     * 
     * @param creationTimeAfter
     *        Filters the results to only those optimization jobs that were created after the specified time.
     */

    public void setCreationTimeAfter(java.util.Date creationTimeAfter) {
        this.creationTimeAfter = creationTimeAfter;
    }

    /**
     * <p>
     * Filters the results to only those optimization jobs that were created after the specified time.
     * </p>
     * 
     * @return Filters the results to only those optimization jobs that were created after the specified time.
     */

    public java.util.Date getCreationTimeAfter() {
        return this.creationTimeAfter;
    }

    /**
     * <p>
     * Filters the results to only those optimization jobs that were created after the specified time.
     * </p>
     * 
     * @param creationTimeAfter
     *        Filters the results to only those optimization jobs that were created after the specified time.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ListOptimizationJobsRequest withCreationTimeAfter(java.util.Date creationTimeAfter) {
        setCreationTimeAfter(creationTimeAfter);
        return this;
    }

    /**
     * <p>
     * Filters the results to only those optimization jobs that were created before the specified time.
     * </p>
     * 
     * @param creationTimeBefore
     *        Filters the results to only those optimization jobs that were created before the specified time.
     */

    public void setCreationTimeBefore(java.util.Date creationTimeBefore) {
        this.creationTimeBefore = creationTimeBefore;
    }

    /**
     * <p>
     * Filters the results to only those optimization jobs that were created before the specified time.
     * </p>
     * 
     * @return Filters the results to only those optimization jobs that were created before the specified time.
     */

    public java.util.Date getCreationTimeBefore() {
        return this.creationTimeBefore;
    }

    /**
     * <p>
     * Filters the results to only those optimization jobs that were created before the specified time.
     * </p>
     * 
     * @param creationTimeBefore
     *        Filters the results to only those optimization jobs that were created before the specified time.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ListOptimizationJobsRequest withCreationTimeBefore(java.util.Date creationTimeBefore) {
        setCreationTimeBefore(creationTimeBefore);
        return this;
    }

    /**
     * <p>
     * Filters the results to only those optimization jobs that were updated after the specified time.
     * </p>
     * 
     * @param lastModifiedTimeAfter
     *        Filters the results to only those optimization jobs that were updated after the specified time.
     */

    public void setLastModifiedTimeAfter(java.util.Date lastModifiedTimeAfter) {
        this.lastModifiedTimeAfter = lastModifiedTimeAfter;
    }

    /**
     * <p>
     * Filters the results to only those optimization jobs that were updated after the specified time.
     * </p>
     * 
     * @return Filters the results to only those optimization jobs that were updated after the specified time.
     */

    public java.util.Date getLastModifiedTimeAfter() {
        return this.lastModifiedTimeAfter;
    }

    /**
     * <p>
     * Filters the results to only those optimization jobs that were updated after the specified time.
     * </p>
     * 
     * @param lastModifiedTimeAfter
     *        Filters the results to only those optimization jobs that were updated after the specified time.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ListOptimizationJobsRequest withLastModifiedTimeAfter(java.util.Date lastModifiedTimeAfter) {
        setLastModifiedTimeAfter(lastModifiedTimeAfter);
        return this;
    }

    /**
     * <p>
     * Filters the results to only those optimization jobs that were updated before the specified time.
     * </p>
     * 
     * @param lastModifiedTimeBefore
     *        Filters the results to only those optimization jobs that were updated before the specified time.
     */

    public void setLastModifiedTimeBefore(java.util.Date lastModifiedTimeBefore) {
        this.lastModifiedTimeBefore = lastModifiedTimeBefore;
    }

    /**
     * <p>
     * Filters the results to only those optimization jobs that were updated before the specified time.
     * </p>
     * 
     * @return Filters the results to only those optimization jobs that were updated before the specified time.
     */

    public java.util.Date getLastModifiedTimeBefore() {
        return this.lastModifiedTimeBefore;
    }

    /**
     * <p>
     * Filters the results to only those optimization jobs that were updated before the specified time.
     * </p>
     * 
     * @param lastModifiedTimeBefore
     *        Filters the results to only those optimization jobs that were updated before the specified time.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ListOptimizationJobsRequest withLastModifiedTimeBefore(java.util.Date lastModifiedTimeBefore) {
        setLastModifiedTimeBefore(lastModifiedTimeBefore);
        return this;
    }

    /**
     * <p>
     * Filters the results to only those optimization jobs that apply the specified optimization techniques. You can
     * specify either <code>Quantization</code> or <code>Compilation</code>.
     * </p>
     * 
     * @param optimizationContains
     *        Filters the results to only those optimization jobs that apply the specified optimization techniques. You
     *        can specify either <code>Quantization</code> or <code>Compilation</code>.
     */

    public void setOptimizationContains(String optimizationContains) {
        this.optimizationContains = optimizationContains;
    }

    /**
     * <p>
     * Filters the results to only those optimization jobs that apply the specified optimization techniques. You can
     * specify either <code>Quantization</code> or <code>Compilation</code>.
     * </p>
     * 
     * @return Filters the results to only those optimization jobs that apply the specified optimization techniques. You
     *         can specify either <code>Quantization</code> or <code>Compilation</code>.
     */

    public String getOptimizationContains() {
        return this.optimizationContains;
    }

    /**
     * <p>
     * Filters the results to only those optimization jobs that apply the specified optimization techniques. You can
     * specify either <code>Quantization</code> or <code>Compilation</code>.
     * </p>
     * 
     * @param optimizationContains
     *        Filters the results to only those optimization jobs that apply the specified optimization techniques. You
     *        can specify either <code>Quantization</code> or <code>Compilation</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ListOptimizationJobsRequest withOptimizationContains(String optimizationContains) {
        setOptimizationContains(optimizationContains);
        return this;
    }

    /**
     * <p>
     * Filters the results to only those optimization jobs with a name that contains the specified string.
     * </p>
     * 
     * @param nameContains
     *        Filters the results to only those optimization jobs with a name that contains the specified string.
     */

    public void setNameContains(String nameContains) {
        this.nameContains = nameContains;
    }

    /**
     * <p>
     * Filters the results to only those optimization jobs with a name that contains the specified string.
     * </p>
     * 
     * @return Filters the results to only those optimization jobs with a name that contains the specified string.
     */

    public String getNameContains() {
        return this.nameContains;
    }

    /**
     * <p>
     * Filters the results to only those optimization jobs with a name that contains the specified string.
     * </p>
     * 
     * @param nameContains
     *        Filters the results to only those optimization jobs with a name that contains the specified string.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ListOptimizationJobsRequest withNameContains(String nameContains) {
        setNameContains(nameContains);
        return this;
    }

    /**
     * <p>
     * Filters the results to only those optimization jobs with the specified status.
     * </p>
     * 
     * @param statusEquals
     *        Filters the results to only those optimization jobs with the specified status.
     * @see OptimizationJobStatus
     */

    public void setStatusEquals(String statusEquals) {
        this.statusEquals = statusEquals;
    }

    /**
     * <p>
     * Filters the results to only those optimization jobs with the specified status.
     * </p>
     * 
     * @return Filters the results to only those optimization jobs with the specified status.
     * @see OptimizationJobStatus
     */

    public String getStatusEquals() {
        return this.statusEquals;
    }

    /**
     * <p>
     * Filters the results to only those optimization jobs with the specified status.
     * </p>
     * 
     * @param statusEquals
     *        Filters the results to only those optimization jobs with the specified status.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see OptimizationJobStatus
     */

    public ListOptimizationJobsRequest withStatusEquals(String statusEquals) {
        setStatusEquals(statusEquals);
        return this;
    }

    /**
     * <p>
     * Filters the results to only those optimization jobs with the specified status.
     * </p>
     * 
     * @param statusEquals
     *        Filters the results to only those optimization jobs with the specified status.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see OptimizationJobStatus
     */

    public ListOptimizationJobsRequest withStatusEquals(OptimizationJobStatus statusEquals) {
        this.statusEquals = statusEquals.toString();
        return this;
    }

    /**
     * <p>
     * The field by which to sort the optimization jobs in the response. The default is <code>CreationTime</code>
     * </p>
     * 
     * @param sortBy
     *        The field by which to sort the optimization jobs in the response. The default is <code>CreationTime</code>
     * @see ListOptimizationJobsSortBy
     */

    public void setSortBy(String sortBy) {
        this.sortBy = sortBy;
    }

    /**
     * <p>
     * The field by which to sort the optimization jobs in the response. The default is <code>CreationTime</code>
     * </p>
     * 
     * @return The field by which to sort the optimization jobs in the response. The default is
     *         <code>CreationTime</code>
     * @see ListOptimizationJobsSortBy
     */

    public String getSortBy() {
        return this.sortBy;
    }

    /**
     * <p>
     * The field by which to sort the optimization jobs in the response. The default is <code>CreationTime</code>
     * </p>
     * 
     * @param sortBy
     *        The field by which to sort the optimization jobs in the response. The default is <code>CreationTime</code>
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see ListOptimizationJobsSortBy
     */

    public ListOptimizationJobsRequest withSortBy(String sortBy) {
        setSortBy(sortBy);
        return this;
    }

    /**
     * <p>
     * The field by which to sort the optimization jobs in the response. The default is <code>CreationTime</code>
     * </p>
     * 
     * @param sortBy
     *        The field by which to sort the optimization jobs in the response. The default is <code>CreationTime</code>
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see ListOptimizationJobsSortBy
     */

    public ListOptimizationJobsRequest withSortBy(ListOptimizationJobsSortBy sortBy) {
        this.sortBy = sortBy.toString();
        return this;
    }

    /**
     * <p>
     * The sort order for results. The default is <code>Ascending</code>
     * </p>
     * 
     * @param sortOrder
     *        The sort order for results. The default is <code>Ascending</code>
     * @see SortOrder
     */

    public void setSortOrder(String sortOrder) {
        this.sortOrder = sortOrder;
    }

    /**
     * <p>
     * The sort order for results. The default is <code>Ascending</code>
     * </p>
     * 
     * @return The sort order for results. The default is <code>Ascending</code>
     * @see SortOrder
     */

    public String getSortOrder() {
        return this.sortOrder;
    }

    /**
     * <p>
     * The sort order for results. The default is <code>Ascending</code>
     * </p>
     * 
     * @param sortOrder
     *        The sort order for results. The default is <code>Ascending</code>
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see SortOrder
     */

    public ListOptimizationJobsRequest withSortOrder(String sortOrder) {
        setSortOrder(sortOrder);
        return this;
    }

    /**
     * <p>
     * The sort order for results. The default is <code>Ascending</code>
     * </p>
     * 
     * @param sortOrder
     *        The sort order for results. The default is <code>Ascending</code>
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see SortOrder
     */

    public ListOptimizationJobsRequest withSortOrder(SortOrder sortOrder) {
        this.sortOrder = sortOrder.toString();
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
        if (getNextToken() != null)
            sb.append("NextToken: ").append(getNextToken()).append(",");
        if (getMaxResults() != null)
            sb.append("MaxResults: ").append(getMaxResults()).append(",");
        if (getCreationTimeAfter() != null)
            sb.append("CreationTimeAfter: ").append(getCreationTimeAfter()).append(",");
        if (getCreationTimeBefore() != null)
            sb.append("CreationTimeBefore: ").append(getCreationTimeBefore()).append(",");
        if (getLastModifiedTimeAfter() != null)
            sb.append("LastModifiedTimeAfter: ").append(getLastModifiedTimeAfter()).append(",");
        if (getLastModifiedTimeBefore() != null)
            sb.append("LastModifiedTimeBefore: ").append(getLastModifiedTimeBefore()).append(",");
        if (getOptimizationContains() != null)
            sb.append("OptimizationContains: ").append(getOptimizationContains()).append(",");
        if (getNameContains() != null)
            sb.append("NameContains: ").append(getNameContains()).append(",");
        if (getStatusEquals() != null)
            sb.append("StatusEquals: ").append(getStatusEquals()).append(",");
        if (getSortBy() != null)
            sb.append("SortBy: ").append(getSortBy()).append(",");
        if (getSortOrder() != null)
            sb.append("SortOrder: ").append(getSortOrder());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof ListOptimizationJobsRequest == false)
            return false;
        ListOptimizationJobsRequest other = (ListOptimizationJobsRequest) obj;
        if (other.getNextToken() == null ^ this.getNextToken() == null)
            return false;
        if (other.getNextToken() != null && other.getNextToken().equals(this.getNextToken()) == false)
            return false;
        if (other.getMaxResults() == null ^ this.getMaxResults() == null)
            return false;
        if (other.getMaxResults() != null && other.getMaxResults().equals(this.getMaxResults()) == false)
            return false;
        if (other.getCreationTimeAfter() == null ^ this.getCreationTimeAfter() == null)
            return false;
        if (other.getCreationTimeAfter() != null && other.getCreationTimeAfter().equals(this.getCreationTimeAfter()) == false)
            return false;
        if (other.getCreationTimeBefore() == null ^ this.getCreationTimeBefore() == null)
            return false;
        if (other.getCreationTimeBefore() != null && other.getCreationTimeBefore().equals(this.getCreationTimeBefore()) == false)
            return false;
        if (other.getLastModifiedTimeAfter() == null ^ this.getLastModifiedTimeAfter() == null)
            return false;
        if (other.getLastModifiedTimeAfter() != null && other.getLastModifiedTimeAfter().equals(this.getLastModifiedTimeAfter()) == false)
            return false;
        if (other.getLastModifiedTimeBefore() == null ^ this.getLastModifiedTimeBefore() == null)
            return false;
        if (other.getLastModifiedTimeBefore() != null && other.getLastModifiedTimeBefore().equals(this.getLastModifiedTimeBefore()) == false)
            return false;
        if (other.getOptimizationContains() == null ^ this.getOptimizationContains() == null)
            return false;
        if (other.getOptimizationContains() != null && other.getOptimizationContains().equals(this.getOptimizationContains()) == false)
            return false;
        if (other.getNameContains() == null ^ this.getNameContains() == null)
            return false;
        if (other.getNameContains() != null && other.getNameContains().equals(this.getNameContains()) == false)
            return false;
        if (other.getStatusEquals() == null ^ this.getStatusEquals() == null)
            return false;
        if (other.getStatusEquals() != null && other.getStatusEquals().equals(this.getStatusEquals()) == false)
            return false;
        if (other.getSortBy() == null ^ this.getSortBy() == null)
            return false;
        if (other.getSortBy() != null && other.getSortBy().equals(this.getSortBy()) == false)
            return false;
        if (other.getSortOrder() == null ^ this.getSortOrder() == null)
            return false;
        if (other.getSortOrder() != null && other.getSortOrder().equals(this.getSortOrder()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getNextToken() == null) ? 0 : getNextToken().hashCode());
        hashCode = prime * hashCode + ((getMaxResults() == null) ? 0 : getMaxResults().hashCode());
        hashCode = prime * hashCode + ((getCreationTimeAfter() == null) ? 0 : getCreationTimeAfter().hashCode());
        hashCode = prime * hashCode + ((getCreationTimeBefore() == null) ? 0 : getCreationTimeBefore().hashCode());
        hashCode = prime * hashCode + ((getLastModifiedTimeAfter() == null) ? 0 : getLastModifiedTimeAfter().hashCode());
        hashCode = prime * hashCode + ((getLastModifiedTimeBefore() == null) ? 0 : getLastModifiedTimeBefore().hashCode());
        hashCode = prime * hashCode + ((getOptimizationContains() == null) ? 0 : getOptimizationContains().hashCode());
        hashCode = prime * hashCode + ((getNameContains() == null) ? 0 : getNameContains().hashCode());
        hashCode = prime * hashCode + ((getStatusEquals() == null) ? 0 : getStatusEquals().hashCode());
        hashCode = prime * hashCode + ((getSortBy() == null) ? 0 : getSortBy().hashCode());
        hashCode = prime * hashCode + ((getSortOrder() == null) ? 0 : getSortOrder().hashCode());
        return hashCode;
    }

    @Override
    public ListOptimizationJobsRequest clone() {
        return (ListOptimizationJobsRequest) super.clone();
    }

}
