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
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/sagemaker-2017-07-24/ListMlflowTrackingServers"
 *      target="_top">AWS API Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class ListMlflowTrackingServersRequest extends com.amazonaws.AmazonWebServiceRequest implements Serializable, Cloneable {

    /**
     * <p>
     * Use the <code>CreatedAfter</code> filter to only list tracking servers created after a specific date and time.
     * Listed tracking servers are shown with a date and time such as <code>"2024-03-16T01:46:56+00:00"</code>. The
     * <code>CreatedAfter</code> parameter takes in a Unix timestamp. To convert a date and time into a Unix timestamp,
     * see <a href="https://www.epochconverter.com/">EpochConverter</a>.
     * </p>
     */
    private java.util.Date createdAfter;
    /**
     * <p>
     * Use the <code>CreatedBefore</code> filter to only list tracking servers created before a specific date and time.
     * Listed tracking servers are shown with a date and time such as <code>"2024-03-16T01:46:56+00:00"</code>. The
     * <code>CreatedBefore</code> parameter takes in a Unix timestamp. To convert a date and time into a Unix timestamp,
     * see <a href="https://www.epochconverter.com/">EpochConverter</a>.
     * </p>
     */
    private java.util.Date createdBefore;
    /**
     * <p>
     * Filter for tracking servers with a specified creation status.
     * </p>
     */
    private String trackingServerStatus;
    /**
     * <p>
     * Filter for tracking servers using the specified MLflow version.
     * </p>
     */
    private String mlflowVersion;
    /**
     * <p>
     * Filter for trackings servers sorting by name, creation time, or creation status.
     * </p>
     */
    private String sortBy;
    /**
     * <p>
     * Change the order of the listed tracking servers. By default, tracking servers are listed in
     * <code>Descending</code> order by creation time. To change the list order, you can specify <code>SortOrder</code>
     * to be <code>Ascending</code>.
     * </p>
     */
    private String sortOrder;
    /**
     * <p>
     * If the previous response was truncated, you will receive this token. Use it in your next request to receive the
     * next set of results.
     * </p>
     */
    private String nextToken;
    /**
     * <p>
     * The maximum number of tracking servers to list.
     * </p>
     */
    private Integer maxResults;

    /**
     * <p>
     * Use the <code>CreatedAfter</code> filter to only list tracking servers created after a specific date and time.
     * Listed tracking servers are shown with a date and time such as <code>"2024-03-16T01:46:56+00:00"</code>. The
     * <code>CreatedAfter</code> parameter takes in a Unix timestamp. To convert a date and time into a Unix timestamp,
     * see <a href="https://www.epochconverter.com/">EpochConverter</a>.
     * </p>
     * 
     * @param createdAfter
     *        Use the <code>CreatedAfter</code> filter to only list tracking servers created after a specific date and
     *        time. Listed tracking servers are shown with a date and time such as
     *        <code>"2024-03-16T01:46:56+00:00"</code>. The <code>CreatedAfter</code> parameter takes in a Unix
     *        timestamp. To convert a date and time into a Unix timestamp, see <a
     *        href="https://www.epochconverter.com/">EpochConverter</a>.
     */

    public void setCreatedAfter(java.util.Date createdAfter) {
        this.createdAfter = createdAfter;
    }

    /**
     * <p>
     * Use the <code>CreatedAfter</code> filter to only list tracking servers created after a specific date and time.
     * Listed tracking servers are shown with a date and time such as <code>"2024-03-16T01:46:56+00:00"</code>. The
     * <code>CreatedAfter</code> parameter takes in a Unix timestamp. To convert a date and time into a Unix timestamp,
     * see <a href="https://www.epochconverter.com/">EpochConverter</a>.
     * </p>
     * 
     * @return Use the <code>CreatedAfter</code> filter to only list tracking servers created after a specific date and
     *         time. Listed tracking servers are shown with a date and time such as
     *         <code>"2024-03-16T01:46:56+00:00"</code>. The <code>CreatedAfter</code> parameter takes in a Unix
     *         timestamp. To convert a date and time into a Unix timestamp, see <a
     *         href="https://www.epochconverter.com/">EpochConverter</a>.
     */

    public java.util.Date getCreatedAfter() {
        return this.createdAfter;
    }

    /**
     * <p>
     * Use the <code>CreatedAfter</code> filter to only list tracking servers created after a specific date and time.
     * Listed tracking servers are shown with a date and time such as <code>"2024-03-16T01:46:56+00:00"</code>. The
     * <code>CreatedAfter</code> parameter takes in a Unix timestamp. To convert a date and time into a Unix timestamp,
     * see <a href="https://www.epochconverter.com/">EpochConverter</a>.
     * </p>
     * 
     * @param createdAfter
     *        Use the <code>CreatedAfter</code> filter to only list tracking servers created after a specific date and
     *        time. Listed tracking servers are shown with a date and time such as
     *        <code>"2024-03-16T01:46:56+00:00"</code>. The <code>CreatedAfter</code> parameter takes in a Unix
     *        timestamp. To convert a date and time into a Unix timestamp, see <a
     *        href="https://www.epochconverter.com/">EpochConverter</a>.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ListMlflowTrackingServersRequest withCreatedAfter(java.util.Date createdAfter) {
        setCreatedAfter(createdAfter);
        return this;
    }

    /**
     * <p>
     * Use the <code>CreatedBefore</code> filter to only list tracking servers created before a specific date and time.
     * Listed tracking servers are shown with a date and time such as <code>"2024-03-16T01:46:56+00:00"</code>. The
     * <code>CreatedBefore</code> parameter takes in a Unix timestamp. To convert a date and time into a Unix timestamp,
     * see <a href="https://www.epochconverter.com/">EpochConverter</a>.
     * </p>
     * 
     * @param createdBefore
     *        Use the <code>CreatedBefore</code> filter to only list tracking servers created before a specific date and
     *        time. Listed tracking servers are shown with a date and time such as
     *        <code>"2024-03-16T01:46:56+00:00"</code>. The <code>CreatedBefore</code> parameter takes in a Unix
     *        timestamp. To convert a date and time into a Unix timestamp, see <a
     *        href="https://www.epochconverter.com/">EpochConverter</a>.
     */

    public void setCreatedBefore(java.util.Date createdBefore) {
        this.createdBefore = createdBefore;
    }

    /**
     * <p>
     * Use the <code>CreatedBefore</code> filter to only list tracking servers created before a specific date and time.
     * Listed tracking servers are shown with a date and time such as <code>"2024-03-16T01:46:56+00:00"</code>. The
     * <code>CreatedBefore</code> parameter takes in a Unix timestamp. To convert a date and time into a Unix timestamp,
     * see <a href="https://www.epochconverter.com/">EpochConverter</a>.
     * </p>
     * 
     * @return Use the <code>CreatedBefore</code> filter to only list tracking servers created before a specific date
     *         and time. Listed tracking servers are shown with a date and time such as
     *         <code>"2024-03-16T01:46:56+00:00"</code>. The <code>CreatedBefore</code> parameter takes in a Unix
     *         timestamp. To convert a date and time into a Unix timestamp, see <a
     *         href="https://www.epochconverter.com/">EpochConverter</a>.
     */

    public java.util.Date getCreatedBefore() {
        return this.createdBefore;
    }

    /**
     * <p>
     * Use the <code>CreatedBefore</code> filter to only list tracking servers created before a specific date and time.
     * Listed tracking servers are shown with a date and time such as <code>"2024-03-16T01:46:56+00:00"</code>. The
     * <code>CreatedBefore</code> parameter takes in a Unix timestamp. To convert a date and time into a Unix timestamp,
     * see <a href="https://www.epochconverter.com/">EpochConverter</a>.
     * </p>
     * 
     * @param createdBefore
     *        Use the <code>CreatedBefore</code> filter to only list tracking servers created before a specific date and
     *        time. Listed tracking servers are shown with a date and time such as
     *        <code>"2024-03-16T01:46:56+00:00"</code>. The <code>CreatedBefore</code> parameter takes in a Unix
     *        timestamp. To convert a date and time into a Unix timestamp, see <a
     *        href="https://www.epochconverter.com/">EpochConverter</a>.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ListMlflowTrackingServersRequest withCreatedBefore(java.util.Date createdBefore) {
        setCreatedBefore(createdBefore);
        return this;
    }

    /**
     * <p>
     * Filter for tracking servers with a specified creation status.
     * </p>
     * 
     * @param trackingServerStatus
     *        Filter for tracking servers with a specified creation status.
     * @see TrackingServerStatus
     */

    public void setTrackingServerStatus(String trackingServerStatus) {
        this.trackingServerStatus = trackingServerStatus;
    }

    /**
     * <p>
     * Filter for tracking servers with a specified creation status.
     * </p>
     * 
     * @return Filter for tracking servers with a specified creation status.
     * @see TrackingServerStatus
     */

    public String getTrackingServerStatus() {
        return this.trackingServerStatus;
    }

    /**
     * <p>
     * Filter for tracking servers with a specified creation status.
     * </p>
     * 
     * @param trackingServerStatus
     *        Filter for tracking servers with a specified creation status.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see TrackingServerStatus
     */

    public ListMlflowTrackingServersRequest withTrackingServerStatus(String trackingServerStatus) {
        setTrackingServerStatus(trackingServerStatus);
        return this;
    }

    /**
     * <p>
     * Filter for tracking servers with a specified creation status.
     * </p>
     * 
     * @param trackingServerStatus
     *        Filter for tracking servers with a specified creation status.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see TrackingServerStatus
     */

    public ListMlflowTrackingServersRequest withTrackingServerStatus(TrackingServerStatus trackingServerStatus) {
        this.trackingServerStatus = trackingServerStatus.toString();
        return this;
    }

    /**
     * <p>
     * Filter for tracking servers using the specified MLflow version.
     * </p>
     * 
     * @param mlflowVersion
     *        Filter for tracking servers using the specified MLflow version.
     */

    public void setMlflowVersion(String mlflowVersion) {
        this.mlflowVersion = mlflowVersion;
    }

    /**
     * <p>
     * Filter for tracking servers using the specified MLflow version.
     * </p>
     * 
     * @return Filter for tracking servers using the specified MLflow version.
     */

    public String getMlflowVersion() {
        return this.mlflowVersion;
    }

    /**
     * <p>
     * Filter for tracking servers using the specified MLflow version.
     * </p>
     * 
     * @param mlflowVersion
     *        Filter for tracking servers using the specified MLflow version.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ListMlflowTrackingServersRequest withMlflowVersion(String mlflowVersion) {
        setMlflowVersion(mlflowVersion);
        return this;
    }

    /**
     * <p>
     * Filter for trackings servers sorting by name, creation time, or creation status.
     * </p>
     * 
     * @param sortBy
     *        Filter for trackings servers sorting by name, creation time, or creation status.
     * @see SortTrackingServerBy
     */

    public void setSortBy(String sortBy) {
        this.sortBy = sortBy;
    }

    /**
     * <p>
     * Filter for trackings servers sorting by name, creation time, or creation status.
     * </p>
     * 
     * @return Filter for trackings servers sorting by name, creation time, or creation status.
     * @see SortTrackingServerBy
     */

    public String getSortBy() {
        return this.sortBy;
    }

    /**
     * <p>
     * Filter for trackings servers sorting by name, creation time, or creation status.
     * </p>
     * 
     * @param sortBy
     *        Filter for trackings servers sorting by name, creation time, or creation status.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see SortTrackingServerBy
     */

    public ListMlflowTrackingServersRequest withSortBy(String sortBy) {
        setSortBy(sortBy);
        return this;
    }

    /**
     * <p>
     * Filter for trackings servers sorting by name, creation time, or creation status.
     * </p>
     * 
     * @param sortBy
     *        Filter for trackings servers sorting by name, creation time, or creation status.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see SortTrackingServerBy
     */

    public ListMlflowTrackingServersRequest withSortBy(SortTrackingServerBy sortBy) {
        this.sortBy = sortBy.toString();
        return this;
    }

    /**
     * <p>
     * Change the order of the listed tracking servers. By default, tracking servers are listed in
     * <code>Descending</code> order by creation time. To change the list order, you can specify <code>SortOrder</code>
     * to be <code>Ascending</code>.
     * </p>
     * 
     * @param sortOrder
     *        Change the order of the listed tracking servers. By default, tracking servers are listed in
     *        <code>Descending</code> order by creation time. To change the list order, you can specify
     *        <code>SortOrder</code> to be <code>Ascending</code>.
     * @see SortOrder
     */

    public void setSortOrder(String sortOrder) {
        this.sortOrder = sortOrder;
    }

    /**
     * <p>
     * Change the order of the listed tracking servers. By default, tracking servers are listed in
     * <code>Descending</code> order by creation time. To change the list order, you can specify <code>SortOrder</code>
     * to be <code>Ascending</code>.
     * </p>
     * 
     * @return Change the order of the listed tracking servers. By default, tracking servers are listed in
     *         <code>Descending</code> order by creation time. To change the list order, you can specify
     *         <code>SortOrder</code> to be <code>Ascending</code>.
     * @see SortOrder
     */

    public String getSortOrder() {
        return this.sortOrder;
    }

    /**
     * <p>
     * Change the order of the listed tracking servers. By default, tracking servers are listed in
     * <code>Descending</code> order by creation time. To change the list order, you can specify <code>SortOrder</code>
     * to be <code>Ascending</code>.
     * </p>
     * 
     * @param sortOrder
     *        Change the order of the listed tracking servers. By default, tracking servers are listed in
     *        <code>Descending</code> order by creation time. To change the list order, you can specify
     *        <code>SortOrder</code> to be <code>Ascending</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see SortOrder
     */

    public ListMlflowTrackingServersRequest withSortOrder(String sortOrder) {
        setSortOrder(sortOrder);
        return this;
    }

    /**
     * <p>
     * Change the order of the listed tracking servers. By default, tracking servers are listed in
     * <code>Descending</code> order by creation time. To change the list order, you can specify <code>SortOrder</code>
     * to be <code>Ascending</code>.
     * </p>
     * 
     * @param sortOrder
     *        Change the order of the listed tracking servers. By default, tracking servers are listed in
     *        <code>Descending</code> order by creation time. To change the list order, you can specify
     *        <code>SortOrder</code> to be <code>Ascending</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see SortOrder
     */

    public ListMlflowTrackingServersRequest withSortOrder(SortOrder sortOrder) {
        this.sortOrder = sortOrder.toString();
        return this;
    }

    /**
     * <p>
     * If the previous response was truncated, you will receive this token. Use it in your next request to receive the
     * next set of results.
     * </p>
     * 
     * @param nextToken
     *        If the previous response was truncated, you will receive this token. Use it in your next request to
     *        receive the next set of results.
     */

    public void setNextToken(String nextToken) {
        this.nextToken = nextToken;
    }

    /**
     * <p>
     * If the previous response was truncated, you will receive this token. Use it in your next request to receive the
     * next set of results.
     * </p>
     * 
     * @return If the previous response was truncated, you will receive this token. Use it in your next request to
     *         receive the next set of results.
     */

    public String getNextToken() {
        return this.nextToken;
    }

    /**
     * <p>
     * If the previous response was truncated, you will receive this token. Use it in your next request to receive the
     * next set of results.
     * </p>
     * 
     * @param nextToken
     *        If the previous response was truncated, you will receive this token. Use it in your next request to
     *        receive the next set of results.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ListMlflowTrackingServersRequest withNextToken(String nextToken) {
        setNextToken(nextToken);
        return this;
    }

    /**
     * <p>
     * The maximum number of tracking servers to list.
     * </p>
     * 
     * @param maxResults
     *        The maximum number of tracking servers to list.
     */

    public void setMaxResults(Integer maxResults) {
        this.maxResults = maxResults;
    }

    /**
     * <p>
     * The maximum number of tracking servers to list.
     * </p>
     * 
     * @return The maximum number of tracking servers to list.
     */

    public Integer getMaxResults() {
        return this.maxResults;
    }

    /**
     * <p>
     * The maximum number of tracking servers to list.
     * </p>
     * 
     * @param maxResults
     *        The maximum number of tracking servers to list.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ListMlflowTrackingServersRequest withMaxResults(Integer maxResults) {
        setMaxResults(maxResults);
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
        if (getCreatedAfter() != null)
            sb.append("CreatedAfter: ").append(getCreatedAfter()).append(",");
        if (getCreatedBefore() != null)
            sb.append("CreatedBefore: ").append(getCreatedBefore()).append(",");
        if (getTrackingServerStatus() != null)
            sb.append("TrackingServerStatus: ").append(getTrackingServerStatus()).append(",");
        if (getMlflowVersion() != null)
            sb.append("MlflowVersion: ").append(getMlflowVersion()).append(",");
        if (getSortBy() != null)
            sb.append("SortBy: ").append(getSortBy()).append(",");
        if (getSortOrder() != null)
            sb.append("SortOrder: ").append(getSortOrder()).append(",");
        if (getNextToken() != null)
            sb.append("NextToken: ").append(getNextToken()).append(",");
        if (getMaxResults() != null)
            sb.append("MaxResults: ").append(getMaxResults());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof ListMlflowTrackingServersRequest == false)
            return false;
        ListMlflowTrackingServersRequest other = (ListMlflowTrackingServersRequest) obj;
        if (other.getCreatedAfter() == null ^ this.getCreatedAfter() == null)
            return false;
        if (other.getCreatedAfter() != null && other.getCreatedAfter().equals(this.getCreatedAfter()) == false)
            return false;
        if (other.getCreatedBefore() == null ^ this.getCreatedBefore() == null)
            return false;
        if (other.getCreatedBefore() != null && other.getCreatedBefore().equals(this.getCreatedBefore()) == false)
            return false;
        if (other.getTrackingServerStatus() == null ^ this.getTrackingServerStatus() == null)
            return false;
        if (other.getTrackingServerStatus() != null && other.getTrackingServerStatus().equals(this.getTrackingServerStatus()) == false)
            return false;
        if (other.getMlflowVersion() == null ^ this.getMlflowVersion() == null)
            return false;
        if (other.getMlflowVersion() != null && other.getMlflowVersion().equals(this.getMlflowVersion()) == false)
            return false;
        if (other.getSortBy() == null ^ this.getSortBy() == null)
            return false;
        if (other.getSortBy() != null && other.getSortBy().equals(this.getSortBy()) == false)
            return false;
        if (other.getSortOrder() == null ^ this.getSortOrder() == null)
            return false;
        if (other.getSortOrder() != null && other.getSortOrder().equals(this.getSortOrder()) == false)
            return false;
        if (other.getNextToken() == null ^ this.getNextToken() == null)
            return false;
        if (other.getNextToken() != null && other.getNextToken().equals(this.getNextToken()) == false)
            return false;
        if (other.getMaxResults() == null ^ this.getMaxResults() == null)
            return false;
        if (other.getMaxResults() != null && other.getMaxResults().equals(this.getMaxResults()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getCreatedAfter() == null) ? 0 : getCreatedAfter().hashCode());
        hashCode = prime * hashCode + ((getCreatedBefore() == null) ? 0 : getCreatedBefore().hashCode());
        hashCode = prime * hashCode + ((getTrackingServerStatus() == null) ? 0 : getTrackingServerStatus().hashCode());
        hashCode = prime * hashCode + ((getMlflowVersion() == null) ? 0 : getMlflowVersion().hashCode());
        hashCode = prime * hashCode + ((getSortBy() == null) ? 0 : getSortBy().hashCode());
        hashCode = prime * hashCode + ((getSortOrder() == null) ? 0 : getSortOrder().hashCode());
        hashCode = prime * hashCode + ((getNextToken() == null) ? 0 : getNextToken().hashCode());
        hashCode = prime * hashCode + ((getMaxResults() == null) ? 0 : getMaxResults().hashCode());
        return hashCode;
    }

    @Override
    public ListMlflowTrackingServersRequest clone() {
        return (ListMlflowTrackingServersRequest) super.clone();
    }

}
