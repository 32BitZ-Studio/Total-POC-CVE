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

/**
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/sagemaker-2017-07-24/ListMlflowTrackingServers"
 *      target="_top">AWS API Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class ListMlflowTrackingServersResult extends com.amazonaws.AmazonWebServiceResult<com.amazonaws.ResponseMetadata> implements Serializable, Cloneable {

    /**
     * <p>
     * A list of tracking servers according to chosen filters.
     * </p>
     */
    private java.util.List<TrackingServerSummary> trackingServerSummaries;
    /**
     * <p>
     * If the previous response was truncated, you will receive this token. Use it in your next request to receive the
     * next set of results.
     * </p>
     */
    private String nextToken;

    /**
     * <p>
     * A list of tracking servers according to chosen filters.
     * </p>
     * 
     * @return A list of tracking servers according to chosen filters.
     */

    public java.util.List<TrackingServerSummary> getTrackingServerSummaries() {
        return trackingServerSummaries;
    }

    /**
     * <p>
     * A list of tracking servers according to chosen filters.
     * </p>
     * 
     * @param trackingServerSummaries
     *        A list of tracking servers according to chosen filters.
     */

    public void setTrackingServerSummaries(java.util.Collection<TrackingServerSummary> trackingServerSummaries) {
        if (trackingServerSummaries == null) {
            this.trackingServerSummaries = null;
            return;
        }

        this.trackingServerSummaries = new java.util.ArrayList<TrackingServerSummary>(trackingServerSummaries);
    }

    /**
     * <p>
     * A list of tracking servers according to chosen filters.
     * </p>
     * <p>
     * <b>NOTE:</b> This method appends the values to the existing list (if any). Use
     * {@link #setTrackingServerSummaries(java.util.Collection)} or
     * {@link #withTrackingServerSummaries(java.util.Collection)} if you want to override the existing values.
     * </p>
     * 
     * @param trackingServerSummaries
     *        A list of tracking servers according to chosen filters.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ListMlflowTrackingServersResult withTrackingServerSummaries(TrackingServerSummary... trackingServerSummaries) {
        if (this.trackingServerSummaries == null) {
            setTrackingServerSummaries(new java.util.ArrayList<TrackingServerSummary>(trackingServerSummaries.length));
        }
        for (TrackingServerSummary ele : trackingServerSummaries) {
            this.trackingServerSummaries.add(ele);
        }
        return this;
    }

    /**
     * <p>
     * A list of tracking servers according to chosen filters.
     * </p>
     * 
     * @param trackingServerSummaries
     *        A list of tracking servers according to chosen filters.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ListMlflowTrackingServersResult withTrackingServerSummaries(java.util.Collection<TrackingServerSummary> trackingServerSummaries) {
        setTrackingServerSummaries(trackingServerSummaries);
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

    public ListMlflowTrackingServersResult withNextToken(String nextToken) {
        setNextToken(nextToken);
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
        if (getTrackingServerSummaries() != null)
            sb.append("TrackingServerSummaries: ").append(getTrackingServerSummaries()).append(",");
        if (getNextToken() != null)
            sb.append("NextToken: ").append(getNextToken());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof ListMlflowTrackingServersResult == false)
            return false;
        ListMlflowTrackingServersResult other = (ListMlflowTrackingServersResult) obj;
        if (other.getTrackingServerSummaries() == null ^ this.getTrackingServerSummaries() == null)
            return false;
        if (other.getTrackingServerSummaries() != null && other.getTrackingServerSummaries().equals(this.getTrackingServerSummaries()) == false)
            return false;
        if (other.getNextToken() == null ^ this.getNextToken() == null)
            return false;
        if (other.getNextToken() != null && other.getNextToken().equals(this.getNextToken()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getTrackingServerSummaries() == null) ? 0 : getTrackingServerSummaries().hashCode());
        hashCode = prime * hashCode + ((getNextToken() == null) ? 0 : getNextToken().hashCode());
        return hashCode;
    }

    @Override
    public ListMlflowTrackingServersResult clone() {
        try {
            return (ListMlflowTrackingServersResult) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

}
