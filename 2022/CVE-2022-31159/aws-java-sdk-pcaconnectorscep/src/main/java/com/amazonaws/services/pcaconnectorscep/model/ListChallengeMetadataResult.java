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
package com.amazonaws.services.pcaconnectorscep.model;

import java.io.Serializable;
import javax.annotation.Generated;

/**
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/pca-connector-scep-2018-05-10/ListChallengeMetadata"
 *      target="_top">AWS API Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class ListChallengeMetadataResult extends com.amazonaws.AmazonWebServiceResult<com.amazonaws.ResponseMetadata> implements Serializable, Cloneable {

    /**
     * <p>
     * The challenge metadata for the challenges belonging to your Amazon Web Services account.
     * </p>
     */
    private java.util.List<ChallengeMetadataSummary> challenges;
    /**
     * <p>
     * When you request a list of objects with a <code>MaxResults</code> setting, if the number of objects that are
     * still available for retrieval exceeds the maximum you requested, Connector for SCEP returns a
     * <code>NextToken</code> value in the response. To retrieve the next batch of objects, use the token returned from
     * the prior request in your next request.
     * </p>
     */
    private String nextToken;

    /**
     * <p>
     * The challenge metadata for the challenges belonging to your Amazon Web Services account.
     * </p>
     * 
     * @return The challenge metadata for the challenges belonging to your Amazon Web Services account.
     */

    public java.util.List<ChallengeMetadataSummary> getChallenges() {
        return challenges;
    }

    /**
     * <p>
     * The challenge metadata for the challenges belonging to your Amazon Web Services account.
     * </p>
     * 
     * @param challenges
     *        The challenge metadata for the challenges belonging to your Amazon Web Services account.
     */

    public void setChallenges(java.util.Collection<ChallengeMetadataSummary> challenges) {
        if (challenges == null) {
            this.challenges = null;
            return;
        }

        this.challenges = new java.util.ArrayList<ChallengeMetadataSummary>(challenges);
    }

    /**
     * <p>
     * The challenge metadata for the challenges belonging to your Amazon Web Services account.
     * </p>
     * <p>
     * <b>NOTE:</b> This method appends the values to the existing list (if any). Use
     * {@link #setChallenges(java.util.Collection)} or {@link #withChallenges(java.util.Collection)} if you want to
     * override the existing values.
     * </p>
     * 
     * @param challenges
     *        The challenge metadata for the challenges belonging to your Amazon Web Services account.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ListChallengeMetadataResult withChallenges(ChallengeMetadataSummary... challenges) {
        if (this.challenges == null) {
            setChallenges(new java.util.ArrayList<ChallengeMetadataSummary>(challenges.length));
        }
        for (ChallengeMetadataSummary ele : challenges) {
            this.challenges.add(ele);
        }
        return this;
    }

    /**
     * <p>
     * The challenge metadata for the challenges belonging to your Amazon Web Services account.
     * </p>
     * 
     * @param challenges
     *        The challenge metadata for the challenges belonging to your Amazon Web Services account.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ListChallengeMetadataResult withChallenges(java.util.Collection<ChallengeMetadataSummary> challenges) {
        setChallenges(challenges);
        return this;
    }

    /**
     * <p>
     * When you request a list of objects with a <code>MaxResults</code> setting, if the number of objects that are
     * still available for retrieval exceeds the maximum you requested, Connector for SCEP returns a
     * <code>NextToken</code> value in the response. To retrieve the next batch of objects, use the token returned from
     * the prior request in your next request.
     * </p>
     * 
     * @param nextToken
     *        When you request a list of objects with a <code>MaxResults</code> setting, if the number of objects that
     *        are still available for retrieval exceeds the maximum you requested, Connector for SCEP returns a
     *        <code>NextToken</code> value in the response. To retrieve the next batch of objects, use the token
     *        returned from the prior request in your next request.
     */

    public void setNextToken(String nextToken) {
        this.nextToken = nextToken;
    }

    /**
     * <p>
     * When you request a list of objects with a <code>MaxResults</code> setting, if the number of objects that are
     * still available for retrieval exceeds the maximum you requested, Connector for SCEP returns a
     * <code>NextToken</code> value in the response. To retrieve the next batch of objects, use the token returned from
     * the prior request in your next request.
     * </p>
     * 
     * @return When you request a list of objects with a <code>MaxResults</code> setting, if the number of objects that
     *         are still available for retrieval exceeds the maximum you requested, Connector for SCEP returns a
     *         <code>NextToken</code> value in the response. To retrieve the next batch of objects, use the token
     *         returned from the prior request in your next request.
     */

    public String getNextToken() {
        return this.nextToken;
    }

    /**
     * <p>
     * When you request a list of objects with a <code>MaxResults</code> setting, if the number of objects that are
     * still available for retrieval exceeds the maximum you requested, Connector for SCEP returns a
     * <code>NextToken</code> value in the response. To retrieve the next batch of objects, use the token returned from
     * the prior request in your next request.
     * </p>
     * 
     * @param nextToken
     *        When you request a list of objects with a <code>MaxResults</code> setting, if the number of objects that
     *        are still available for retrieval exceeds the maximum you requested, Connector for SCEP returns a
     *        <code>NextToken</code> value in the response. To retrieve the next batch of objects, use the token
     *        returned from the prior request in your next request.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ListChallengeMetadataResult withNextToken(String nextToken) {
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
        if (getChallenges() != null)
            sb.append("Challenges: ").append(getChallenges()).append(",");
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

        if (obj instanceof ListChallengeMetadataResult == false)
            return false;
        ListChallengeMetadataResult other = (ListChallengeMetadataResult) obj;
        if (other.getChallenges() == null ^ this.getChallenges() == null)
            return false;
        if (other.getChallenges() != null && other.getChallenges().equals(this.getChallenges()) == false)
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

        hashCode = prime * hashCode + ((getChallenges() == null) ? 0 : getChallenges().hashCode());
        hashCode = prime * hashCode + ((getNextToken() == null) ? 0 : getNextToken().hashCode());
        return hashCode;
    }

    @Override
    public ListChallengeMetadataResult clone() {
        try {
            return (ListChallengeMetadataResult) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

}
