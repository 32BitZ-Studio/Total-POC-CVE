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

import com.amazonaws.AmazonWebServiceRequest;

/**
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/quicksight-2018-04-01/BatchDeleteTopicReviewedAnswer"
 *      target="_top">AWS API Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class BatchDeleteTopicReviewedAnswerRequest extends com.amazonaws.AmazonWebServiceRequest implements Serializable, Cloneable {

    /**
     * <p>
     * The ID of the Amazon Web Services account that you want to delete a reviewed answers in.
     * </p>
     */
    private String awsAccountId;
    /**
     * <p>
     * The ID for the topic reviewed answer that you want to delete. This ID is unique per Amazon Web Services Region
     * for each Amazon Web Services account.
     * </p>
     */
    private String topicId;
    /**
     * <p>
     * The Answer IDs of the Answers to be deleted.
     * </p>
     */
    private java.util.List<String> answerIds;

    /**
     * <p>
     * The ID of the Amazon Web Services account that you want to delete a reviewed answers in.
     * </p>
     * 
     * @param awsAccountId
     *        The ID of the Amazon Web Services account that you want to delete a reviewed answers in.
     */

    public void setAwsAccountId(String awsAccountId) {
        this.awsAccountId = awsAccountId;
    }

    /**
     * <p>
     * The ID of the Amazon Web Services account that you want to delete a reviewed answers in.
     * </p>
     * 
     * @return The ID of the Amazon Web Services account that you want to delete a reviewed answers in.
     */

    public String getAwsAccountId() {
        return this.awsAccountId;
    }

    /**
     * <p>
     * The ID of the Amazon Web Services account that you want to delete a reviewed answers in.
     * </p>
     * 
     * @param awsAccountId
     *        The ID of the Amazon Web Services account that you want to delete a reviewed answers in.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public BatchDeleteTopicReviewedAnswerRequest withAwsAccountId(String awsAccountId) {
        setAwsAccountId(awsAccountId);
        return this;
    }

    /**
     * <p>
     * The ID for the topic reviewed answer that you want to delete. This ID is unique per Amazon Web Services Region
     * for each Amazon Web Services account.
     * </p>
     * 
     * @param topicId
     *        The ID for the topic reviewed answer that you want to delete. This ID is unique per Amazon Web Services
     *        Region for each Amazon Web Services account.
     */

    public void setTopicId(String topicId) {
        this.topicId = topicId;
    }

    /**
     * <p>
     * The ID for the topic reviewed answer that you want to delete. This ID is unique per Amazon Web Services Region
     * for each Amazon Web Services account.
     * </p>
     * 
     * @return The ID for the topic reviewed answer that you want to delete. This ID is unique per Amazon Web Services
     *         Region for each Amazon Web Services account.
     */

    public String getTopicId() {
        return this.topicId;
    }

    /**
     * <p>
     * The ID for the topic reviewed answer that you want to delete. This ID is unique per Amazon Web Services Region
     * for each Amazon Web Services account.
     * </p>
     * 
     * @param topicId
     *        The ID for the topic reviewed answer that you want to delete. This ID is unique per Amazon Web Services
     *        Region for each Amazon Web Services account.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public BatchDeleteTopicReviewedAnswerRequest withTopicId(String topicId) {
        setTopicId(topicId);
        return this;
    }

    /**
     * <p>
     * The Answer IDs of the Answers to be deleted.
     * </p>
     * 
     * @return The Answer IDs of the Answers to be deleted.
     */

    public java.util.List<String> getAnswerIds() {
        return answerIds;
    }

    /**
     * <p>
     * The Answer IDs of the Answers to be deleted.
     * </p>
     * 
     * @param answerIds
     *        The Answer IDs of the Answers to be deleted.
     */

    public void setAnswerIds(java.util.Collection<String> answerIds) {
        if (answerIds == null) {
            this.answerIds = null;
            return;
        }

        this.answerIds = new java.util.ArrayList<String>(answerIds);
    }

    /**
     * <p>
     * The Answer IDs of the Answers to be deleted.
     * </p>
     * <p>
     * <b>NOTE:</b> This method appends the values to the existing list (if any). Use
     * {@link #setAnswerIds(java.util.Collection)} or {@link #withAnswerIds(java.util.Collection)} if you want to
     * override the existing values.
     * </p>
     * 
     * @param answerIds
     *        The Answer IDs of the Answers to be deleted.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public BatchDeleteTopicReviewedAnswerRequest withAnswerIds(String... answerIds) {
        if (this.answerIds == null) {
            setAnswerIds(new java.util.ArrayList<String>(answerIds.length));
        }
        for (String ele : answerIds) {
            this.answerIds.add(ele);
        }
        return this;
    }

    /**
     * <p>
     * The Answer IDs of the Answers to be deleted.
     * </p>
     * 
     * @param answerIds
     *        The Answer IDs of the Answers to be deleted.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public BatchDeleteTopicReviewedAnswerRequest withAnswerIds(java.util.Collection<String> answerIds) {
        setAnswerIds(answerIds);
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
        if (getAwsAccountId() != null)
            sb.append("AwsAccountId: ").append(getAwsAccountId()).append(",");
        if (getTopicId() != null)
            sb.append("TopicId: ").append(getTopicId()).append(",");
        if (getAnswerIds() != null)
            sb.append("AnswerIds: ").append(getAnswerIds());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof BatchDeleteTopicReviewedAnswerRequest == false)
            return false;
        BatchDeleteTopicReviewedAnswerRequest other = (BatchDeleteTopicReviewedAnswerRequest) obj;
        if (other.getAwsAccountId() == null ^ this.getAwsAccountId() == null)
            return false;
        if (other.getAwsAccountId() != null && other.getAwsAccountId().equals(this.getAwsAccountId()) == false)
            return false;
        if (other.getTopicId() == null ^ this.getTopicId() == null)
            return false;
        if (other.getTopicId() != null && other.getTopicId().equals(this.getTopicId()) == false)
            return false;
        if (other.getAnswerIds() == null ^ this.getAnswerIds() == null)
            return false;
        if (other.getAnswerIds() != null && other.getAnswerIds().equals(this.getAnswerIds()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getAwsAccountId() == null) ? 0 : getAwsAccountId().hashCode());
        hashCode = prime * hashCode + ((getTopicId() == null) ? 0 : getTopicId().hashCode());
        hashCode = prime * hashCode + ((getAnswerIds() == null) ? 0 : getAnswerIds().hashCode());
        return hashCode;
    }

    @Override
    public BatchDeleteTopicReviewedAnswerRequest clone() {
        return (BatchDeleteTopicReviewedAnswerRequest) super.clone();
    }

}
