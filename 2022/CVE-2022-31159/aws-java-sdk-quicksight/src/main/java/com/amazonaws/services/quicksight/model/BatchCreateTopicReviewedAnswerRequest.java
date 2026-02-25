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
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/quicksight-2018-04-01/BatchCreateTopicReviewedAnswer"
 *      target="_top">AWS API Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class BatchCreateTopicReviewedAnswerRequest extends com.amazonaws.AmazonWebServiceRequest implements Serializable, Cloneable {

    /**
     * <p>
     * The ID of the Amazon Web Services account that you want to create a reviewed answer in.
     * </p>
     */
    private String awsAccountId;
    /**
     * <p>
     * The ID for the topic reviewed answer that you want to create. This ID is unique per Amazon Web Services Region
     * for each Amazon Web Services account.
     * </p>
     */
    private String topicId;
    /**
     * <p>
     * The definition of the Answers to be created.
     * </p>
     */
    private java.util.List<CreateTopicReviewedAnswer> answers;

    /**
     * <p>
     * The ID of the Amazon Web Services account that you want to create a reviewed answer in.
     * </p>
     * 
     * @param awsAccountId
     *        The ID of the Amazon Web Services account that you want to create a reviewed answer in.
     */

    public void setAwsAccountId(String awsAccountId) {
        this.awsAccountId = awsAccountId;
    }

    /**
     * <p>
     * The ID of the Amazon Web Services account that you want to create a reviewed answer in.
     * </p>
     * 
     * @return The ID of the Amazon Web Services account that you want to create a reviewed answer in.
     */

    public String getAwsAccountId() {
        return this.awsAccountId;
    }

    /**
     * <p>
     * The ID of the Amazon Web Services account that you want to create a reviewed answer in.
     * </p>
     * 
     * @param awsAccountId
     *        The ID of the Amazon Web Services account that you want to create a reviewed answer in.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public BatchCreateTopicReviewedAnswerRequest withAwsAccountId(String awsAccountId) {
        setAwsAccountId(awsAccountId);
        return this;
    }

    /**
     * <p>
     * The ID for the topic reviewed answer that you want to create. This ID is unique per Amazon Web Services Region
     * for each Amazon Web Services account.
     * </p>
     * 
     * @param topicId
     *        The ID for the topic reviewed answer that you want to create. This ID is unique per Amazon Web Services
     *        Region for each Amazon Web Services account.
     */

    public void setTopicId(String topicId) {
        this.topicId = topicId;
    }

    /**
     * <p>
     * The ID for the topic reviewed answer that you want to create. This ID is unique per Amazon Web Services Region
     * for each Amazon Web Services account.
     * </p>
     * 
     * @return The ID for the topic reviewed answer that you want to create. This ID is unique per Amazon Web Services
     *         Region for each Amazon Web Services account.
     */

    public String getTopicId() {
        return this.topicId;
    }

    /**
     * <p>
     * The ID for the topic reviewed answer that you want to create. This ID is unique per Amazon Web Services Region
     * for each Amazon Web Services account.
     * </p>
     * 
     * @param topicId
     *        The ID for the topic reviewed answer that you want to create. This ID is unique per Amazon Web Services
     *        Region for each Amazon Web Services account.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public BatchCreateTopicReviewedAnswerRequest withTopicId(String topicId) {
        setTopicId(topicId);
        return this;
    }

    /**
     * <p>
     * The definition of the Answers to be created.
     * </p>
     * 
     * @return The definition of the Answers to be created.
     */

    public java.util.List<CreateTopicReviewedAnswer> getAnswers() {
        return answers;
    }

    /**
     * <p>
     * The definition of the Answers to be created.
     * </p>
     * 
     * @param answers
     *        The definition of the Answers to be created.
     */

    public void setAnswers(java.util.Collection<CreateTopicReviewedAnswer> answers) {
        if (answers == null) {
            this.answers = null;
            return;
        }

        this.answers = new java.util.ArrayList<CreateTopicReviewedAnswer>(answers);
    }

    /**
     * <p>
     * The definition of the Answers to be created.
     * </p>
     * <p>
     * <b>NOTE:</b> This method appends the values to the existing list (if any). Use
     * {@link #setAnswers(java.util.Collection)} or {@link #withAnswers(java.util.Collection)} if you want to override
     * the existing values.
     * </p>
     * 
     * @param answers
     *        The definition of the Answers to be created.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public BatchCreateTopicReviewedAnswerRequest withAnswers(CreateTopicReviewedAnswer... answers) {
        if (this.answers == null) {
            setAnswers(new java.util.ArrayList<CreateTopicReviewedAnswer>(answers.length));
        }
        for (CreateTopicReviewedAnswer ele : answers) {
            this.answers.add(ele);
        }
        return this;
    }

    /**
     * <p>
     * The definition of the Answers to be created.
     * </p>
     * 
     * @param answers
     *        The definition of the Answers to be created.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public BatchCreateTopicReviewedAnswerRequest withAnswers(java.util.Collection<CreateTopicReviewedAnswer> answers) {
        setAnswers(answers);
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
        if (getAnswers() != null)
            sb.append("Answers: ").append(getAnswers());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof BatchCreateTopicReviewedAnswerRequest == false)
            return false;
        BatchCreateTopicReviewedAnswerRequest other = (BatchCreateTopicReviewedAnswerRequest) obj;
        if (other.getAwsAccountId() == null ^ this.getAwsAccountId() == null)
            return false;
        if (other.getAwsAccountId() != null && other.getAwsAccountId().equals(this.getAwsAccountId()) == false)
            return false;
        if (other.getTopicId() == null ^ this.getTopicId() == null)
            return false;
        if (other.getTopicId() != null && other.getTopicId().equals(this.getTopicId()) == false)
            return false;
        if (other.getAnswers() == null ^ this.getAnswers() == null)
            return false;
        if (other.getAnswers() != null && other.getAnswers().equals(this.getAnswers()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getAwsAccountId() == null) ? 0 : getAwsAccountId().hashCode());
        hashCode = prime * hashCode + ((getTopicId() == null) ? 0 : getTopicId().hashCode());
        hashCode = prime * hashCode + ((getAnswers() == null) ? 0 : getAnswers().hashCode());
        return hashCode;
    }

    @Override
    public BatchCreateTopicReviewedAnswerRequest clone() {
        return (BatchCreateTopicReviewedAnswerRequest) super.clone();
    }

}
