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
 * The definition for a <code>InvalidTopicReviewedAnswer</code>.
 * </p>
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/quicksight-2018-04-01/InvalidTopicReviewedAnswer"
 *      target="_top">AWS API Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class InvalidTopicReviewedAnswer implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * The answer ID for the <code>InvalidTopicReviewedAnswer</code>.
     * </p>
     */
    private String answerId;
    /**
     * <p>
     * The error that is returned for the <code>InvalidTopicReviewedAnswer</code>.
     * </p>
     */
    private String error;

    /**
     * <p>
     * The answer ID for the <code>InvalidTopicReviewedAnswer</code>.
     * </p>
     * 
     * @param answerId
     *        The answer ID for the <code>InvalidTopicReviewedAnswer</code>.
     */

    public void setAnswerId(String answerId) {
        this.answerId = answerId;
    }

    /**
     * <p>
     * The answer ID for the <code>InvalidTopicReviewedAnswer</code>.
     * </p>
     * 
     * @return The answer ID for the <code>InvalidTopicReviewedAnswer</code>.
     */

    public String getAnswerId() {
        return this.answerId;
    }

    /**
     * <p>
     * The answer ID for the <code>InvalidTopicReviewedAnswer</code>.
     * </p>
     * 
     * @param answerId
     *        The answer ID for the <code>InvalidTopicReviewedAnswer</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public InvalidTopicReviewedAnswer withAnswerId(String answerId) {
        setAnswerId(answerId);
        return this;
    }

    /**
     * <p>
     * The error that is returned for the <code>InvalidTopicReviewedAnswer</code>.
     * </p>
     * 
     * @param error
     *        The error that is returned for the <code>InvalidTopicReviewedAnswer</code>.
     * @see ReviewedAnswerErrorCode
     */

    public void setError(String error) {
        this.error = error;
    }

    /**
     * <p>
     * The error that is returned for the <code>InvalidTopicReviewedAnswer</code>.
     * </p>
     * 
     * @return The error that is returned for the <code>InvalidTopicReviewedAnswer</code>.
     * @see ReviewedAnswerErrorCode
     */

    public String getError() {
        return this.error;
    }

    /**
     * <p>
     * The error that is returned for the <code>InvalidTopicReviewedAnswer</code>.
     * </p>
     * 
     * @param error
     *        The error that is returned for the <code>InvalidTopicReviewedAnswer</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see ReviewedAnswerErrorCode
     */

    public InvalidTopicReviewedAnswer withError(String error) {
        setError(error);
        return this;
    }

    /**
     * <p>
     * The error that is returned for the <code>InvalidTopicReviewedAnswer</code>.
     * </p>
     * 
     * @param error
     *        The error that is returned for the <code>InvalidTopicReviewedAnswer</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see ReviewedAnswerErrorCode
     */

    public InvalidTopicReviewedAnswer withError(ReviewedAnswerErrorCode error) {
        this.error = error.toString();
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
        if (getAnswerId() != null)
            sb.append("AnswerId: ").append(getAnswerId()).append(",");
        if (getError() != null)
            sb.append("Error: ").append(getError());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof InvalidTopicReviewedAnswer == false)
            return false;
        InvalidTopicReviewedAnswer other = (InvalidTopicReviewedAnswer) obj;
        if (other.getAnswerId() == null ^ this.getAnswerId() == null)
            return false;
        if (other.getAnswerId() != null && other.getAnswerId().equals(this.getAnswerId()) == false)
            return false;
        if (other.getError() == null ^ this.getError() == null)
            return false;
        if (other.getError() != null && other.getError().equals(this.getError()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getAnswerId() == null) ? 0 : getAnswerId().hashCode());
        hashCode = prime * hashCode + ((getError() == null) ? 0 : getError().hashCode());
        return hashCode;
    }

    @Override
    public InvalidTopicReviewedAnswer clone() {
        try {
            return (InvalidTopicReviewedAnswer) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.quicksight.model.transform.InvalidTopicReviewedAnswerMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
