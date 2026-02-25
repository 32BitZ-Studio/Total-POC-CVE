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
 * The definition for a <code>CreateTopicReviewedAnswer</code>.
 * </p>
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/quicksight-2018-04-01/CreateTopicReviewedAnswer"
 *      target="_top">AWS API Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class CreateTopicReviewedAnswer implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * The answer ID for the <code>CreateTopicReviewedAnswer</code>.
     * </p>
     */
    private String answerId;
    /**
     * <p>
     * The Dataset arn for the <code>CreateTopicReviewedAnswer</code>.
     * </p>
     */
    private String datasetArn;
    /**
     * <p>
     * The Question to be created.
     * </p>
     */
    private String question;
    /**
     * <p>
     * The Mir for the <code>CreateTopicReviewedAnswer</code>.
     * </p>
     */
    private TopicIR mir;
    /**
     * <p>
     * The <code>PrimaryVisual</code> for the <code>CreateTopicReviewedAnswer</code>.
     * </p>
     */
    private TopicVisual primaryVisual;
    /**
     * <p>
     * The template for the <code>CreateTopicReviewedAnswer</code>.
     * </p>
     */
    private TopicTemplate template;

    /**
     * <p>
     * The answer ID for the <code>CreateTopicReviewedAnswer</code>.
     * </p>
     * 
     * @param answerId
     *        The answer ID for the <code>CreateTopicReviewedAnswer</code>.
     */

    public void setAnswerId(String answerId) {
        this.answerId = answerId;
    }

    /**
     * <p>
     * The answer ID for the <code>CreateTopicReviewedAnswer</code>.
     * </p>
     * 
     * @return The answer ID for the <code>CreateTopicReviewedAnswer</code>.
     */

    public String getAnswerId() {
        return this.answerId;
    }

    /**
     * <p>
     * The answer ID for the <code>CreateTopicReviewedAnswer</code>.
     * </p>
     * 
     * @param answerId
     *        The answer ID for the <code>CreateTopicReviewedAnswer</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public CreateTopicReviewedAnswer withAnswerId(String answerId) {
        setAnswerId(answerId);
        return this;
    }

    /**
     * <p>
     * The Dataset arn for the <code>CreateTopicReviewedAnswer</code>.
     * </p>
     * 
     * @param datasetArn
     *        The Dataset arn for the <code>CreateTopicReviewedAnswer</code>.
     */

    public void setDatasetArn(String datasetArn) {
        this.datasetArn = datasetArn;
    }

    /**
     * <p>
     * The Dataset arn for the <code>CreateTopicReviewedAnswer</code>.
     * </p>
     * 
     * @return The Dataset arn for the <code>CreateTopicReviewedAnswer</code>.
     */

    public String getDatasetArn() {
        return this.datasetArn;
    }

    /**
     * <p>
     * The Dataset arn for the <code>CreateTopicReviewedAnswer</code>.
     * </p>
     * 
     * @param datasetArn
     *        The Dataset arn for the <code>CreateTopicReviewedAnswer</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public CreateTopicReviewedAnswer withDatasetArn(String datasetArn) {
        setDatasetArn(datasetArn);
        return this;
    }

    /**
     * <p>
     * The Question to be created.
     * </p>
     * 
     * @param question
     *        The Question to be created.
     */

    public void setQuestion(String question) {
        this.question = question;
    }

    /**
     * <p>
     * The Question to be created.
     * </p>
     * 
     * @return The Question to be created.
     */

    public String getQuestion() {
        return this.question;
    }

    /**
     * <p>
     * The Question to be created.
     * </p>
     * 
     * @param question
     *        The Question to be created.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public CreateTopicReviewedAnswer withQuestion(String question) {
        setQuestion(question);
        return this;
    }

    /**
     * <p>
     * The Mir for the <code>CreateTopicReviewedAnswer</code>.
     * </p>
     * 
     * @param mir
     *        The Mir for the <code>CreateTopicReviewedAnswer</code>.
     */

    public void setMir(TopicIR mir) {
        this.mir = mir;
    }

    /**
     * <p>
     * The Mir for the <code>CreateTopicReviewedAnswer</code>.
     * </p>
     * 
     * @return The Mir for the <code>CreateTopicReviewedAnswer</code>.
     */

    public TopicIR getMir() {
        return this.mir;
    }

    /**
     * <p>
     * The Mir for the <code>CreateTopicReviewedAnswer</code>.
     * </p>
     * 
     * @param mir
     *        The Mir for the <code>CreateTopicReviewedAnswer</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public CreateTopicReviewedAnswer withMir(TopicIR mir) {
        setMir(mir);
        return this;
    }

    /**
     * <p>
     * The <code>PrimaryVisual</code> for the <code>CreateTopicReviewedAnswer</code>.
     * </p>
     * 
     * @param primaryVisual
     *        The <code>PrimaryVisual</code> for the <code>CreateTopicReviewedAnswer</code>.
     */

    public void setPrimaryVisual(TopicVisual primaryVisual) {
        this.primaryVisual = primaryVisual;
    }

    /**
     * <p>
     * The <code>PrimaryVisual</code> for the <code>CreateTopicReviewedAnswer</code>.
     * </p>
     * 
     * @return The <code>PrimaryVisual</code> for the <code>CreateTopicReviewedAnswer</code>.
     */

    public TopicVisual getPrimaryVisual() {
        return this.primaryVisual;
    }

    /**
     * <p>
     * The <code>PrimaryVisual</code> for the <code>CreateTopicReviewedAnswer</code>.
     * </p>
     * 
     * @param primaryVisual
     *        The <code>PrimaryVisual</code> for the <code>CreateTopicReviewedAnswer</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public CreateTopicReviewedAnswer withPrimaryVisual(TopicVisual primaryVisual) {
        setPrimaryVisual(primaryVisual);
        return this;
    }

    /**
     * <p>
     * The template for the <code>CreateTopicReviewedAnswer</code>.
     * </p>
     * 
     * @param template
     *        The template for the <code>CreateTopicReviewedAnswer</code>.
     */

    public void setTemplate(TopicTemplate template) {
        this.template = template;
    }

    /**
     * <p>
     * The template for the <code>CreateTopicReviewedAnswer</code>.
     * </p>
     * 
     * @return The template for the <code>CreateTopicReviewedAnswer</code>.
     */

    public TopicTemplate getTemplate() {
        return this.template;
    }

    /**
     * <p>
     * The template for the <code>CreateTopicReviewedAnswer</code>.
     * </p>
     * 
     * @param template
     *        The template for the <code>CreateTopicReviewedAnswer</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public CreateTopicReviewedAnswer withTemplate(TopicTemplate template) {
        setTemplate(template);
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
        if (getDatasetArn() != null)
            sb.append("DatasetArn: ").append(getDatasetArn()).append(",");
        if (getQuestion() != null)
            sb.append("Question: ").append(getQuestion()).append(",");
        if (getMir() != null)
            sb.append("Mir: ").append(getMir()).append(",");
        if (getPrimaryVisual() != null)
            sb.append("PrimaryVisual: ").append(getPrimaryVisual()).append(",");
        if (getTemplate() != null)
            sb.append("Template: ").append(getTemplate());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof CreateTopicReviewedAnswer == false)
            return false;
        CreateTopicReviewedAnswer other = (CreateTopicReviewedAnswer) obj;
        if (other.getAnswerId() == null ^ this.getAnswerId() == null)
            return false;
        if (other.getAnswerId() != null && other.getAnswerId().equals(this.getAnswerId()) == false)
            return false;
        if (other.getDatasetArn() == null ^ this.getDatasetArn() == null)
            return false;
        if (other.getDatasetArn() != null && other.getDatasetArn().equals(this.getDatasetArn()) == false)
            return false;
        if (other.getQuestion() == null ^ this.getQuestion() == null)
            return false;
        if (other.getQuestion() != null && other.getQuestion().equals(this.getQuestion()) == false)
            return false;
        if (other.getMir() == null ^ this.getMir() == null)
            return false;
        if (other.getMir() != null && other.getMir().equals(this.getMir()) == false)
            return false;
        if (other.getPrimaryVisual() == null ^ this.getPrimaryVisual() == null)
            return false;
        if (other.getPrimaryVisual() != null && other.getPrimaryVisual().equals(this.getPrimaryVisual()) == false)
            return false;
        if (other.getTemplate() == null ^ this.getTemplate() == null)
            return false;
        if (other.getTemplate() != null && other.getTemplate().equals(this.getTemplate()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getAnswerId() == null) ? 0 : getAnswerId().hashCode());
        hashCode = prime * hashCode + ((getDatasetArn() == null) ? 0 : getDatasetArn().hashCode());
        hashCode = prime * hashCode + ((getQuestion() == null) ? 0 : getQuestion().hashCode());
        hashCode = prime * hashCode + ((getMir() == null) ? 0 : getMir().hashCode());
        hashCode = prime * hashCode + ((getPrimaryVisual() == null) ? 0 : getPrimaryVisual().hashCode());
        hashCode = prime * hashCode + ((getTemplate() == null) ? 0 : getTemplate().hashCode());
        return hashCode;
    }

    @Override
    public CreateTopicReviewedAnswer clone() {
        try {
            return (CreateTopicReviewedAnswer) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.quicksight.model.transform.CreateTopicReviewedAnswerMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
