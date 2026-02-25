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
import com.amazonaws.protocol.StructuredPojo;
import com.amazonaws.protocol.ProtocolMarshaller;

/**
 * <p>
 * The model card associated with the model package. Since <code>ModelPackageModelCard</code> is tied to a model
 * package, it is a specific usage of a model card and its schema is simplified compared to the schema of
 * <code>ModelCard</code>. The <code>ModelPackageModelCard</code> schema does not include
 * <code>model_package_details</code>, and <code>model_overview</code> is composed of the <code>model_creator</code> and
 * <code>model_artifact</code> properties. For more information about the model package model card schema, see <a
 * href="https://docs.aws.amazon.com/sagemaker/latest/dg/model-registry-details.html#model-card-schema">Model package
 * model card schema</a>. For more information about the model card associated with the model package, see <a
 * href="https://docs.aws.amazon.com/sagemaker/latest/dg/model-registry-details.html">View the Details of a Model
 * Version</a>.
 * </p>
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/sagemaker-2017-07-24/ModelPackageModelCard" target="_top">AWS
 *      API Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class ModelPackageModelCard implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * The content of the model card. The content must follow the schema described in <a
     * href="https://docs.aws.amazon.com/sagemaker/latest/dg/model-registry-details.html#model-card-schema">Model
     * Package Model Card Schema</a>.
     * </p>
     */
    private String modelCardContent;
    /**
     * <p>
     * The approval status of the model card within your organization. Different organizations might have different
     * criteria for model card review and approval.
     * </p>
     * <ul>
     * <li>
     * <p>
     * <code>Draft</code>: The model card is a work in progress.
     * </p>
     * </li>
     * <li>
     * <p>
     * <code>PendingReview</code>: The model card is pending review.
     * </p>
     * </li>
     * <li>
     * <p>
     * <code>Approved</code>: The model card is approved.
     * </p>
     * </li>
     * <li>
     * <p>
     * <code>Archived</code>: The model card is archived. No more updates can be made to the model card content. If you
     * try to update the model card content, you will receive the message <code>Model Card is in Archived state</code>.
     * </p>
     * </li>
     * </ul>
     */
    private String modelCardStatus;

    /**
     * <p>
     * The content of the model card. The content must follow the schema described in <a
     * href="https://docs.aws.amazon.com/sagemaker/latest/dg/model-registry-details.html#model-card-schema">Model
     * Package Model Card Schema</a>.
     * </p>
     * 
     * @param modelCardContent
     *        The content of the model card. The content must follow the schema described in <a
     *        href="https://docs.aws.amazon.com/sagemaker/latest/dg/model-registry-details.html#model-card-schema">Model
     *        Package Model Card Schema</a>.
     */

    public void setModelCardContent(String modelCardContent) {
        this.modelCardContent = modelCardContent;
    }

    /**
     * <p>
     * The content of the model card. The content must follow the schema described in <a
     * href="https://docs.aws.amazon.com/sagemaker/latest/dg/model-registry-details.html#model-card-schema">Model
     * Package Model Card Schema</a>.
     * </p>
     * 
     * @return The content of the model card. The content must follow the schema described in <a
     *         href="https://docs.aws.amazon.com/sagemaker/latest/dg/model-registry-details.html#model-card-schema"
     *         >Model Package Model Card Schema</a>.
     */

    public String getModelCardContent() {
        return this.modelCardContent;
    }

    /**
     * <p>
     * The content of the model card. The content must follow the schema described in <a
     * href="https://docs.aws.amazon.com/sagemaker/latest/dg/model-registry-details.html#model-card-schema">Model
     * Package Model Card Schema</a>.
     * </p>
     * 
     * @param modelCardContent
     *        The content of the model card. The content must follow the schema described in <a
     *        href="https://docs.aws.amazon.com/sagemaker/latest/dg/model-registry-details.html#model-card-schema">Model
     *        Package Model Card Schema</a>.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ModelPackageModelCard withModelCardContent(String modelCardContent) {
        setModelCardContent(modelCardContent);
        return this;
    }

    /**
     * <p>
     * The approval status of the model card within your organization. Different organizations might have different
     * criteria for model card review and approval.
     * </p>
     * <ul>
     * <li>
     * <p>
     * <code>Draft</code>: The model card is a work in progress.
     * </p>
     * </li>
     * <li>
     * <p>
     * <code>PendingReview</code>: The model card is pending review.
     * </p>
     * </li>
     * <li>
     * <p>
     * <code>Approved</code>: The model card is approved.
     * </p>
     * </li>
     * <li>
     * <p>
     * <code>Archived</code>: The model card is archived. No more updates can be made to the model card content. If you
     * try to update the model card content, you will receive the message <code>Model Card is in Archived state</code>.
     * </p>
     * </li>
     * </ul>
     * 
     * @param modelCardStatus
     *        The approval status of the model card within your organization. Different organizations might have
     *        different criteria for model card review and approval.</p>
     *        <ul>
     *        <li>
     *        <p>
     *        <code>Draft</code>: The model card is a work in progress.
     *        </p>
     *        </li>
     *        <li>
     *        <p>
     *        <code>PendingReview</code>: The model card is pending review.
     *        </p>
     *        </li>
     *        <li>
     *        <p>
     *        <code>Approved</code>: The model card is approved.
     *        </p>
     *        </li>
     *        <li>
     *        <p>
     *        <code>Archived</code>: The model card is archived. No more updates can be made to the model card content.
     *        If you try to update the model card content, you will receive the message
     *        <code>Model Card is in Archived state</code>.
     *        </p>
     *        </li>
     * @see ModelCardStatus
     */

    public void setModelCardStatus(String modelCardStatus) {
        this.modelCardStatus = modelCardStatus;
    }

    /**
     * <p>
     * The approval status of the model card within your organization. Different organizations might have different
     * criteria for model card review and approval.
     * </p>
     * <ul>
     * <li>
     * <p>
     * <code>Draft</code>: The model card is a work in progress.
     * </p>
     * </li>
     * <li>
     * <p>
     * <code>PendingReview</code>: The model card is pending review.
     * </p>
     * </li>
     * <li>
     * <p>
     * <code>Approved</code>: The model card is approved.
     * </p>
     * </li>
     * <li>
     * <p>
     * <code>Archived</code>: The model card is archived. No more updates can be made to the model card content. If you
     * try to update the model card content, you will receive the message <code>Model Card is in Archived state</code>.
     * </p>
     * </li>
     * </ul>
     * 
     * @return The approval status of the model card within your organization. Different organizations might have
     *         different criteria for model card review and approval.</p>
     *         <ul>
     *         <li>
     *         <p>
     *         <code>Draft</code>: The model card is a work in progress.
     *         </p>
     *         </li>
     *         <li>
     *         <p>
     *         <code>PendingReview</code>: The model card is pending review.
     *         </p>
     *         </li>
     *         <li>
     *         <p>
     *         <code>Approved</code>: The model card is approved.
     *         </p>
     *         </li>
     *         <li>
     *         <p>
     *         <code>Archived</code>: The model card is archived. No more updates can be made to the model card content.
     *         If you try to update the model card content, you will receive the message
     *         <code>Model Card is in Archived state</code>.
     *         </p>
     *         </li>
     * @see ModelCardStatus
     */

    public String getModelCardStatus() {
        return this.modelCardStatus;
    }

    /**
     * <p>
     * The approval status of the model card within your organization. Different organizations might have different
     * criteria for model card review and approval.
     * </p>
     * <ul>
     * <li>
     * <p>
     * <code>Draft</code>: The model card is a work in progress.
     * </p>
     * </li>
     * <li>
     * <p>
     * <code>PendingReview</code>: The model card is pending review.
     * </p>
     * </li>
     * <li>
     * <p>
     * <code>Approved</code>: The model card is approved.
     * </p>
     * </li>
     * <li>
     * <p>
     * <code>Archived</code>: The model card is archived. No more updates can be made to the model card content. If you
     * try to update the model card content, you will receive the message <code>Model Card is in Archived state</code>.
     * </p>
     * </li>
     * </ul>
     * 
     * @param modelCardStatus
     *        The approval status of the model card within your organization. Different organizations might have
     *        different criteria for model card review and approval.</p>
     *        <ul>
     *        <li>
     *        <p>
     *        <code>Draft</code>: The model card is a work in progress.
     *        </p>
     *        </li>
     *        <li>
     *        <p>
     *        <code>PendingReview</code>: The model card is pending review.
     *        </p>
     *        </li>
     *        <li>
     *        <p>
     *        <code>Approved</code>: The model card is approved.
     *        </p>
     *        </li>
     *        <li>
     *        <p>
     *        <code>Archived</code>: The model card is archived. No more updates can be made to the model card content.
     *        If you try to update the model card content, you will receive the message
     *        <code>Model Card is in Archived state</code>.
     *        </p>
     *        </li>
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see ModelCardStatus
     */

    public ModelPackageModelCard withModelCardStatus(String modelCardStatus) {
        setModelCardStatus(modelCardStatus);
        return this;
    }

    /**
     * <p>
     * The approval status of the model card within your organization. Different organizations might have different
     * criteria for model card review and approval.
     * </p>
     * <ul>
     * <li>
     * <p>
     * <code>Draft</code>: The model card is a work in progress.
     * </p>
     * </li>
     * <li>
     * <p>
     * <code>PendingReview</code>: The model card is pending review.
     * </p>
     * </li>
     * <li>
     * <p>
     * <code>Approved</code>: The model card is approved.
     * </p>
     * </li>
     * <li>
     * <p>
     * <code>Archived</code>: The model card is archived. No more updates can be made to the model card content. If you
     * try to update the model card content, you will receive the message <code>Model Card is in Archived state</code>.
     * </p>
     * </li>
     * </ul>
     * 
     * @param modelCardStatus
     *        The approval status of the model card within your organization. Different organizations might have
     *        different criteria for model card review and approval.</p>
     *        <ul>
     *        <li>
     *        <p>
     *        <code>Draft</code>: The model card is a work in progress.
     *        </p>
     *        </li>
     *        <li>
     *        <p>
     *        <code>PendingReview</code>: The model card is pending review.
     *        </p>
     *        </li>
     *        <li>
     *        <p>
     *        <code>Approved</code>: The model card is approved.
     *        </p>
     *        </li>
     *        <li>
     *        <p>
     *        <code>Archived</code>: The model card is archived. No more updates can be made to the model card content.
     *        If you try to update the model card content, you will receive the message
     *        <code>Model Card is in Archived state</code>.
     *        </p>
     *        </li>
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see ModelCardStatus
     */

    public ModelPackageModelCard withModelCardStatus(ModelCardStatus modelCardStatus) {
        this.modelCardStatus = modelCardStatus.toString();
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
        if (getModelCardContent() != null)
            sb.append("ModelCardContent: ").append("***Sensitive Data Redacted***").append(",");
        if (getModelCardStatus() != null)
            sb.append("ModelCardStatus: ").append(getModelCardStatus());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof ModelPackageModelCard == false)
            return false;
        ModelPackageModelCard other = (ModelPackageModelCard) obj;
        if (other.getModelCardContent() == null ^ this.getModelCardContent() == null)
            return false;
        if (other.getModelCardContent() != null && other.getModelCardContent().equals(this.getModelCardContent()) == false)
            return false;
        if (other.getModelCardStatus() == null ^ this.getModelCardStatus() == null)
            return false;
        if (other.getModelCardStatus() != null && other.getModelCardStatus().equals(this.getModelCardStatus()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getModelCardContent() == null) ? 0 : getModelCardContent().hashCode());
        hashCode = prime * hashCode + ((getModelCardStatus() == null) ? 0 : getModelCardStatus().hashCode());
        return hashCode;
    }

    @Override
    public ModelPackageModelCard clone() {
        try {
            return (ModelPackageModelCard) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.sagemaker.model.transform.ModelPackageModelCardMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
