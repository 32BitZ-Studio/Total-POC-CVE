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
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/sagemaker-2017-07-24/DeleteHubContentReference"
 *      target="_top">AWS API Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class DeleteHubContentReferenceRequest extends com.amazonaws.AmazonWebServiceRequest implements Serializable, Cloneable {

    /**
     * <p>
     * The name of the hub to delete the hub content reference from.
     * </p>
     */
    private String hubName;
    /**
     * <p>
     * The type of hub content reference to delete. The only supported type of hub content reference to delete is
     * <code>ModelReference</code>.
     * </p>
     */
    private String hubContentType;
    /**
     * <p>
     * The name of the hub content to delete.
     * </p>
     */
    private String hubContentName;

    /**
     * <p>
     * The name of the hub to delete the hub content reference from.
     * </p>
     * 
     * @param hubName
     *        The name of the hub to delete the hub content reference from.
     */

    public void setHubName(String hubName) {
        this.hubName = hubName;
    }

    /**
     * <p>
     * The name of the hub to delete the hub content reference from.
     * </p>
     * 
     * @return The name of the hub to delete the hub content reference from.
     */

    public String getHubName() {
        return this.hubName;
    }

    /**
     * <p>
     * The name of the hub to delete the hub content reference from.
     * </p>
     * 
     * @param hubName
     *        The name of the hub to delete the hub content reference from.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public DeleteHubContentReferenceRequest withHubName(String hubName) {
        setHubName(hubName);
        return this;
    }

    /**
     * <p>
     * The type of hub content reference to delete. The only supported type of hub content reference to delete is
     * <code>ModelReference</code>.
     * </p>
     * 
     * @param hubContentType
     *        The type of hub content reference to delete. The only supported type of hub content reference to delete is
     *        <code>ModelReference</code>.
     * @see HubContentType
     */

    public void setHubContentType(String hubContentType) {
        this.hubContentType = hubContentType;
    }

    /**
     * <p>
     * The type of hub content reference to delete. The only supported type of hub content reference to delete is
     * <code>ModelReference</code>.
     * </p>
     * 
     * @return The type of hub content reference to delete. The only supported type of hub content reference to delete
     *         is <code>ModelReference</code>.
     * @see HubContentType
     */

    public String getHubContentType() {
        return this.hubContentType;
    }

    /**
     * <p>
     * The type of hub content reference to delete. The only supported type of hub content reference to delete is
     * <code>ModelReference</code>.
     * </p>
     * 
     * @param hubContentType
     *        The type of hub content reference to delete. The only supported type of hub content reference to delete is
     *        <code>ModelReference</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see HubContentType
     */

    public DeleteHubContentReferenceRequest withHubContentType(String hubContentType) {
        setHubContentType(hubContentType);
        return this;
    }

    /**
     * <p>
     * The type of hub content reference to delete. The only supported type of hub content reference to delete is
     * <code>ModelReference</code>.
     * </p>
     * 
     * @param hubContentType
     *        The type of hub content reference to delete. The only supported type of hub content reference to delete is
     *        <code>ModelReference</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see HubContentType
     */

    public DeleteHubContentReferenceRequest withHubContentType(HubContentType hubContentType) {
        this.hubContentType = hubContentType.toString();
        return this;
    }

    /**
     * <p>
     * The name of the hub content to delete.
     * </p>
     * 
     * @param hubContentName
     *        The name of the hub content to delete.
     */

    public void setHubContentName(String hubContentName) {
        this.hubContentName = hubContentName;
    }

    /**
     * <p>
     * The name of the hub content to delete.
     * </p>
     * 
     * @return The name of the hub content to delete.
     */

    public String getHubContentName() {
        return this.hubContentName;
    }

    /**
     * <p>
     * The name of the hub content to delete.
     * </p>
     * 
     * @param hubContentName
     *        The name of the hub content to delete.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public DeleteHubContentReferenceRequest withHubContentName(String hubContentName) {
        setHubContentName(hubContentName);
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
        if (getHubName() != null)
            sb.append("HubName: ").append(getHubName()).append(",");
        if (getHubContentType() != null)
            sb.append("HubContentType: ").append(getHubContentType()).append(",");
        if (getHubContentName() != null)
            sb.append("HubContentName: ").append(getHubContentName());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof DeleteHubContentReferenceRequest == false)
            return false;
        DeleteHubContentReferenceRequest other = (DeleteHubContentReferenceRequest) obj;
        if (other.getHubName() == null ^ this.getHubName() == null)
            return false;
        if (other.getHubName() != null && other.getHubName().equals(this.getHubName()) == false)
            return false;
        if (other.getHubContentType() == null ^ this.getHubContentType() == null)
            return false;
        if (other.getHubContentType() != null && other.getHubContentType().equals(this.getHubContentType()) == false)
            return false;
        if (other.getHubContentName() == null ^ this.getHubContentName() == null)
            return false;
        if (other.getHubContentName() != null && other.getHubContentName().equals(this.getHubContentName()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getHubName() == null) ? 0 : getHubName().hashCode());
        hashCode = prime * hashCode + ((getHubContentType() == null) ? 0 : getHubContentType().hashCode());
        hashCode = prime * hashCode + ((getHubContentName() == null) ? 0 : getHubContentName().hashCode());
        return hashCode;
    }

    @Override
    public DeleteHubContentReferenceRequest clone() {
        return (DeleteHubContentReferenceRequest) super.clone();
    }

}
