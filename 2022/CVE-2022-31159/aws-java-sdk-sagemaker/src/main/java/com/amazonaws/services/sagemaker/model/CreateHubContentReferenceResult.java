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
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/sagemaker-2017-07-24/CreateHubContentReference"
 *      target="_top">AWS API Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class CreateHubContentReferenceResult extends com.amazonaws.AmazonWebServiceResult<com.amazonaws.ResponseMetadata> implements Serializable, Cloneable {

    /**
     * <p>
     * The ARN of the hub that the hub content reference was added to.
     * </p>
     */
    private String hubArn;
    /**
     * <p>
     * The ARN of the hub content.
     * </p>
     */
    private String hubContentArn;

    /**
     * <p>
     * The ARN of the hub that the hub content reference was added to.
     * </p>
     * 
     * @param hubArn
     *        The ARN of the hub that the hub content reference was added to.
     */

    public void setHubArn(String hubArn) {
        this.hubArn = hubArn;
    }

    /**
     * <p>
     * The ARN of the hub that the hub content reference was added to.
     * </p>
     * 
     * @return The ARN of the hub that the hub content reference was added to.
     */

    public String getHubArn() {
        return this.hubArn;
    }

    /**
     * <p>
     * The ARN of the hub that the hub content reference was added to.
     * </p>
     * 
     * @param hubArn
     *        The ARN of the hub that the hub content reference was added to.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public CreateHubContentReferenceResult withHubArn(String hubArn) {
        setHubArn(hubArn);
        return this;
    }

    /**
     * <p>
     * The ARN of the hub content.
     * </p>
     * 
     * @param hubContentArn
     *        The ARN of the hub content.
     */

    public void setHubContentArn(String hubContentArn) {
        this.hubContentArn = hubContentArn;
    }

    /**
     * <p>
     * The ARN of the hub content.
     * </p>
     * 
     * @return The ARN of the hub content.
     */

    public String getHubContentArn() {
        return this.hubContentArn;
    }

    /**
     * <p>
     * The ARN of the hub content.
     * </p>
     * 
     * @param hubContentArn
     *        The ARN of the hub content.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public CreateHubContentReferenceResult withHubContentArn(String hubContentArn) {
        setHubContentArn(hubContentArn);
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
        if (getHubArn() != null)
            sb.append("HubArn: ").append(getHubArn()).append(",");
        if (getHubContentArn() != null)
            sb.append("HubContentArn: ").append(getHubContentArn());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof CreateHubContentReferenceResult == false)
            return false;
        CreateHubContentReferenceResult other = (CreateHubContentReferenceResult) obj;
        if (other.getHubArn() == null ^ this.getHubArn() == null)
            return false;
        if (other.getHubArn() != null && other.getHubArn().equals(this.getHubArn()) == false)
            return false;
        if (other.getHubContentArn() == null ^ this.getHubContentArn() == null)
            return false;
        if (other.getHubContentArn() != null && other.getHubContentArn().equals(this.getHubContentArn()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getHubArn() == null) ? 0 : getHubArn().hashCode());
        hashCode = prime * hashCode + ((getHubContentArn() == null) ? 0 : getHubContentArn().hashCode());
        return hashCode;
    }

    @Override
    public CreateHubContentReferenceResult clone() {
        try {
            return (CreateHubContentReferenceResult) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

}
