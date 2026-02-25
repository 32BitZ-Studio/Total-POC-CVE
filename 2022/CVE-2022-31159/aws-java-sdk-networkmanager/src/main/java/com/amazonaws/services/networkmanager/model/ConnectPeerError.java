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
package com.amazonaws.services.networkmanager.model;

import java.io.Serializable;
import javax.annotation.Generated;
import com.amazonaws.protocol.StructuredPojo;
import com.amazonaws.protocol.ProtocolMarshaller;

/**
 * <p>
 * Describes an error associated with a Connect peer request
 * </p>
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/networkmanager-2019-07-05/ConnectPeerError" target="_top">AWS
 *      API Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class ConnectPeerError implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * The error code for the Connect peer request.
     * </p>
     */
    private String code;
    /**
     * <p>
     * The message associated with the error <code>code</code>.
     * </p>
     */
    private String message;
    /**
     * <p>
     * The ARN of the requested Connect peer resource.
     * </p>
     */
    private String resourceArn;
    /**
     * <p>
     * The ID of the Connect peer request.
     * </p>
     */
    private String requestId;

    /**
     * <p>
     * The error code for the Connect peer request.
     * </p>
     * 
     * @param code
     *        The error code for the Connect peer request.
     * @see ConnectPeerErrorCode
     */

    public void setCode(String code) {
        this.code = code;
    }

    /**
     * <p>
     * The error code for the Connect peer request.
     * </p>
     * 
     * @return The error code for the Connect peer request.
     * @see ConnectPeerErrorCode
     */

    public String getCode() {
        return this.code;
    }

    /**
     * <p>
     * The error code for the Connect peer request.
     * </p>
     * 
     * @param code
     *        The error code for the Connect peer request.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see ConnectPeerErrorCode
     */

    public ConnectPeerError withCode(String code) {
        setCode(code);
        return this;
    }

    /**
     * <p>
     * The error code for the Connect peer request.
     * </p>
     * 
     * @param code
     *        The error code for the Connect peer request.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see ConnectPeerErrorCode
     */

    public ConnectPeerError withCode(ConnectPeerErrorCode code) {
        this.code = code.toString();
        return this;
    }

    /**
     * <p>
     * The message associated with the error <code>code</code>.
     * </p>
     * 
     * @param message
     *        The message associated with the error <code>code</code>.
     */

    public void setMessage(String message) {
        this.message = message;
    }

    /**
     * <p>
     * The message associated with the error <code>code</code>.
     * </p>
     * 
     * @return The message associated with the error <code>code</code>.
     */

    public String getMessage() {
        return this.message;
    }

    /**
     * <p>
     * The message associated with the error <code>code</code>.
     * </p>
     * 
     * @param message
     *        The message associated with the error <code>code</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ConnectPeerError withMessage(String message) {
        setMessage(message);
        return this;
    }

    /**
     * <p>
     * The ARN of the requested Connect peer resource.
     * </p>
     * 
     * @param resourceArn
     *        The ARN of the requested Connect peer resource.
     */

    public void setResourceArn(String resourceArn) {
        this.resourceArn = resourceArn;
    }

    /**
     * <p>
     * The ARN of the requested Connect peer resource.
     * </p>
     * 
     * @return The ARN of the requested Connect peer resource.
     */

    public String getResourceArn() {
        return this.resourceArn;
    }

    /**
     * <p>
     * The ARN of the requested Connect peer resource.
     * </p>
     * 
     * @param resourceArn
     *        The ARN of the requested Connect peer resource.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ConnectPeerError withResourceArn(String resourceArn) {
        setResourceArn(resourceArn);
        return this;
    }

    /**
     * <p>
     * The ID of the Connect peer request.
     * </p>
     * 
     * @param requestId
     *        The ID of the Connect peer request.
     */

    public void setRequestId(String requestId) {
        this.requestId = requestId;
    }

    /**
     * <p>
     * The ID of the Connect peer request.
     * </p>
     * 
     * @return The ID of the Connect peer request.
     */

    public String getRequestId() {
        return this.requestId;
    }

    /**
     * <p>
     * The ID of the Connect peer request.
     * </p>
     * 
     * @param requestId
     *        The ID of the Connect peer request.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ConnectPeerError withRequestId(String requestId) {
        setRequestId(requestId);
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
        if (getCode() != null)
            sb.append("Code: ").append(getCode()).append(",");
        if (getMessage() != null)
            sb.append("Message: ").append(getMessage()).append(",");
        if (getResourceArn() != null)
            sb.append("ResourceArn: ").append(getResourceArn()).append(",");
        if (getRequestId() != null)
            sb.append("RequestId: ").append(getRequestId());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof ConnectPeerError == false)
            return false;
        ConnectPeerError other = (ConnectPeerError) obj;
        if (other.getCode() == null ^ this.getCode() == null)
            return false;
        if (other.getCode() != null && other.getCode().equals(this.getCode()) == false)
            return false;
        if (other.getMessage() == null ^ this.getMessage() == null)
            return false;
        if (other.getMessage() != null && other.getMessage().equals(this.getMessage()) == false)
            return false;
        if (other.getResourceArn() == null ^ this.getResourceArn() == null)
            return false;
        if (other.getResourceArn() != null && other.getResourceArn().equals(this.getResourceArn()) == false)
            return false;
        if (other.getRequestId() == null ^ this.getRequestId() == null)
            return false;
        if (other.getRequestId() != null && other.getRequestId().equals(this.getRequestId()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getCode() == null) ? 0 : getCode().hashCode());
        hashCode = prime * hashCode + ((getMessage() == null) ? 0 : getMessage().hashCode());
        hashCode = prime * hashCode + ((getResourceArn() == null) ? 0 : getResourceArn().hashCode());
        hashCode = prime * hashCode + ((getRequestId() == null) ? 0 : getRequestId().hashCode());
        return hashCode;
    }

    @Override
    public ConnectPeerError clone() {
        try {
            return (ConnectPeerError) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.networkmanager.model.transform.ConnectPeerErrorMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
