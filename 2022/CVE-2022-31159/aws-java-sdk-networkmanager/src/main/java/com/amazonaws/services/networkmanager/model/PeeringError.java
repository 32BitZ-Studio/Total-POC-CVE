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
 * Describes an error associated with a peering request.
 * </p>
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/networkmanager-2019-07-05/PeeringError" target="_top">AWS API
 *      Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class PeeringError implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * The error code for the peering request.
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
     * The ARN of the requested peering resource.
     * </p>
     */
    private String resourceArn;
    /**
     * <p>
     * The ID of the Peering request.
     * </p>
     */
    private String requestId;
    /**
     * <p>
     * Provides additional information about missing permissions for the peering error.
     * </p>
     */
    private PermissionsErrorContext missingPermissionsContext;

    /**
     * <p>
     * The error code for the peering request.
     * </p>
     * 
     * @param code
     *        The error code for the peering request.
     * @see PeeringErrorCode
     */

    public void setCode(String code) {
        this.code = code;
    }

    /**
     * <p>
     * The error code for the peering request.
     * </p>
     * 
     * @return The error code for the peering request.
     * @see PeeringErrorCode
     */

    public String getCode() {
        return this.code;
    }

    /**
     * <p>
     * The error code for the peering request.
     * </p>
     * 
     * @param code
     *        The error code for the peering request.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see PeeringErrorCode
     */

    public PeeringError withCode(String code) {
        setCode(code);
        return this;
    }

    /**
     * <p>
     * The error code for the peering request.
     * </p>
     * 
     * @param code
     *        The error code for the peering request.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see PeeringErrorCode
     */

    public PeeringError withCode(PeeringErrorCode code) {
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

    public PeeringError withMessage(String message) {
        setMessage(message);
        return this;
    }

    /**
     * <p>
     * The ARN of the requested peering resource.
     * </p>
     * 
     * @param resourceArn
     *        The ARN of the requested peering resource.
     */

    public void setResourceArn(String resourceArn) {
        this.resourceArn = resourceArn;
    }

    /**
     * <p>
     * The ARN of the requested peering resource.
     * </p>
     * 
     * @return The ARN of the requested peering resource.
     */

    public String getResourceArn() {
        return this.resourceArn;
    }

    /**
     * <p>
     * The ARN of the requested peering resource.
     * </p>
     * 
     * @param resourceArn
     *        The ARN of the requested peering resource.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public PeeringError withResourceArn(String resourceArn) {
        setResourceArn(resourceArn);
        return this;
    }

    /**
     * <p>
     * The ID of the Peering request.
     * </p>
     * 
     * @param requestId
     *        The ID of the Peering request.
     */

    public void setRequestId(String requestId) {
        this.requestId = requestId;
    }

    /**
     * <p>
     * The ID of the Peering request.
     * </p>
     * 
     * @return The ID of the Peering request.
     */

    public String getRequestId() {
        return this.requestId;
    }

    /**
     * <p>
     * The ID of the Peering request.
     * </p>
     * 
     * @param requestId
     *        The ID of the Peering request.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public PeeringError withRequestId(String requestId) {
        setRequestId(requestId);
        return this;
    }

    /**
     * <p>
     * Provides additional information about missing permissions for the peering error.
     * </p>
     * 
     * @param missingPermissionsContext
     *        Provides additional information about missing permissions for the peering error.
     */

    public void setMissingPermissionsContext(PermissionsErrorContext missingPermissionsContext) {
        this.missingPermissionsContext = missingPermissionsContext;
    }

    /**
     * <p>
     * Provides additional information about missing permissions for the peering error.
     * </p>
     * 
     * @return Provides additional information about missing permissions for the peering error.
     */

    public PermissionsErrorContext getMissingPermissionsContext() {
        return this.missingPermissionsContext;
    }

    /**
     * <p>
     * Provides additional information about missing permissions for the peering error.
     * </p>
     * 
     * @param missingPermissionsContext
     *        Provides additional information about missing permissions for the peering error.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public PeeringError withMissingPermissionsContext(PermissionsErrorContext missingPermissionsContext) {
        setMissingPermissionsContext(missingPermissionsContext);
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
            sb.append("RequestId: ").append(getRequestId()).append(",");
        if (getMissingPermissionsContext() != null)
            sb.append("MissingPermissionsContext: ").append(getMissingPermissionsContext());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof PeeringError == false)
            return false;
        PeeringError other = (PeeringError) obj;
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
        if (other.getMissingPermissionsContext() == null ^ this.getMissingPermissionsContext() == null)
            return false;
        if (other.getMissingPermissionsContext() != null && other.getMissingPermissionsContext().equals(this.getMissingPermissionsContext()) == false)
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
        hashCode = prime * hashCode + ((getMissingPermissionsContext() == null) ? 0 : getMissingPermissionsContext().hashCode());
        return hashCode;
    }

    @Override
    public PeeringError clone() {
        try {
            return (PeeringError) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.networkmanager.model.transform.PeeringErrorMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
