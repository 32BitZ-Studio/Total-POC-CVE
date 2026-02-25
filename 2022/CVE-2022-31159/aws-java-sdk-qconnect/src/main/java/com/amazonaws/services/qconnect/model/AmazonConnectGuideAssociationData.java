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
package com.amazonaws.services.qconnect.model;

import java.io.Serializable;
import javax.annotation.Generated;
import com.amazonaws.protocol.StructuredPojo;
import com.amazonaws.protocol.ProtocolMarshaller;

/**
 * <p>
 * Content association data for a <a
 * href="https://docs.aws.amazon.com/connect/latest/adminguide/step-by-step-guided-experiences.html">step-by-step
 * guide</a>.
 * </p>
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/qconnect-2020-10-19/AmazonConnectGuideAssociationData"
 *      target="_top">AWS API Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class AmazonConnectGuideAssociationData implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * The Amazon Resource Name (ARN) of an Amazon Connect flow. Step-by-step guides are a type of flow.
     * </p>
     */
    private String flowId;

    /**
     * <p>
     * The Amazon Resource Name (ARN) of an Amazon Connect flow. Step-by-step guides are a type of flow.
     * </p>
     * 
     * @param flowId
     *        The Amazon Resource Name (ARN) of an Amazon Connect flow. Step-by-step guides are a type of flow.
     */

    public void setFlowId(String flowId) {
        this.flowId = flowId;
    }

    /**
     * <p>
     * The Amazon Resource Name (ARN) of an Amazon Connect flow. Step-by-step guides are a type of flow.
     * </p>
     * 
     * @return The Amazon Resource Name (ARN) of an Amazon Connect flow. Step-by-step guides are a type of flow.
     */

    public String getFlowId() {
        return this.flowId;
    }

    /**
     * <p>
     * The Amazon Resource Name (ARN) of an Amazon Connect flow. Step-by-step guides are a type of flow.
     * </p>
     * 
     * @param flowId
     *        The Amazon Resource Name (ARN) of an Amazon Connect flow. Step-by-step guides are a type of flow.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public AmazonConnectGuideAssociationData withFlowId(String flowId) {
        setFlowId(flowId);
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
        if (getFlowId() != null)
            sb.append("FlowId: ").append(getFlowId());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof AmazonConnectGuideAssociationData == false)
            return false;
        AmazonConnectGuideAssociationData other = (AmazonConnectGuideAssociationData) obj;
        if (other.getFlowId() == null ^ this.getFlowId() == null)
            return false;
        if (other.getFlowId() != null && other.getFlowId().equals(this.getFlowId()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getFlowId() == null) ? 0 : getFlowId().hashCode());
        return hashCode;
    }

    @Override
    public AmazonConnectGuideAssociationData clone() {
        try {
            return (AmazonConnectGuideAssociationData) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.qconnect.model.transform.AmazonConnectGuideAssociationDataMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
