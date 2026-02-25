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
 * Describes the segments associated with the service insertion action.
 * </p>
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/networkmanager-2019-07-05/ServiceInsertionSegments"
 *      target="_top">AWS API Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class ServiceInsertionSegments implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * The list of segments associated with the <code>send-via</code> action.
     * </p>
     */
    private java.util.List<String> sendVia;
    /**
     * <p>
     * The list of segments associated with the <code>send-to</code> action.
     * </p>
     */
    private java.util.List<String> sendTo;

    /**
     * <p>
     * The list of segments associated with the <code>send-via</code> action.
     * </p>
     * 
     * @return The list of segments associated with the <code>send-via</code> action.
     */

    public java.util.List<String> getSendVia() {
        return sendVia;
    }

    /**
     * <p>
     * The list of segments associated with the <code>send-via</code> action.
     * </p>
     * 
     * @param sendVia
     *        The list of segments associated with the <code>send-via</code> action.
     */

    public void setSendVia(java.util.Collection<String> sendVia) {
        if (sendVia == null) {
            this.sendVia = null;
            return;
        }

        this.sendVia = new java.util.ArrayList<String>(sendVia);
    }

    /**
     * <p>
     * The list of segments associated with the <code>send-via</code> action.
     * </p>
     * <p>
     * <b>NOTE:</b> This method appends the values to the existing list (if any). Use
     * {@link #setSendVia(java.util.Collection)} or {@link #withSendVia(java.util.Collection)} if you want to override
     * the existing values.
     * </p>
     * 
     * @param sendVia
     *        The list of segments associated with the <code>send-via</code> action.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ServiceInsertionSegments withSendVia(String... sendVia) {
        if (this.sendVia == null) {
            setSendVia(new java.util.ArrayList<String>(sendVia.length));
        }
        for (String ele : sendVia) {
            this.sendVia.add(ele);
        }
        return this;
    }

    /**
     * <p>
     * The list of segments associated with the <code>send-via</code> action.
     * </p>
     * 
     * @param sendVia
     *        The list of segments associated with the <code>send-via</code> action.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ServiceInsertionSegments withSendVia(java.util.Collection<String> sendVia) {
        setSendVia(sendVia);
        return this;
    }

    /**
     * <p>
     * The list of segments associated with the <code>send-to</code> action.
     * </p>
     * 
     * @return The list of segments associated with the <code>send-to</code> action.
     */

    public java.util.List<String> getSendTo() {
        return sendTo;
    }

    /**
     * <p>
     * The list of segments associated with the <code>send-to</code> action.
     * </p>
     * 
     * @param sendTo
     *        The list of segments associated with the <code>send-to</code> action.
     */

    public void setSendTo(java.util.Collection<String> sendTo) {
        if (sendTo == null) {
            this.sendTo = null;
            return;
        }

        this.sendTo = new java.util.ArrayList<String>(sendTo);
    }

    /**
     * <p>
     * The list of segments associated with the <code>send-to</code> action.
     * </p>
     * <p>
     * <b>NOTE:</b> This method appends the values to the existing list (if any). Use
     * {@link #setSendTo(java.util.Collection)} or {@link #withSendTo(java.util.Collection)} if you want to override the
     * existing values.
     * </p>
     * 
     * @param sendTo
     *        The list of segments associated with the <code>send-to</code> action.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ServiceInsertionSegments withSendTo(String... sendTo) {
        if (this.sendTo == null) {
            setSendTo(new java.util.ArrayList<String>(sendTo.length));
        }
        for (String ele : sendTo) {
            this.sendTo.add(ele);
        }
        return this;
    }

    /**
     * <p>
     * The list of segments associated with the <code>send-to</code> action.
     * </p>
     * 
     * @param sendTo
     *        The list of segments associated with the <code>send-to</code> action.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ServiceInsertionSegments withSendTo(java.util.Collection<String> sendTo) {
        setSendTo(sendTo);
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
        if (getSendVia() != null)
            sb.append("SendVia: ").append(getSendVia()).append(",");
        if (getSendTo() != null)
            sb.append("SendTo: ").append(getSendTo());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof ServiceInsertionSegments == false)
            return false;
        ServiceInsertionSegments other = (ServiceInsertionSegments) obj;
        if (other.getSendVia() == null ^ this.getSendVia() == null)
            return false;
        if (other.getSendVia() != null && other.getSendVia().equals(this.getSendVia()) == false)
            return false;
        if (other.getSendTo() == null ^ this.getSendTo() == null)
            return false;
        if (other.getSendTo() != null && other.getSendTo().equals(this.getSendTo()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getSendVia() == null) ? 0 : getSendVia().hashCode());
        hashCode = prime * hashCode + ((getSendTo() == null) ? 0 : getSendTo().hashCode());
        return hashCode;
    }

    @Override
    public ServiceInsertionSegments clone() {
        try {
            return (ServiceInsertionSegments) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.networkmanager.model.transform.ServiceInsertionSegmentsMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
