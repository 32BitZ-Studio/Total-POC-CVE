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
package com.amazonaws.services.qapps.model;

import java.io.Serializable;
import javax.annotation.Generated;

import com.amazonaws.AmazonWebServiceRequest;

/**
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/qapps-2023-11-27/UpdateQAppSession" target="_top">AWS API
 *      Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class UpdateQAppSessionRequest extends com.amazonaws.AmazonWebServiceRequest implements Serializable, Cloneable {

    /**
     * <p>
     * The unique identifier of the Amazon Q Business application environment instance.
     * </p>
     */
    private String instanceId;
    /**
     * <p>
     * The unique identifier of the Q App session to provide input for.
     * </p>
     */
    private String sessionId;
    /**
     * <p>
     * The input values to provide for the current state of the Q App session.
     * </p>
     */
    private java.util.List<CardValue> values;

    /**
     * <p>
     * The unique identifier of the Amazon Q Business application environment instance.
     * </p>
     * 
     * @param instanceId
     *        The unique identifier of the Amazon Q Business application environment instance.
     */

    public void setInstanceId(String instanceId) {
        this.instanceId = instanceId;
    }

    /**
     * <p>
     * The unique identifier of the Amazon Q Business application environment instance.
     * </p>
     * 
     * @return The unique identifier of the Amazon Q Business application environment instance.
     */

    public String getInstanceId() {
        return this.instanceId;
    }

    /**
     * <p>
     * The unique identifier of the Amazon Q Business application environment instance.
     * </p>
     * 
     * @param instanceId
     *        The unique identifier of the Amazon Q Business application environment instance.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public UpdateQAppSessionRequest withInstanceId(String instanceId) {
        setInstanceId(instanceId);
        return this;
    }

    /**
     * <p>
     * The unique identifier of the Q App session to provide input for.
     * </p>
     * 
     * @param sessionId
     *        The unique identifier of the Q App session to provide input for.
     */

    public void setSessionId(String sessionId) {
        this.sessionId = sessionId;
    }

    /**
     * <p>
     * The unique identifier of the Q App session to provide input for.
     * </p>
     * 
     * @return The unique identifier of the Q App session to provide input for.
     */

    public String getSessionId() {
        return this.sessionId;
    }

    /**
     * <p>
     * The unique identifier of the Q App session to provide input for.
     * </p>
     * 
     * @param sessionId
     *        The unique identifier of the Q App session to provide input for.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public UpdateQAppSessionRequest withSessionId(String sessionId) {
        setSessionId(sessionId);
        return this;
    }

    /**
     * <p>
     * The input values to provide for the current state of the Q App session.
     * </p>
     * 
     * @return The input values to provide for the current state of the Q App session.
     */

    public java.util.List<CardValue> getValues() {
        return values;
    }

    /**
     * <p>
     * The input values to provide for the current state of the Q App session.
     * </p>
     * 
     * @param values
     *        The input values to provide for the current state of the Q App session.
     */

    public void setValues(java.util.Collection<CardValue> values) {
        if (values == null) {
            this.values = null;
            return;
        }

        this.values = new java.util.ArrayList<CardValue>(values);
    }

    /**
     * <p>
     * The input values to provide for the current state of the Q App session.
     * </p>
     * <p>
     * <b>NOTE:</b> This method appends the values to the existing list (if any). Use
     * {@link #setValues(java.util.Collection)} or {@link #withValues(java.util.Collection)} if you want to override the
     * existing values.
     * </p>
     * 
     * @param values
     *        The input values to provide for the current state of the Q App session.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public UpdateQAppSessionRequest withValues(CardValue... values) {
        if (this.values == null) {
            setValues(new java.util.ArrayList<CardValue>(values.length));
        }
        for (CardValue ele : values) {
            this.values.add(ele);
        }
        return this;
    }

    /**
     * <p>
     * The input values to provide for the current state of the Q App session.
     * </p>
     * 
     * @param values
     *        The input values to provide for the current state of the Q App session.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public UpdateQAppSessionRequest withValues(java.util.Collection<CardValue> values) {
        setValues(values);
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
        if (getInstanceId() != null)
            sb.append("InstanceId: ").append(getInstanceId()).append(",");
        if (getSessionId() != null)
            sb.append("SessionId: ").append(getSessionId()).append(",");
        if (getValues() != null)
            sb.append("Values: ").append(getValues());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof UpdateQAppSessionRequest == false)
            return false;
        UpdateQAppSessionRequest other = (UpdateQAppSessionRequest) obj;
        if (other.getInstanceId() == null ^ this.getInstanceId() == null)
            return false;
        if (other.getInstanceId() != null && other.getInstanceId().equals(this.getInstanceId()) == false)
            return false;
        if (other.getSessionId() == null ^ this.getSessionId() == null)
            return false;
        if (other.getSessionId() != null && other.getSessionId().equals(this.getSessionId()) == false)
            return false;
        if (other.getValues() == null ^ this.getValues() == null)
            return false;
        if (other.getValues() != null && other.getValues().equals(this.getValues()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getInstanceId() == null) ? 0 : getInstanceId().hashCode());
        hashCode = prime * hashCode + ((getSessionId() == null) ? 0 : getSessionId().hashCode());
        hashCode = prime * hashCode + ((getValues() == null) ? 0 : getValues().hashCode());
        return hashCode;
    }

    @Override
    public UpdateQAppSessionRequest clone() {
        return (UpdateQAppSessionRequest) super.clone();
    }

}
