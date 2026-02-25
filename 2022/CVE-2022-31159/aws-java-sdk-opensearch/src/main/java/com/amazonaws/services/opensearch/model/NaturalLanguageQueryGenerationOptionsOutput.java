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
package com.amazonaws.services.opensearch.model;

import java.io.Serializable;
import javax.annotation.Generated;
import com.amazonaws.protocol.StructuredPojo;
import com.amazonaws.protocol.ProtocolMarshaller;

/**
 * <p>
 * Container for parameters representing the state of the natural language query generation feature on the specified
 * domain.
 * </p>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class NaturalLanguageQueryGenerationOptionsOutput implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * The desired state of the natural language query generation feature. Valid values are ENABLED and DISABLED.
     * </p>
     */
    private String desiredState;
    /**
     * <p>
     * The current state of the natural language query generation feature, indicating completion, in progress, or
     * failure.
     * </p>
     */
    private String currentState;

    /**
     * <p>
     * The desired state of the natural language query generation feature. Valid values are ENABLED and DISABLED.
     * </p>
     * 
     * @param desiredState
     *        The desired state of the natural language query generation feature. Valid values are ENABLED and DISABLED.
     * @see NaturalLanguageQueryGenerationDesiredState
     */

    public void setDesiredState(String desiredState) {
        this.desiredState = desiredState;
    }

    /**
     * <p>
     * The desired state of the natural language query generation feature. Valid values are ENABLED and DISABLED.
     * </p>
     * 
     * @return The desired state of the natural language query generation feature. Valid values are ENABLED and
     *         DISABLED.
     * @see NaturalLanguageQueryGenerationDesiredState
     */

    public String getDesiredState() {
        return this.desiredState;
    }

    /**
     * <p>
     * The desired state of the natural language query generation feature. Valid values are ENABLED and DISABLED.
     * </p>
     * 
     * @param desiredState
     *        The desired state of the natural language query generation feature. Valid values are ENABLED and DISABLED.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see NaturalLanguageQueryGenerationDesiredState
     */

    public NaturalLanguageQueryGenerationOptionsOutput withDesiredState(String desiredState) {
        setDesiredState(desiredState);
        return this;
    }

    /**
     * <p>
     * The desired state of the natural language query generation feature. Valid values are ENABLED and DISABLED.
     * </p>
     * 
     * @param desiredState
     *        The desired state of the natural language query generation feature. Valid values are ENABLED and DISABLED.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see NaturalLanguageQueryGenerationDesiredState
     */

    public NaturalLanguageQueryGenerationOptionsOutput withDesiredState(NaturalLanguageQueryGenerationDesiredState desiredState) {
        this.desiredState = desiredState.toString();
        return this;
    }

    /**
     * <p>
     * The current state of the natural language query generation feature, indicating completion, in progress, or
     * failure.
     * </p>
     * 
     * @param currentState
     *        The current state of the natural language query generation feature, indicating completion, in progress, or
     *        failure.
     * @see NaturalLanguageQueryGenerationCurrentState
     */

    public void setCurrentState(String currentState) {
        this.currentState = currentState;
    }

    /**
     * <p>
     * The current state of the natural language query generation feature, indicating completion, in progress, or
     * failure.
     * </p>
     * 
     * @return The current state of the natural language query generation feature, indicating completion, in progress,
     *         or failure.
     * @see NaturalLanguageQueryGenerationCurrentState
     */

    public String getCurrentState() {
        return this.currentState;
    }

    /**
     * <p>
     * The current state of the natural language query generation feature, indicating completion, in progress, or
     * failure.
     * </p>
     * 
     * @param currentState
     *        The current state of the natural language query generation feature, indicating completion, in progress, or
     *        failure.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see NaturalLanguageQueryGenerationCurrentState
     */

    public NaturalLanguageQueryGenerationOptionsOutput withCurrentState(String currentState) {
        setCurrentState(currentState);
        return this;
    }

    /**
     * <p>
     * The current state of the natural language query generation feature, indicating completion, in progress, or
     * failure.
     * </p>
     * 
     * @param currentState
     *        The current state of the natural language query generation feature, indicating completion, in progress, or
     *        failure.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see NaturalLanguageQueryGenerationCurrentState
     */

    public NaturalLanguageQueryGenerationOptionsOutput withCurrentState(NaturalLanguageQueryGenerationCurrentState currentState) {
        this.currentState = currentState.toString();
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
        if (getDesiredState() != null)
            sb.append("DesiredState: ").append(getDesiredState()).append(",");
        if (getCurrentState() != null)
            sb.append("CurrentState: ").append(getCurrentState());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof NaturalLanguageQueryGenerationOptionsOutput == false)
            return false;
        NaturalLanguageQueryGenerationOptionsOutput other = (NaturalLanguageQueryGenerationOptionsOutput) obj;
        if (other.getDesiredState() == null ^ this.getDesiredState() == null)
            return false;
        if (other.getDesiredState() != null && other.getDesiredState().equals(this.getDesiredState()) == false)
            return false;
        if (other.getCurrentState() == null ^ this.getCurrentState() == null)
            return false;
        if (other.getCurrentState() != null && other.getCurrentState().equals(this.getCurrentState()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getDesiredState() == null) ? 0 : getDesiredState().hashCode());
        hashCode = prime * hashCode + ((getCurrentState() == null) ? 0 : getCurrentState().hashCode());
        return hashCode;
    }

    @Override
    public NaturalLanguageQueryGenerationOptionsOutput clone() {
        try {
            return (NaturalLanguageQueryGenerationOptionsOutput) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.opensearch.model.transform.NaturalLanguageQueryGenerationOptionsOutputMarshaller.getInstance()
                .marshall(this, protocolMarshaller);
    }
}
