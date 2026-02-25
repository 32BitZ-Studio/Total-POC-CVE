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
import com.amazonaws.protocol.StructuredPojo;
import com.amazonaws.protocol.ProtocolMarshaller;

/**
 * <p>
 * The current status and value of a card in an active Amazon Q App session.
 * </p>
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/qapps-2023-11-27/CardStatus" target="_top">AWS API
 *      Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class CardStatus implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * The current state of the card.
     * </p>
     */
    private String currentState;
    /**
     * <p>
     * The current value or result associated with the card.
     * </p>
     */
    private String currentValue;

    /**
     * <p>
     * The current state of the card.
     * </p>
     * 
     * @param currentState
     *        The current state of the card.
     * @see ExecutionStatus
     */

    public void setCurrentState(String currentState) {
        this.currentState = currentState;
    }

    /**
     * <p>
     * The current state of the card.
     * </p>
     * 
     * @return The current state of the card.
     * @see ExecutionStatus
     */

    public String getCurrentState() {
        return this.currentState;
    }

    /**
     * <p>
     * The current state of the card.
     * </p>
     * 
     * @param currentState
     *        The current state of the card.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see ExecutionStatus
     */

    public CardStatus withCurrentState(String currentState) {
        setCurrentState(currentState);
        return this;
    }

    /**
     * <p>
     * The current state of the card.
     * </p>
     * 
     * @param currentState
     *        The current state of the card.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see ExecutionStatus
     */

    public CardStatus withCurrentState(ExecutionStatus currentState) {
        this.currentState = currentState.toString();
        return this;
    }

    /**
     * <p>
     * The current value or result associated with the card.
     * </p>
     * 
     * @param currentValue
     *        The current value or result associated with the card.
     */

    public void setCurrentValue(String currentValue) {
        this.currentValue = currentValue;
    }

    /**
     * <p>
     * The current value or result associated with the card.
     * </p>
     * 
     * @return The current value or result associated with the card.
     */

    public String getCurrentValue() {
        return this.currentValue;
    }

    /**
     * <p>
     * The current value or result associated with the card.
     * </p>
     * 
     * @param currentValue
     *        The current value or result associated with the card.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public CardStatus withCurrentValue(String currentValue) {
        setCurrentValue(currentValue);
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
        if (getCurrentState() != null)
            sb.append("CurrentState: ").append(getCurrentState()).append(",");
        if (getCurrentValue() != null)
            sb.append("CurrentValue: ").append(getCurrentValue());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof CardStatus == false)
            return false;
        CardStatus other = (CardStatus) obj;
        if (other.getCurrentState() == null ^ this.getCurrentState() == null)
            return false;
        if (other.getCurrentState() != null && other.getCurrentState().equals(this.getCurrentState()) == false)
            return false;
        if (other.getCurrentValue() == null ^ this.getCurrentValue() == null)
            return false;
        if (other.getCurrentValue() != null && other.getCurrentValue().equals(this.getCurrentValue()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getCurrentState() == null) ? 0 : getCurrentState().hashCode());
        hashCode = prime * hashCode + ((getCurrentValue() == null) ? 0 : getCurrentValue().hashCode());
        return hashCode;
    }

    @Override
    public CardStatus clone() {
        try {
            return (CardStatus) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.qapps.model.transform.CardStatusMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
