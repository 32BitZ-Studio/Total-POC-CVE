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
 * The value or result associated with a card in a Amazon Q App session.
 * </p>
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/qapps-2023-11-27/CardValue" target="_top">AWS API
 *      Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class CardValue implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * The unique identifier of the card.
     * </p>
     */
    private String cardId;
    /**
     * <p>
     * The value or result associated with the card.
     * </p>
     */
    private String value;

    /**
     * <p>
     * The unique identifier of the card.
     * </p>
     * 
     * @param cardId
     *        The unique identifier of the card.
     */

    public void setCardId(String cardId) {
        this.cardId = cardId;
    }

    /**
     * <p>
     * The unique identifier of the card.
     * </p>
     * 
     * @return The unique identifier of the card.
     */

    public String getCardId() {
        return this.cardId;
    }

    /**
     * <p>
     * The unique identifier of the card.
     * </p>
     * 
     * @param cardId
     *        The unique identifier of the card.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public CardValue withCardId(String cardId) {
        setCardId(cardId);
        return this;
    }

    /**
     * <p>
     * The value or result associated with the card.
     * </p>
     * 
     * @param value
     *        The value or result associated with the card.
     */

    public void setValue(String value) {
        this.value = value;
    }

    /**
     * <p>
     * The value or result associated with the card.
     * </p>
     * 
     * @return The value or result associated with the card.
     */

    public String getValue() {
        return this.value;
    }

    /**
     * <p>
     * The value or result associated with the card.
     * </p>
     * 
     * @param value
     *        The value or result associated with the card.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public CardValue withValue(String value) {
        setValue(value);
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
        if (getCardId() != null)
            sb.append("CardId: ").append(getCardId()).append(",");
        if (getValue() != null)
            sb.append("Value: ").append(getValue());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof CardValue == false)
            return false;
        CardValue other = (CardValue) obj;
        if (other.getCardId() == null ^ this.getCardId() == null)
            return false;
        if (other.getCardId() != null && other.getCardId().equals(this.getCardId()) == false)
            return false;
        if (other.getValue() == null ^ this.getValue() == null)
            return false;
        if (other.getValue() != null && other.getValue().equals(this.getValue()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getCardId() == null) ? 0 : getCardId().hashCode());
        hashCode = prime * hashCode + ((getValue() == null) ? 0 : getValue().hashCode());
        return hashCode;
    }

    @Override
    public CardValue clone() {
        try {
            return (CardValue) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.qapps.model.transform.CardValueMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
