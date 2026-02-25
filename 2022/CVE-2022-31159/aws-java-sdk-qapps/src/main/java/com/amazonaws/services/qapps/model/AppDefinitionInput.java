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
 * The input for defining an Q App.
 * </p>
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/qapps-2023-11-27/AppDefinitionInput" target="_top">AWS API
 *      Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class AppDefinitionInput implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * The cards that make up the Q App definition.
     * </p>
     */
    private java.util.List<CardInput> cards;
    /**
     * <p>
     * The initial prompt displayed when the Q App is started.
     * </p>
     */
    private String initialPrompt;

    /**
     * <p>
     * The cards that make up the Q App definition.
     * </p>
     * 
     * @return The cards that make up the Q App definition.
     */

    public java.util.List<CardInput> getCards() {
        return cards;
    }

    /**
     * <p>
     * The cards that make up the Q App definition.
     * </p>
     * 
     * @param cards
     *        The cards that make up the Q App definition.
     */

    public void setCards(java.util.Collection<CardInput> cards) {
        if (cards == null) {
            this.cards = null;
            return;
        }

        this.cards = new java.util.ArrayList<CardInput>(cards);
    }

    /**
     * <p>
     * The cards that make up the Q App definition.
     * </p>
     * <p>
     * <b>NOTE:</b> This method appends the values to the existing list (if any). Use
     * {@link #setCards(java.util.Collection)} or {@link #withCards(java.util.Collection)} if you want to override the
     * existing values.
     * </p>
     * 
     * @param cards
     *        The cards that make up the Q App definition.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public AppDefinitionInput withCards(CardInput... cards) {
        if (this.cards == null) {
            setCards(new java.util.ArrayList<CardInput>(cards.length));
        }
        for (CardInput ele : cards) {
            this.cards.add(ele);
        }
        return this;
    }

    /**
     * <p>
     * The cards that make up the Q App definition.
     * </p>
     * 
     * @param cards
     *        The cards that make up the Q App definition.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public AppDefinitionInput withCards(java.util.Collection<CardInput> cards) {
        setCards(cards);
        return this;
    }

    /**
     * <p>
     * The initial prompt displayed when the Q App is started.
     * </p>
     * 
     * @param initialPrompt
     *        The initial prompt displayed when the Q App is started.
     */

    public void setInitialPrompt(String initialPrompt) {
        this.initialPrompt = initialPrompt;
    }

    /**
     * <p>
     * The initial prompt displayed when the Q App is started.
     * </p>
     * 
     * @return The initial prompt displayed when the Q App is started.
     */

    public String getInitialPrompt() {
        return this.initialPrompt;
    }

    /**
     * <p>
     * The initial prompt displayed when the Q App is started.
     * </p>
     * 
     * @param initialPrompt
     *        The initial prompt displayed when the Q App is started.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public AppDefinitionInput withInitialPrompt(String initialPrompt) {
        setInitialPrompt(initialPrompt);
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
        if (getCards() != null)
            sb.append("Cards: ").append(getCards()).append(",");
        if (getInitialPrompt() != null)
            sb.append("InitialPrompt: ").append(getInitialPrompt());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof AppDefinitionInput == false)
            return false;
        AppDefinitionInput other = (AppDefinitionInput) obj;
        if (other.getCards() == null ^ this.getCards() == null)
            return false;
        if (other.getCards() != null && other.getCards().equals(this.getCards()) == false)
            return false;
        if (other.getInitialPrompt() == null ^ this.getInitialPrompt() == null)
            return false;
        if (other.getInitialPrompt() != null && other.getInitialPrompt().equals(this.getInitialPrompt()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getCards() == null) ? 0 : getCards().hashCode());
        hashCode = prime * hashCode + ((getInitialPrompt() == null) ? 0 : getInitialPrompt().hashCode());
        return hashCode;
    }

    @Override
    public AppDefinitionInput clone() {
        try {
            return (AppDefinitionInput) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.qapps.model.transform.AppDefinitionInputMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
