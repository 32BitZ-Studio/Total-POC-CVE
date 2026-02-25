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
 * The definition of the Q App, specifying the cards and flow.
 * </p>
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/qapps-2023-11-27/AppDefinition" target="_top">AWS API
 *      Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class AppDefinition implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * The version of the app definition schema or specification.
     * </p>
     */
    private String appDefinitionVersion;
    /**
     * <p>
     * The cards that make up the Q App, such as text input, file upload, or query cards.
     * </p>
     */
    private java.util.List<Card> cards;
    /**
     * <p>
     * A flag indicating whether the Q App's definition can be edited by the user.
     * </p>
     */
    private Boolean canEdit;

    /**
     * <p>
     * The version of the app definition schema or specification.
     * </p>
     * 
     * @param appDefinitionVersion
     *        The version of the app definition schema or specification.
     */

    public void setAppDefinitionVersion(String appDefinitionVersion) {
        this.appDefinitionVersion = appDefinitionVersion;
    }

    /**
     * <p>
     * The version of the app definition schema or specification.
     * </p>
     * 
     * @return The version of the app definition schema or specification.
     */

    public String getAppDefinitionVersion() {
        return this.appDefinitionVersion;
    }

    /**
     * <p>
     * The version of the app definition schema or specification.
     * </p>
     * 
     * @param appDefinitionVersion
     *        The version of the app definition schema or specification.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public AppDefinition withAppDefinitionVersion(String appDefinitionVersion) {
        setAppDefinitionVersion(appDefinitionVersion);
        return this;
    }

    /**
     * <p>
     * The cards that make up the Q App, such as text input, file upload, or query cards.
     * </p>
     * 
     * @return The cards that make up the Q App, such as text input, file upload, or query cards.
     */

    public java.util.List<Card> getCards() {
        return cards;
    }

    /**
     * <p>
     * The cards that make up the Q App, such as text input, file upload, or query cards.
     * </p>
     * 
     * @param cards
     *        The cards that make up the Q App, such as text input, file upload, or query cards.
     */

    public void setCards(java.util.Collection<Card> cards) {
        if (cards == null) {
            this.cards = null;
            return;
        }

        this.cards = new java.util.ArrayList<Card>(cards);
    }

    /**
     * <p>
     * The cards that make up the Q App, such as text input, file upload, or query cards.
     * </p>
     * <p>
     * <b>NOTE:</b> This method appends the values to the existing list (if any). Use
     * {@link #setCards(java.util.Collection)} or {@link #withCards(java.util.Collection)} if you want to override the
     * existing values.
     * </p>
     * 
     * @param cards
     *        The cards that make up the Q App, such as text input, file upload, or query cards.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public AppDefinition withCards(Card... cards) {
        if (this.cards == null) {
            setCards(new java.util.ArrayList<Card>(cards.length));
        }
        for (Card ele : cards) {
            this.cards.add(ele);
        }
        return this;
    }

    /**
     * <p>
     * The cards that make up the Q App, such as text input, file upload, or query cards.
     * </p>
     * 
     * @param cards
     *        The cards that make up the Q App, such as text input, file upload, or query cards.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public AppDefinition withCards(java.util.Collection<Card> cards) {
        setCards(cards);
        return this;
    }

    /**
     * <p>
     * A flag indicating whether the Q App's definition can be edited by the user.
     * </p>
     * 
     * @param canEdit
     *        A flag indicating whether the Q App's definition can be edited by the user.
     */

    public void setCanEdit(Boolean canEdit) {
        this.canEdit = canEdit;
    }

    /**
     * <p>
     * A flag indicating whether the Q App's definition can be edited by the user.
     * </p>
     * 
     * @return A flag indicating whether the Q App's definition can be edited by the user.
     */

    public Boolean getCanEdit() {
        return this.canEdit;
    }

    /**
     * <p>
     * A flag indicating whether the Q App's definition can be edited by the user.
     * </p>
     * 
     * @param canEdit
     *        A flag indicating whether the Q App's definition can be edited by the user.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public AppDefinition withCanEdit(Boolean canEdit) {
        setCanEdit(canEdit);
        return this;
    }

    /**
     * <p>
     * A flag indicating whether the Q App's definition can be edited by the user.
     * </p>
     * 
     * @return A flag indicating whether the Q App's definition can be edited by the user.
     */

    public Boolean isCanEdit() {
        return this.canEdit;
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
        if (getAppDefinitionVersion() != null)
            sb.append("AppDefinitionVersion: ").append(getAppDefinitionVersion()).append(",");
        if (getCards() != null)
            sb.append("Cards: ").append(getCards()).append(",");
        if (getCanEdit() != null)
            sb.append("CanEdit: ").append(getCanEdit());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof AppDefinition == false)
            return false;
        AppDefinition other = (AppDefinition) obj;
        if (other.getAppDefinitionVersion() == null ^ this.getAppDefinitionVersion() == null)
            return false;
        if (other.getAppDefinitionVersion() != null && other.getAppDefinitionVersion().equals(this.getAppDefinitionVersion()) == false)
            return false;
        if (other.getCards() == null ^ this.getCards() == null)
            return false;
        if (other.getCards() != null && other.getCards().equals(this.getCards()) == false)
            return false;
        if (other.getCanEdit() == null ^ this.getCanEdit() == null)
            return false;
        if (other.getCanEdit() != null && other.getCanEdit().equals(this.getCanEdit()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getAppDefinitionVersion() == null) ? 0 : getAppDefinitionVersion().hashCode());
        hashCode = prime * hashCode + ((getCards() == null) ? 0 : getCards().hashCode());
        hashCode = prime * hashCode + ((getCanEdit() == null) ? 0 : getCanEdit().hashCode());
        return hashCode;
    }

    @Override
    public AppDefinition clone() {
        try {
            return (AppDefinition) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.qapps.model.transform.AppDefinitionMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
