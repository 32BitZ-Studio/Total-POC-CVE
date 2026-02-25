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
 * The input shape for defining a text input card in an Amazon Q App.
 * </p>
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/qapps-2023-11-27/TextInputCardInput" target="_top">AWS API
 *      Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class TextInputCardInput implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * The title or label of the text input card.
     * </p>
     */
    private String title;
    /**
     * <p>
     * The unique identifier of the text input card.
     * </p>
     */
    private String id;
    /**
     * <p>
     * The type of the card.
     * </p>
     */
    private String type;
    /**
     * <p>
     * The placeholder text to display in the text input field.
     * </p>
     */
    private String placeholder;
    /**
     * <p>
     * The default value to pre-populate in the text input field.
     * </p>
     */
    private String defaultValue;

    /**
     * <p>
     * The title or label of the text input card.
     * </p>
     * 
     * @param title
     *        The title or label of the text input card.
     */

    public void setTitle(String title) {
        this.title = title;
    }

    /**
     * <p>
     * The title or label of the text input card.
     * </p>
     * 
     * @return The title or label of the text input card.
     */

    public String getTitle() {
        return this.title;
    }

    /**
     * <p>
     * The title or label of the text input card.
     * </p>
     * 
     * @param title
     *        The title or label of the text input card.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public TextInputCardInput withTitle(String title) {
        setTitle(title);
        return this;
    }

    /**
     * <p>
     * The unique identifier of the text input card.
     * </p>
     * 
     * @param id
     *        The unique identifier of the text input card.
     */

    public void setId(String id) {
        this.id = id;
    }

    /**
     * <p>
     * The unique identifier of the text input card.
     * </p>
     * 
     * @return The unique identifier of the text input card.
     */

    public String getId() {
        return this.id;
    }

    /**
     * <p>
     * The unique identifier of the text input card.
     * </p>
     * 
     * @param id
     *        The unique identifier of the text input card.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public TextInputCardInput withId(String id) {
        setId(id);
        return this;
    }

    /**
     * <p>
     * The type of the card.
     * </p>
     * 
     * @param type
     *        The type of the card.
     * @see CardType
     */

    public void setType(String type) {
        this.type = type;
    }

    /**
     * <p>
     * The type of the card.
     * </p>
     * 
     * @return The type of the card.
     * @see CardType
     */

    public String getType() {
        return this.type;
    }

    /**
     * <p>
     * The type of the card.
     * </p>
     * 
     * @param type
     *        The type of the card.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see CardType
     */

    public TextInputCardInput withType(String type) {
        setType(type);
        return this;
    }

    /**
     * <p>
     * The type of the card.
     * </p>
     * 
     * @param type
     *        The type of the card.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see CardType
     */

    public TextInputCardInput withType(CardType type) {
        this.type = type.toString();
        return this;
    }

    /**
     * <p>
     * The placeholder text to display in the text input field.
     * </p>
     * 
     * @param placeholder
     *        The placeholder text to display in the text input field.
     */

    public void setPlaceholder(String placeholder) {
        this.placeholder = placeholder;
    }

    /**
     * <p>
     * The placeholder text to display in the text input field.
     * </p>
     * 
     * @return The placeholder text to display in the text input field.
     */

    public String getPlaceholder() {
        return this.placeholder;
    }

    /**
     * <p>
     * The placeholder text to display in the text input field.
     * </p>
     * 
     * @param placeholder
     *        The placeholder text to display in the text input field.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public TextInputCardInput withPlaceholder(String placeholder) {
        setPlaceholder(placeholder);
        return this;
    }

    /**
     * <p>
     * The default value to pre-populate in the text input field.
     * </p>
     * 
     * @param defaultValue
     *        The default value to pre-populate in the text input field.
     */

    public void setDefaultValue(String defaultValue) {
        this.defaultValue = defaultValue;
    }

    /**
     * <p>
     * The default value to pre-populate in the text input field.
     * </p>
     * 
     * @return The default value to pre-populate in the text input field.
     */

    public String getDefaultValue() {
        return this.defaultValue;
    }

    /**
     * <p>
     * The default value to pre-populate in the text input field.
     * </p>
     * 
     * @param defaultValue
     *        The default value to pre-populate in the text input field.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public TextInputCardInput withDefaultValue(String defaultValue) {
        setDefaultValue(defaultValue);
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
        if (getTitle() != null)
            sb.append("Title: ").append(getTitle()).append(",");
        if (getId() != null)
            sb.append("Id: ").append(getId()).append(",");
        if (getType() != null)
            sb.append("Type: ").append(getType()).append(",");
        if (getPlaceholder() != null)
            sb.append("Placeholder: ").append(getPlaceholder()).append(",");
        if (getDefaultValue() != null)
            sb.append("DefaultValue: ").append(getDefaultValue());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof TextInputCardInput == false)
            return false;
        TextInputCardInput other = (TextInputCardInput) obj;
        if (other.getTitle() == null ^ this.getTitle() == null)
            return false;
        if (other.getTitle() != null && other.getTitle().equals(this.getTitle()) == false)
            return false;
        if (other.getId() == null ^ this.getId() == null)
            return false;
        if (other.getId() != null && other.getId().equals(this.getId()) == false)
            return false;
        if (other.getType() == null ^ this.getType() == null)
            return false;
        if (other.getType() != null && other.getType().equals(this.getType()) == false)
            return false;
        if (other.getPlaceholder() == null ^ this.getPlaceholder() == null)
            return false;
        if (other.getPlaceholder() != null && other.getPlaceholder().equals(this.getPlaceholder()) == false)
            return false;
        if (other.getDefaultValue() == null ^ this.getDefaultValue() == null)
            return false;
        if (other.getDefaultValue() != null && other.getDefaultValue().equals(this.getDefaultValue()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getTitle() == null) ? 0 : getTitle().hashCode());
        hashCode = prime * hashCode + ((getId() == null) ? 0 : getId().hashCode());
        hashCode = prime * hashCode + ((getType() == null) ? 0 : getType().hashCode());
        hashCode = prime * hashCode + ((getPlaceholder() == null) ? 0 : getPlaceholder().hashCode());
        hashCode = prime * hashCode + ((getDefaultValue() == null) ? 0 : getDefaultValue().hashCode());
        return hashCode;
    }

    @Override
    public TextInputCardInput clone() {
        try {
            return (TextInputCardInput) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.qapps.model.transform.TextInputCardInputMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
