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
 * The input shape for defining a plugin card in an Amazon Q App.
 * </p>
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/qapps-2023-11-27/QPluginCardInput" target="_top">AWS API
 *      Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class QPluginCardInput implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * The title or label of the plugin card.
     * </p>
     */
    private String title;
    /**
     * <p>
     * The unique identifier of the plugin card.
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
     * The prompt or instructions displayed for the plugin card.
     * </p>
     */
    private String prompt;
    /**
     * <p>
     * The unique identifier of the plugin used by the card.
     * </p>
     */
    private String pluginId;

    /**
     * <p>
     * The title or label of the plugin card.
     * </p>
     * 
     * @param title
     *        The title or label of the plugin card.
     */

    public void setTitle(String title) {
        this.title = title;
    }

    /**
     * <p>
     * The title or label of the plugin card.
     * </p>
     * 
     * @return The title or label of the plugin card.
     */

    public String getTitle() {
        return this.title;
    }

    /**
     * <p>
     * The title or label of the plugin card.
     * </p>
     * 
     * @param title
     *        The title or label of the plugin card.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public QPluginCardInput withTitle(String title) {
        setTitle(title);
        return this;
    }

    /**
     * <p>
     * The unique identifier of the plugin card.
     * </p>
     * 
     * @param id
     *        The unique identifier of the plugin card.
     */

    public void setId(String id) {
        this.id = id;
    }

    /**
     * <p>
     * The unique identifier of the plugin card.
     * </p>
     * 
     * @return The unique identifier of the plugin card.
     */

    public String getId() {
        return this.id;
    }

    /**
     * <p>
     * The unique identifier of the plugin card.
     * </p>
     * 
     * @param id
     *        The unique identifier of the plugin card.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public QPluginCardInput withId(String id) {
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

    public QPluginCardInput withType(String type) {
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

    public QPluginCardInput withType(CardType type) {
        this.type = type.toString();
        return this;
    }

    /**
     * <p>
     * The prompt or instructions displayed for the plugin card.
     * </p>
     * 
     * @param prompt
     *        The prompt or instructions displayed for the plugin card.
     */

    public void setPrompt(String prompt) {
        this.prompt = prompt;
    }

    /**
     * <p>
     * The prompt or instructions displayed for the plugin card.
     * </p>
     * 
     * @return The prompt or instructions displayed for the plugin card.
     */

    public String getPrompt() {
        return this.prompt;
    }

    /**
     * <p>
     * The prompt or instructions displayed for the plugin card.
     * </p>
     * 
     * @param prompt
     *        The prompt or instructions displayed for the plugin card.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public QPluginCardInput withPrompt(String prompt) {
        setPrompt(prompt);
        return this;
    }

    /**
     * <p>
     * The unique identifier of the plugin used by the card.
     * </p>
     * 
     * @param pluginId
     *        The unique identifier of the plugin used by the card.
     */

    public void setPluginId(String pluginId) {
        this.pluginId = pluginId;
    }

    /**
     * <p>
     * The unique identifier of the plugin used by the card.
     * </p>
     * 
     * @return The unique identifier of the plugin used by the card.
     */

    public String getPluginId() {
        return this.pluginId;
    }

    /**
     * <p>
     * The unique identifier of the plugin used by the card.
     * </p>
     * 
     * @param pluginId
     *        The unique identifier of the plugin used by the card.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public QPluginCardInput withPluginId(String pluginId) {
        setPluginId(pluginId);
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
        if (getPrompt() != null)
            sb.append("Prompt: ").append(getPrompt()).append(",");
        if (getPluginId() != null)
            sb.append("PluginId: ").append(getPluginId());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof QPluginCardInput == false)
            return false;
        QPluginCardInput other = (QPluginCardInput) obj;
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
        if (other.getPrompt() == null ^ this.getPrompt() == null)
            return false;
        if (other.getPrompt() != null && other.getPrompt().equals(this.getPrompt()) == false)
            return false;
        if (other.getPluginId() == null ^ this.getPluginId() == null)
            return false;
        if (other.getPluginId() != null && other.getPluginId().equals(this.getPluginId()) == false)
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
        hashCode = prime * hashCode + ((getPrompt() == null) ? 0 : getPrompt().hashCode());
        hashCode = prime * hashCode + ((getPluginId() == null) ? 0 : getPluginId().hashCode());
        return hashCode;
    }

    @Override
    public QPluginCardInput clone() {
        try {
            return (QPluginCardInput) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.qapps.model.transform.QPluginCardInputMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
