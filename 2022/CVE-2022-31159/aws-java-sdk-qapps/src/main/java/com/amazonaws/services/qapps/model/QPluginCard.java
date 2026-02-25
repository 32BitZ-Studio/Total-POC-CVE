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
 * A card in an Q App that integrates with a third-party plugin or service.
 * </p>
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/qapps-2023-11-27/QPluginCard" target="_top">AWS API
 *      Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class QPluginCard implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * The unique identifier of the plugin card.
     * </p>
     */
    private String id;
    /**
     * <p>
     * The title or label of the plugin card.
     * </p>
     */
    private String title;
    /**
     * <p>
     * Any dependencies or requirements for the plugin card.
     * </p>
     */
    private java.util.List<String> dependencies;
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
     * The type or category of the plugin used by the card.
     * </p>
     */
    private String pluginType;
    /**
     * <p>
     * The unique identifier of the plugin used by the card.
     * </p>
     */
    private String pluginId;

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

    public QPluginCard withId(String id) {
        setId(id);
        return this;
    }

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

    public QPluginCard withTitle(String title) {
        setTitle(title);
        return this;
    }

    /**
     * <p>
     * Any dependencies or requirements for the plugin card.
     * </p>
     * 
     * @return Any dependencies or requirements for the plugin card.
     */

    public java.util.List<String> getDependencies() {
        return dependencies;
    }

    /**
     * <p>
     * Any dependencies or requirements for the plugin card.
     * </p>
     * 
     * @param dependencies
     *        Any dependencies or requirements for the plugin card.
     */

    public void setDependencies(java.util.Collection<String> dependencies) {
        if (dependencies == null) {
            this.dependencies = null;
            return;
        }

        this.dependencies = new java.util.ArrayList<String>(dependencies);
    }

    /**
     * <p>
     * Any dependencies or requirements for the plugin card.
     * </p>
     * <p>
     * <b>NOTE:</b> This method appends the values to the existing list (if any). Use
     * {@link #setDependencies(java.util.Collection)} or {@link #withDependencies(java.util.Collection)} if you want to
     * override the existing values.
     * </p>
     * 
     * @param dependencies
     *        Any dependencies or requirements for the plugin card.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public QPluginCard withDependencies(String... dependencies) {
        if (this.dependencies == null) {
            setDependencies(new java.util.ArrayList<String>(dependencies.length));
        }
        for (String ele : dependencies) {
            this.dependencies.add(ele);
        }
        return this;
    }

    /**
     * <p>
     * Any dependencies or requirements for the plugin card.
     * </p>
     * 
     * @param dependencies
     *        Any dependencies or requirements for the plugin card.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public QPluginCard withDependencies(java.util.Collection<String> dependencies) {
        setDependencies(dependencies);
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

    public QPluginCard withType(String type) {
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

    public QPluginCard withType(CardType type) {
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

    public QPluginCard withPrompt(String prompt) {
        setPrompt(prompt);
        return this;
    }

    /**
     * <p>
     * The type or category of the plugin used by the card.
     * </p>
     * 
     * @param pluginType
     *        The type or category of the plugin used by the card.
     * @see PluginType
     */

    public void setPluginType(String pluginType) {
        this.pluginType = pluginType;
    }

    /**
     * <p>
     * The type or category of the plugin used by the card.
     * </p>
     * 
     * @return The type or category of the plugin used by the card.
     * @see PluginType
     */

    public String getPluginType() {
        return this.pluginType;
    }

    /**
     * <p>
     * The type or category of the plugin used by the card.
     * </p>
     * 
     * @param pluginType
     *        The type or category of the plugin used by the card.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see PluginType
     */

    public QPluginCard withPluginType(String pluginType) {
        setPluginType(pluginType);
        return this;
    }

    /**
     * <p>
     * The type or category of the plugin used by the card.
     * </p>
     * 
     * @param pluginType
     *        The type or category of the plugin used by the card.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see PluginType
     */

    public QPluginCard withPluginType(PluginType pluginType) {
        this.pluginType = pluginType.toString();
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

    public QPluginCard withPluginId(String pluginId) {
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
        if (getId() != null)
            sb.append("Id: ").append(getId()).append(",");
        if (getTitle() != null)
            sb.append("Title: ").append(getTitle()).append(",");
        if (getDependencies() != null)
            sb.append("Dependencies: ").append(getDependencies()).append(",");
        if (getType() != null)
            sb.append("Type: ").append(getType()).append(",");
        if (getPrompt() != null)
            sb.append("Prompt: ").append(getPrompt()).append(",");
        if (getPluginType() != null)
            sb.append("PluginType: ").append(getPluginType()).append(",");
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

        if (obj instanceof QPluginCard == false)
            return false;
        QPluginCard other = (QPluginCard) obj;
        if (other.getId() == null ^ this.getId() == null)
            return false;
        if (other.getId() != null && other.getId().equals(this.getId()) == false)
            return false;
        if (other.getTitle() == null ^ this.getTitle() == null)
            return false;
        if (other.getTitle() != null && other.getTitle().equals(this.getTitle()) == false)
            return false;
        if (other.getDependencies() == null ^ this.getDependencies() == null)
            return false;
        if (other.getDependencies() != null && other.getDependencies().equals(this.getDependencies()) == false)
            return false;
        if (other.getType() == null ^ this.getType() == null)
            return false;
        if (other.getType() != null && other.getType().equals(this.getType()) == false)
            return false;
        if (other.getPrompt() == null ^ this.getPrompt() == null)
            return false;
        if (other.getPrompt() != null && other.getPrompt().equals(this.getPrompt()) == false)
            return false;
        if (other.getPluginType() == null ^ this.getPluginType() == null)
            return false;
        if (other.getPluginType() != null && other.getPluginType().equals(this.getPluginType()) == false)
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

        hashCode = prime * hashCode + ((getId() == null) ? 0 : getId().hashCode());
        hashCode = prime * hashCode + ((getTitle() == null) ? 0 : getTitle().hashCode());
        hashCode = prime * hashCode + ((getDependencies() == null) ? 0 : getDependencies().hashCode());
        hashCode = prime * hashCode + ((getType() == null) ? 0 : getType().hashCode());
        hashCode = prime * hashCode + ((getPrompt() == null) ? 0 : getPrompt().hashCode());
        hashCode = prime * hashCode + ((getPluginType() == null) ? 0 : getPluginType().hashCode());
        hashCode = prime * hashCode + ((getPluginId() == null) ? 0 : getPluginId().hashCode());
        return hashCode;
    }

    @Override
    public QPluginCard clone() {
        try {
            return (QPluginCard) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.qapps.model.transform.QPluginCardMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
