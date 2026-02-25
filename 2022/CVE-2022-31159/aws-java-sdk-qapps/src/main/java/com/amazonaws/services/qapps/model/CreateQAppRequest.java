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
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/qapps-2023-11-27/CreateQApp" target="_top">AWS API
 *      Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class CreateQAppRequest extends com.amazonaws.AmazonWebServiceRequest implements Serializable, Cloneable {

    /**
     * <p>
     * The unique identifier of the Amazon Q Business application environment instance.
     * </p>
     */
    private String instanceId;
    /**
     * <p>
     * The title of the new Q App.
     * </p>
     */
    private String title;
    /**
     * <p>
     * The description of the new Q App.
     * </p>
     */
    private String description;
    /**
     * <p>
     * The definition of the new Q App, specifying the cards and flow.
     * </p>
     */
    private AppDefinitionInput appDefinition;
    /**
     * <p>
     * Optional tags to associate with the new Q App.
     * </p>
     */
    private java.util.Map<String, String> tags;

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

    public CreateQAppRequest withInstanceId(String instanceId) {
        setInstanceId(instanceId);
        return this;
    }

    /**
     * <p>
     * The title of the new Q App.
     * </p>
     * 
     * @param title
     *        The title of the new Q App.
     */

    public void setTitle(String title) {
        this.title = title;
    }

    /**
     * <p>
     * The title of the new Q App.
     * </p>
     * 
     * @return The title of the new Q App.
     */

    public String getTitle() {
        return this.title;
    }

    /**
     * <p>
     * The title of the new Q App.
     * </p>
     * 
     * @param title
     *        The title of the new Q App.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public CreateQAppRequest withTitle(String title) {
        setTitle(title);
        return this;
    }

    /**
     * <p>
     * The description of the new Q App.
     * </p>
     * 
     * @param description
     *        The description of the new Q App.
     */

    public void setDescription(String description) {
        this.description = description;
    }

    /**
     * <p>
     * The description of the new Q App.
     * </p>
     * 
     * @return The description of the new Q App.
     */

    public String getDescription() {
        return this.description;
    }

    /**
     * <p>
     * The description of the new Q App.
     * </p>
     * 
     * @param description
     *        The description of the new Q App.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public CreateQAppRequest withDescription(String description) {
        setDescription(description);
        return this;
    }

    /**
     * <p>
     * The definition of the new Q App, specifying the cards and flow.
     * </p>
     * 
     * @param appDefinition
     *        The definition of the new Q App, specifying the cards and flow.
     */

    public void setAppDefinition(AppDefinitionInput appDefinition) {
        this.appDefinition = appDefinition;
    }

    /**
     * <p>
     * The definition of the new Q App, specifying the cards and flow.
     * </p>
     * 
     * @return The definition of the new Q App, specifying the cards and flow.
     */

    public AppDefinitionInput getAppDefinition() {
        return this.appDefinition;
    }

    /**
     * <p>
     * The definition of the new Q App, specifying the cards and flow.
     * </p>
     * 
     * @param appDefinition
     *        The definition of the new Q App, specifying the cards and flow.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public CreateQAppRequest withAppDefinition(AppDefinitionInput appDefinition) {
        setAppDefinition(appDefinition);
        return this;
    }

    /**
     * <p>
     * Optional tags to associate with the new Q App.
     * </p>
     * 
     * @return Optional tags to associate with the new Q App.
     */

    public java.util.Map<String, String> getTags() {
        return tags;
    }

    /**
     * <p>
     * Optional tags to associate with the new Q App.
     * </p>
     * 
     * @param tags
     *        Optional tags to associate with the new Q App.
     */

    public void setTags(java.util.Map<String, String> tags) {
        this.tags = tags;
    }

    /**
     * <p>
     * Optional tags to associate with the new Q App.
     * </p>
     * 
     * @param tags
     *        Optional tags to associate with the new Q App.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public CreateQAppRequest withTags(java.util.Map<String, String> tags) {
        setTags(tags);
        return this;
    }

    /**
     * Add a single Tags entry
     *
     * @see CreateQAppRequest#withTags
     * @returns a reference to this object so that method calls can be chained together.
     */

    public CreateQAppRequest addTagsEntry(String key, String value) {
        if (null == this.tags) {
            this.tags = new java.util.HashMap<String, String>();
        }
        if (this.tags.containsKey(key))
            throw new IllegalArgumentException("Duplicated keys (" + key.toString() + ") are provided.");
        this.tags.put(key, value);
        return this;
    }

    /**
     * Removes all the entries added into Tags.
     *
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public CreateQAppRequest clearTagsEntries() {
        this.tags = null;
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
        if (getTitle() != null)
            sb.append("Title: ").append(getTitle()).append(",");
        if (getDescription() != null)
            sb.append("Description: ").append(getDescription()).append(",");
        if (getAppDefinition() != null)
            sb.append("AppDefinition: ").append(getAppDefinition()).append(",");
        if (getTags() != null)
            sb.append("Tags: ").append(getTags());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof CreateQAppRequest == false)
            return false;
        CreateQAppRequest other = (CreateQAppRequest) obj;
        if (other.getInstanceId() == null ^ this.getInstanceId() == null)
            return false;
        if (other.getInstanceId() != null && other.getInstanceId().equals(this.getInstanceId()) == false)
            return false;
        if (other.getTitle() == null ^ this.getTitle() == null)
            return false;
        if (other.getTitle() != null && other.getTitle().equals(this.getTitle()) == false)
            return false;
        if (other.getDescription() == null ^ this.getDescription() == null)
            return false;
        if (other.getDescription() != null && other.getDescription().equals(this.getDescription()) == false)
            return false;
        if (other.getAppDefinition() == null ^ this.getAppDefinition() == null)
            return false;
        if (other.getAppDefinition() != null && other.getAppDefinition().equals(this.getAppDefinition()) == false)
            return false;
        if (other.getTags() == null ^ this.getTags() == null)
            return false;
        if (other.getTags() != null && other.getTags().equals(this.getTags()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getInstanceId() == null) ? 0 : getInstanceId().hashCode());
        hashCode = prime * hashCode + ((getTitle() == null) ? 0 : getTitle().hashCode());
        hashCode = prime * hashCode + ((getDescription() == null) ? 0 : getDescription().hashCode());
        hashCode = prime * hashCode + ((getAppDefinition() == null) ? 0 : getAppDefinition().hashCode());
        hashCode = prime * hashCode + ((getTags() == null) ? 0 : getTags().hashCode());
        return hashCode;
    }

    @Override
    public CreateQAppRequest clone() {
        return (CreateQAppRequest) super.clone();
    }

}
