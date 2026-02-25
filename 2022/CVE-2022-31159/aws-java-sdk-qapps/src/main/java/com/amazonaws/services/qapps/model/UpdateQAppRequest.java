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
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/qapps-2023-11-27/UpdateQApp" target="_top">AWS API
 *      Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class UpdateQAppRequest extends com.amazonaws.AmazonWebServiceRequest implements Serializable, Cloneable {

    /**
     * <p>
     * The unique identifier of the Amazon Q Business application environment instance.
     * </p>
     */
    private String instanceId;
    /**
     * <p>
     * The unique identifier of the Q App to update.
     * </p>
     */
    private String appId;
    /**
     * <p>
     * The new title for the Q App.
     * </p>
     */
    private String title;
    /**
     * <p>
     * The new description for the Q App.
     * </p>
     */
    private String description;
    /**
     * <p>
     * The new definition specifying the cards and flow for the Q App.
     * </p>
     */
    private AppDefinitionInput appDefinition;

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

    public UpdateQAppRequest withInstanceId(String instanceId) {
        setInstanceId(instanceId);
        return this;
    }

    /**
     * <p>
     * The unique identifier of the Q App to update.
     * </p>
     * 
     * @param appId
     *        The unique identifier of the Q App to update.
     */

    public void setAppId(String appId) {
        this.appId = appId;
    }

    /**
     * <p>
     * The unique identifier of the Q App to update.
     * </p>
     * 
     * @return The unique identifier of the Q App to update.
     */

    public String getAppId() {
        return this.appId;
    }

    /**
     * <p>
     * The unique identifier of the Q App to update.
     * </p>
     * 
     * @param appId
     *        The unique identifier of the Q App to update.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public UpdateQAppRequest withAppId(String appId) {
        setAppId(appId);
        return this;
    }

    /**
     * <p>
     * The new title for the Q App.
     * </p>
     * 
     * @param title
     *        The new title for the Q App.
     */

    public void setTitle(String title) {
        this.title = title;
    }

    /**
     * <p>
     * The new title for the Q App.
     * </p>
     * 
     * @return The new title for the Q App.
     */

    public String getTitle() {
        return this.title;
    }

    /**
     * <p>
     * The new title for the Q App.
     * </p>
     * 
     * @param title
     *        The new title for the Q App.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public UpdateQAppRequest withTitle(String title) {
        setTitle(title);
        return this;
    }

    /**
     * <p>
     * The new description for the Q App.
     * </p>
     * 
     * @param description
     *        The new description for the Q App.
     */

    public void setDescription(String description) {
        this.description = description;
    }

    /**
     * <p>
     * The new description for the Q App.
     * </p>
     * 
     * @return The new description for the Q App.
     */

    public String getDescription() {
        return this.description;
    }

    /**
     * <p>
     * The new description for the Q App.
     * </p>
     * 
     * @param description
     *        The new description for the Q App.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public UpdateQAppRequest withDescription(String description) {
        setDescription(description);
        return this;
    }

    /**
     * <p>
     * The new definition specifying the cards and flow for the Q App.
     * </p>
     * 
     * @param appDefinition
     *        The new definition specifying the cards and flow for the Q App.
     */

    public void setAppDefinition(AppDefinitionInput appDefinition) {
        this.appDefinition = appDefinition;
    }

    /**
     * <p>
     * The new definition specifying the cards and flow for the Q App.
     * </p>
     * 
     * @return The new definition specifying the cards and flow for the Q App.
     */

    public AppDefinitionInput getAppDefinition() {
        return this.appDefinition;
    }

    /**
     * <p>
     * The new definition specifying the cards and flow for the Q App.
     * </p>
     * 
     * @param appDefinition
     *        The new definition specifying the cards and flow for the Q App.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public UpdateQAppRequest withAppDefinition(AppDefinitionInput appDefinition) {
        setAppDefinition(appDefinition);
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
        if (getAppId() != null)
            sb.append("AppId: ").append(getAppId()).append(",");
        if (getTitle() != null)
            sb.append("Title: ").append(getTitle()).append(",");
        if (getDescription() != null)
            sb.append("Description: ").append(getDescription()).append(",");
        if (getAppDefinition() != null)
            sb.append("AppDefinition: ").append(getAppDefinition());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof UpdateQAppRequest == false)
            return false;
        UpdateQAppRequest other = (UpdateQAppRequest) obj;
        if (other.getInstanceId() == null ^ this.getInstanceId() == null)
            return false;
        if (other.getInstanceId() != null && other.getInstanceId().equals(this.getInstanceId()) == false)
            return false;
        if (other.getAppId() == null ^ this.getAppId() == null)
            return false;
        if (other.getAppId() != null && other.getAppId().equals(this.getAppId()) == false)
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
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getInstanceId() == null) ? 0 : getInstanceId().hashCode());
        hashCode = prime * hashCode + ((getAppId() == null) ? 0 : getAppId().hashCode());
        hashCode = prime * hashCode + ((getTitle() == null) ? 0 : getTitle().hashCode());
        hashCode = prime * hashCode + ((getDescription() == null) ? 0 : getDescription().hashCode());
        hashCode = prime * hashCode + ((getAppDefinition() == null) ? 0 : getAppDefinition().hashCode());
        return hashCode;
    }

    @Override
    public UpdateQAppRequest clone() {
        return (UpdateQAppRequest) super.clone();
    }

}
