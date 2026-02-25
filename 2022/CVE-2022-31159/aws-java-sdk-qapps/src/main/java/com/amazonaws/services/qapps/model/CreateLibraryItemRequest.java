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
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/qapps-2023-11-27/CreateLibraryItem" target="_top">AWS API
 *      Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class CreateLibraryItemRequest extends com.amazonaws.AmazonWebServiceRequest implements Serializable, Cloneable {

    /**
     * <p>
     * The unique identifier of the Amazon Q Business application environment instance.
     * </p>
     */
    private String instanceId;
    /**
     * <p>
     * The unique identifier of the Amazon Q App to publish to the library.
     * </p>
     */
    private String appId;
    /**
     * <p>
     * The version of the Amazon Q App to publish to the library.
     * </p>
     */
    private Integer appVersion;
    /**
     * <p>
     * The categories to associate with the library item for easier discovery.
     * </p>
     */
    private java.util.List<String> categories;

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

    public CreateLibraryItemRequest withInstanceId(String instanceId) {
        setInstanceId(instanceId);
        return this;
    }

    /**
     * <p>
     * The unique identifier of the Amazon Q App to publish to the library.
     * </p>
     * 
     * @param appId
     *        The unique identifier of the Amazon Q App to publish to the library.
     */

    public void setAppId(String appId) {
        this.appId = appId;
    }

    /**
     * <p>
     * The unique identifier of the Amazon Q App to publish to the library.
     * </p>
     * 
     * @return The unique identifier of the Amazon Q App to publish to the library.
     */

    public String getAppId() {
        return this.appId;
    }

    /**
     * <p>
     * The unique identifier of the Amazon Q App to publish to the library.
     * </p>
     * 
     * @param appId
     *        The unique identifier of the Amazon Q App to publish to the library.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public CreateLibraryItemRequest withAppId(String appId) {
        setAppId(appId);
        return this;
    }

    /**
     * <p>
     * The version of the Amazon Q App to publish to the library.
     * </p>
     * 
     * @param appVersion
     *        The version of the Amazon Q App to publish to the library.
     */

    public void setAppVersion(Integer appVersion) {
        this.appVersion = appVersion;
    }

    /**
     * <p>
     * The version of the Amazon Q App to publish to the library.
     * </p>
     * 
     * @return The version of the Amazon Q App to publish to the library.
     */

    public Integer getAppVersion() {
        return this.appVersion;
    }

    /**
     * <p>
     * The version of the Amazon Q App to publish to the library.
     * </p>
     * 
     * @param appVersion
     *        The version of the Amazon Q App to publish to the library.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public CreateLibraryItemRequest withAppVersion(Integer appVersion) {
        setAppVersion(appVersion);
        return this;
    }

    /**
     * <p>
     * The categories to associate with the library item for easier discovery.
     * </p>
     * 
     * @return The categories to associate with the library item for easier discovery.
     */

    public java.util.List<String> getCategories() {
        return categories;
    }

    /**
     * <p>
     * The categories to associate with the library item for easier discovery.
     * </p>
     * 
     * @param categories
     *        The categories to associate with the library item for easier discovery.
     */

    public void setCategories(java.util.Collection<String> categories) {
        if (categories == null) {
            this.categories = null;
            return;
        }

        this.categories = new java.util.ArrayList<String>(categories);
    }

    /**
     * <p>
     * The categories to associate with the library item for easier discovery.
     * </p>
     * <p>
     * <b>NOTE:</b> This method appends the values to the existing list (if any). Use
     * {@link #setCategories(java.util.Collection)} or {@link #withCategories(java.util.Collection)} if you want to
     * override the existing values.
     * </p>
     * 
     * @param categories
     *        The categories to associate with the library item for easier discovery.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public CreateLibraryItemRequest withCategories(String... categories) {
        if (this.categories == null) {
            setCategories(new java.util.ArrayList<String>(categories.length));
        }
        for (String ele : categories) {
            this.categories.add(ele);
        }
        return this;
    }

    /**
     * <p>
     * The categories to associate with the library item for easier discovery.
     * </p>
     * 
     * @param categories
     *        The categories to associate with the library item for easier discovery.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public CreateLibraryItemRequest withCategories(java.util.Collection<String> categories) {
        setCategories(categories);
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
        if (getAppVersion() != null)
            sb.append("AppVersion: ").append(getAppVersion()).append(",");
        if (getCategories() != null)
            sb.append("Categories: ").append(getCategories());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof CreateLibraryItemRequest == false)
            return false;
        CreateLibraryItemRequest other = (CreateLibraryItemRequest) obj;
        if (other.getInstanceId() == null ^ this.getInstanceId() == null)
            return false;
        if (other.getInstanceId() != null && other.getInstanceId().equals(this.getInstanceId()) == false)
            return false;
        if (other.getAppId() == null ^ this.getAppId() == null)
            return false;
        if (other.getAppId() != null && other.getAppId().equals(this.getAppId()) == false)
            return false;
        if (other.getAppVersion() == null ^ this.getAppVersion() == null)
            return false;
        if (other.getAppVersion() != null && other.getAppVersion().equals(this.getAppVersion()) == false)
            return false;
        if (other.getCategories() == null ^ this.getCategories() == null)
            return false;
        if (other.getCategories() != null && other.getCategories().equals(this.getCategories()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getInstanceId() == null) ? 0 : getInstanceId().hashCode());
        hashCode = prime * hashCode + ((getAppId() == null) ? 0 : getAppId().hashCode());
        hashCode = prime * hashCode + ((getAppVersion() == null) ? 0 : getAppVersion().hashCode());
        hashCode = prime * hashCode + ((getCategories() == null) ? 0 : getCategories().hashCode());
        return hashCode;
    }

    @Override
    public CreateLibraryItemRequest clone() {
        return (CreateLibraryItemRequest) super.clone();
    }

}
