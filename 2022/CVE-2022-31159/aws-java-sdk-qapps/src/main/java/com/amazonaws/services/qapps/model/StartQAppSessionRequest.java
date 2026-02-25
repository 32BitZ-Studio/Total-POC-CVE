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
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/qapps-2023-11-27/StartQAppSession" target="_top">AWS API
 *      Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class StartQAppSessionRequest extends com.amazonaws.AmazonWebServiceRequest implements Serializable, Cloneable {

    /**
     * <p>
     * The unique identifier of the Amazon Q Business application environment instance.
     * </p>
     */
    private String instanceId;
    /**
     * <p>
     * The unique identifier of the Q App to start a session for.
     * </p>
     */
    private String appId;
    /**
     * <p>
     * The version of the Q App to use for the session.
     * </p>
     */
    private Integer appVersion;
    /**
     * <p>
     * Optional initial input values to provide for the Q App session.
     * </p>
     */
    private java.util.List<CardValue> initialValues;
    /**
     * <p>
     * Optional tags to associate with the new Q App session.
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

    public StartQAppSessionRequest withInstanceId(String instanceId) {
        setInstanceId(instanceId);
        return this;
    }

    /**
     * <p>
     * The unique identifier of the Q App to start a session for.
     * </p>
     * 
     * @param appId
     *        The unique identifier of the Q App to start a session for.
     */

    public void setAppId(String appId) {
        this.appId = appId;
    }

    /**
     * <p>
     * The unique identifier of the Q App to start a session for.
     * </p>
     * 
     * @return The unique identifier of the Q App to start a session for.
     */

    public String getAppId() {
        return this.appId;
    }

    /**
     * <p>
     * The unique identifier of the Q App to start a session for.
     * </p>
     * 
     * @param appId
     *        The unique identifier of the Q App to start a session for.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public StartQAppSessionRequest withAppId(String appId) {
        setAppId(appId);
        return this;
    }

    /**
     * <p>
     * The version of the Q App to use for the session.
     * </p>
     * 
     * @param appVersion
     *        The version of the Q App to use for the session.
     */

    public void setAppVersion(Integer appVersion) {
        this.appVersion = appVersion;
    }

    /**
     * <p>
     * The version of the Q App to use for the session.
     * </p>
     * 
     * @return The version of the Q App to use for the session.
     */

    public Integer getAppVersion() {
        return this.appVersion;
    }

    /**
     * <p>
     * The version of the Q App to use for the session.
     * </p>
     * 
     * @param appVersion
     *        The version of the Q App to use for the session.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public StartQAppSessionRequest withAppVersion(Integer appVersion) {
        setAppVersion(appVersion);
        return this;
    }

    /**
     * <p>
     * Optional initial input values to provide for the Q App session.
     * </p>
     * 
     * @return Optional initial input values to provide for the Q App session.
     */

    public java.util.List<CardValue> getInitialValues() {
        return initialValues;
    }

    /**
     * <p>
     * Optional initial input values to provide for the Q App session.
     * </p>
     * 
     * @param initialValues
     *        Optional initial input values to provide for the Q App session.
     */

    public void setInitialValues(java.util.Collection<CardValue> initialValues) {
        if (initialValues == null) {
            this.initialValues = null;
            return;
        }

        this.initialValues = new java.util.ArrayList<CardValue>(initialValues);
    }

    /**
     * <p>
     * Optional initial input values to provide for the Q App session.
     * </p>
     * <p>
     * <b>NOTE:</b> This method appends the values to the existing list (if any). Use
     * {@link #setInitialValues(java.util.Collection)} or {@link #withInitialValues(java.util.Collection)} if you want
     * to override the existing values.
     * </p>
     * 
     * @param initialValues
     *        Optional initial input values to provide for the Q App session.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public StartQAppSessionRequest withInitialValues(CardValue... initialValues) {
        if (this.initialValues == null) {
            setInitialValues(new java.util.ArrayList<CardValue>(initialValues.length));
        }
        for (CardValue ele : initialValues) {
            this.initialValues.add(ele);
        }
        return this;
    }

    /**
     * <p>
     * Optional initial input values to provide for the Q App session.
     * </p>
     * 
     * @param initialValues
     *        Optional initial input values to provide for the Q App session.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public StartQAppSessionRequest withInitialValues(java.util.Collection<CardValue> initialValues) {
        setInitialValues(initialValues);
        return this;
    }

    /**
     * <p>
     * Optional tags to associate with the new Q App session.
     * </p>
     * 
     * @return Optional tags to associate with the new Q App session.
     */

    public java.util.Map<String, String> getTags() {
        return tags;
    }

    /**
     * <p>
     * Optional tags to associate with the new Q App session.
     * </p>
     * 
     * @param tags
     *        Optional tags to associate with the new Q App session.
     */

    public void setTags(java.util.Map<String, String> tags) {
        this.tags = tags;
    }

    /**
     * <p>
     * Optional tags to associate with the new Q App session.
     * </p>
     * 
     * @param tags
     *        Optional tags to associate with the new Q App session.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public StartQAppSessionRequest withTags(java.util.Map<String, String> tags) {
        setTags(tags);
        return this;
    }

    /**
     * Add a single Tags entry
     *
     * @see StartQAppSessionRequest#withTags
     * @returns a reference to this object so that method calls can be chained together.
     */

    public StartQAppSessionRequest addTagsEntry(String key, String value) {
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

    public StartQAppSessionRequest clearTagsEntries() {
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
        if (getAppId() != null)
            sb.append("AppId: ").append(getAppId()).append(",");
        if (getAppVersion() != null)
            sb.append("AppVersion: ").append(getAppVersion()).append(",");
        if (getInitialValues() != null)
            sb.append("InitialValues: ").append(getInitialValues()).append(",");
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

        if (obj instanceof StartQAppSessionRequest == false)
            return false;
        StartQAppSessionRequest other = (StartQAppSessionRequest) obj;
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
        if (other.getInitialValues() == null ^ this.getInitialValues() == null)
            return false;
        if (other.getInitialValues() != null && other.getInitialValues().equals(this.getInitialValues()) == false)
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
        hashCode = prime * hashCode + ((getAppId() == null) ? 0 : getAppId().hashCode());
        hashCode = prime * hashCode + ((getAppVersion() == null) ? 0 : getAppVersion().hashCode());
        hashCode = prime * hashCode + ((getInitialValues() == null) ? 0 : getInitialValues().hashCode());
        hashCode = prime * hashCode + ((getTags() == null) ? 0 : getTags().hashCode());
        return hashCode;
    }

    @Override
    public StartQAppSessionRequest clone() {
        return (StartQAppSessionRequest) super.clone();
    }

}
