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
package com.amazonaws.services.workspaces.model;

import java.io.Serializable;
import javax.annotation.Generated;
import com.amazonaws.protocol.StructuredPojo;
import com.amazonaws.protocol.ProtocolMarshaller;

/**
 * <p>
 * Describes the streaming properties.
 * </p>
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/workspaces-2015-04-08/StreamingProperties" target="_top">AWS API
 *      Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class StreamingProperties implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * Indicates the type of preferred protocol for the streaming experience.
     * </p>
     */
    private String streamingExperiencePreferredProtocol;
    /**
     * <p>
     * Indicates the permission settings asscoiated with the user.
     * </p>
     */
    private com.amazonaws.internal.SdkInternalList<UserSetting> userSettings;
    /**
     * <p>
     * Indicates the storage connector used
     * </p>
     */
    private com.amazonaws.internal.SdkInternalList<StorageConnector> storageConnectors;

    /**
     * <p>
     * Indicates the type of preferred protocol for the streaming experience.
     * </p>
     * 
     * @param streamingExperiencePreferredProtocol
     *        Indicates the type of preferred protocol for the streaming experience.
     * @see StreamingExperiencePreferredProtocolEnum
     */

    public void setStreamingExperiencePreferredProtocol(String streamingExperiencePreferredProtocol) {
        this.streamingExperiencePreferredProtocol = streamingExperiencePreferredProtocol;
    }

    /**
     * <p>
     * Indicates the type of preferred protocol for the streaming experience.
     * </p>
     * 
     * @return Indicates the type of preferred protocol for the streaming experience.
     * @see StreamingExperiencePreferredProtocolEnum
     */

    public String getStreamingExperiencePreferredProtocol() {
        return this.streamingExperiencePreferredProtocol;
    }

    /**
     * <p>
     * Indicates the type of preferred protocol for the streaming experience.
     * </p>
     * 
     * @param streamingExperiencePreferredProtocol
     *        Indicates the type of preferred protocol for the streaming experience.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see StreamingExperiencePreferredProtocolEnum
     */

    public StreamingProperties withStreamingExperiencePreferredProtocol(String streamingExperiencePreferredProtocol) {
        setStreamingExperiencePreferredProtocol(streamingExperiencePreferredProtocol);
        return this;
    }

    /**
     * <p>
     * Indicates the type of preferred protocol for the streaming experience.
     * </p>
     * 
     * @param streamingExperiencePreferredProtocol
     *        Indicates the type of preferred protocol for the streaming experience.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see StreamingExperiencePreferredProtocolEnum
     */

    public StreamingProperties withStreamingExperiencePreferredProtocol(StreamingExperiencePreferredProtocolEnum streamingExperiencePreferredProtocol) {
        this.streamingExperiencePreferredProtocol = streamingExperiencePreferredProtocol.toString();
        return this;
    }

    /**
     * <p>
     * Indicates the permission settings asscoiated with the user.
     * </p>
     * 
     * @return Indicates the permission settings asscoiated with the user.
     */

    public java.util.List<UserSetting> getUserSettings() {
        if (userSettings == null) {
            userSettings = new com.amazonaws.internal.SdkInternalList<UserSetting>();
        }
        return userSettings;
    }

    /**
     * <p>
     * Indicates the permission settings asscoiated with the user.
     * </p>
     * 
     * @param userSettings
     *        Indicates the permission settings asscoiated with the user.
     */

    public void setUserSettings(java.util.Collection<UserSetting> userSettings) {
        if (userSettings == null) {
            this.userSettings = null;
            return;
        }

        this.userSettings = new com.amazonaws.internal.SdkInternalList<UserSetting>(userSettings);
    }

    /**
     * <p>
     * Indicates the permission settings asscoiated with the user.
     * </p>
     * <p>
     * <b>NOTE:</b> This method appends the values to the existing list (if any). Use
     * {@link #setUserSettings(java.util.Collection)} or {@link #withUserSettings(java.util.Collection)} if you want to
     * override the existing values.
     * </p>
     * 
     * @param userSettings
     *        Indicates the permission settings asscoiated with the user.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public StreamingProperties withUserSettings(UserSetting... userSettings) {
        if (this.userSettings == null) {
            setUserSettings(new com.amazonaws.internal.SdkInternalList<UserSetting>(userSettings.length));
        }
        for (UserSetting ele : userSettings) {
            this.userSettings.add(ele);
        }
        return this;
    }

    /**
     * <p>
     * Indicates the permission settings asscoiated with the user.
     * </p>
     * 
     * @param userSettings
     *        Indicates the permission settings asscoiated with the user.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public StreamingProperties withUserSettings(java.util.Collection<UserSetting> userSettings) {
        setUserSettings(userSettings);
        return this;
    }

    /**
     * <p>
     * Indicates the storage connector used
     * </p>
     * 
     * @return Indicates the storage connector used
     */

    public java.util.List<StorageConnector> getStorageConnectors() {
        if (storageConnectors == null) {
            storageConnectors = new com.amazonaws.internal.SdkInternalList<StorageConnector>();
        }
        return storageConnectors;
    }

    /**
     * <p>
     * Indicates the storage connector used
     * </p>
     * 
     * @param storageConnectors
     *        Indicates the storage connector used
     */

    public void setStorageConnectors(java.util.Collection<StorageConnector> storageConnectors) {
        if (storageConnectors == null) {
            this.storageConnectors = null;
            return;
        }

        this.storageConnectors = new com.amazonaws.internal.SdkInternalList<StorageConnector>(storageConnectors);
    }

    /**
     * <p>
     * Indicates the storage connector used
     * </p>
     * <p>
     * <b>NOTE:</b> This method appends the values to the existing list (if any). Use
     * {@link #setStorageConnectors(java.util.Collection)} or {@link #withStorageConnectors(java.util.Collection)} if
     * you want to override the existing values.
     * </p>
     * 
     * @param storageConnectors
     *        Indicates the storage connector used
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public StreamingProperties withStorageConnectors(StorageConnector... storageConnectors) {
        if (this.storageConnectors == null) {
            setStorageConnectors(new com.amazonaws.internal.SdkInternalList<StorageConnector>(storageConnectors.length));
        }
        for (StorageConnector ele : storageConnectors) {
            this.storageConnectors.add(ele);
        }
        return this;
    }

    /**
     * <p>
     * Indicates the storage connector used
     * </p>
     * 
     * @param storageConnectors
     *        Indicates the storage connector used
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public StreamingProperties withStorageConnectors(java.util.Collection<StorageConnector> storageConnectors) {
        setStorageConnectors(storageConnectors);
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
        if (getStreamingExperiencePreferredProtocol() != null)
            sb.append("StreamingExperiencePreferredProtocol: ").append(getStreamingExperiencePreferredProtocol()).append(",");
        if (getUserSettings() != null)
            sb.append("UserSettings: ").append(getUserSettings()).append(",");
        if (getStorageConnectors() != null)
            sb.append("StorageConnectors: ").append(getStorageConnectors());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof StreamingProperties == false)
            return false;
        StreamingProperties other = (StreamingProperties) obj;
        if (other.getStreamingExperiencePreferredProtocol() == null ^ this.getStreamingExperiencePreferredProtocol() == null)
            return false;
        if (other.getStreamingExperiencePreferredProtocol() != null
                && other.getStreamingExperiencePreferredProtocol().equals(this.getStreamingExperiencePreferredProtocol()) == false)
            return false;
        if (other.getUserSettings() == null ^ this.getUserSettings() == null)
            return false;
        if (other.getUserSettings() != null && other.getUserSettings().equals(this.getUserSettings()) == false)
            return false;
        if (other.getStorageConnectors() == null ^ this.getStorageConnectors() == null)
            return false;
        if (other.getStorageConnectors() != null && other.getStorageConnectors().equals(this.getStorageConnectors()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getStreamingExperiencePreferredProtocol() == null) ? 0 : getStreamingExperiencePreferredProtocol().hashCode());
        hashCode = prime * hashCode + ((getUserSettings() == null) ? 0 : getUserSettings().hashCode());
        hashCode = prime * hashCode + ((getStorageConnectors() == null) ? 0 : getStorageConnectors().hashCode());
        return hashCode;
    }

    @Override
    public StreamingProperties clone() {
        try {
            return (StreamingProperties) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.workspaces.model.transform.StreamingPropertiesMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
