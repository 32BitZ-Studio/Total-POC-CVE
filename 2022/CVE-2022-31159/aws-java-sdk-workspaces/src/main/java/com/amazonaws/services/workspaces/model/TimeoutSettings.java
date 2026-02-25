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
 * Describes the timeout settings for a pool of WorkSpaces.
 * </p>
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/workspaces-2015-04-08/TimeoutSettings" target="_top">AWS API
 *      Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class TimeoutSettings implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * Specifies the amount of time, in seconds, that a streaming session remains active after users disconnect. If
     * users try to reconnect to the streaming session after a disconnection or network interruption within the time
     * set, they are connected to their previous session. Otherwise, they are connected to a new session with a new
     * streaming instance.
     * </p>
     */
    private Integer disconnectTimeoutInSeconds;
    /**
     * <p>
     * The amount of time in seconds a connection will stay active while idle.
     * </p>
     */
    private Integer idleDisconnectTimeoutInSeconds;
    /**
     * <p>
     * Specifies the maximum amount of time, in seconds, that a streaming session can remain active. If users are still
     * connected to a streaming instance five minutes before this limit is reached, they are prompted to save any open
     * documents before being disconnected. After this time elapses, the instance is terminated and replaced by a new
     * instance.
     * </p>
     */
    private Integer maxUserDurationInSeconds;

    /**
     * <p>
     * Specifies the amount of time, in seconds, that a streaming session remains active after users disconnect. If
     * users try to reconnect to the streaming session after a disconnection or network interruption within the time
     * set, they are connected to their previous session. Otherwise, they are connected to a new session with a new
     * streaming instance.
     * </p>
     * 
     * @param disconnectTimeoutInSeconds
     *        Specifies the amount of time, in seconds, that a streaming session remains active after users disconnect.
     *        If users try to reconnect to the streaming session after a disconnection or network interruption within
     *        the time set, they are connected to their previous session. Otherwise, they are connected to a new session
     *        with a new streaming instance.
     */

    public void setDisconnectTimeoutInSeconds(Integer disconnectTimeoutInSeconds) {
        this.disconnectTimeoutInSeconds = disconnectTimeoutInSeconds;
    }

    /**
     * <p>
     * Specifies the amount of time, in seconds, that a streaming session remains active after users disconnect. If
     * users try to reconnect to the streaming session after a disconnection or network interruption within the time
     * set, they are connected to their previous session. Otherwise, they are connected to a new session with a new
     * streaming instance.
     * </p>
     * 
     * @return Specifies the amount of time, in seconds, that a streaming session remains active after users disconnect.
     *         If users try to reconnect to the streaming session after a disconnection or network interruption within
     *         the time set, they are connected to their previous session. Otherwise, they are connected to a new
     *         session with a new streaming instance.
     */

    public Integer getDisconnectTimeoutInSeconds() {
        return this.disconnectTimeoutInSeconds;
    }

    /**
     * <p>
     * Specifies the amount of time, in seconds, that a streaming session remains active after users disconnect. If
     * users try to reconnect to the streaming session after a disconnection or network interruption within the time
     * set, they are connected to their previous session. Otherwise, they are connected to a new session with a new
     * streaming instance.
     * </p>
     * 
     * @param disconnectTimeoutInSeconds
     *        Specifies the amount of time, in seconds, that a streaming session remains active after users disconnect.
     *        If users try to reconnect to the streaming session after a disconnection or network interruption within
     *        the time set, they are connected to their previous session. Otherwise, they are connected to a new session
     *        with a new streaming instance.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public TimeoutSettings withDisconnectTimeoutInSeconds(Integer disconnectTimeoutInSeconds) {
        setDisconnectTimeoutInSeconds(disconnectTimeoutInSeconds);
        return this;
    }

    /**
     * <p>
     * The amount of time in seconds a connection will stay active while idle.
     * </p>
     * 
     * @param idleDisconnectTimeoutInSeconds
     *        The amount of time in seconds a connection will stay active while idle.
     */

    public void setIdleDisconnectTimeoutInSeconds(Integer idleDisconnectTimeoutInSeconds) {
        this.idleDisconnectTimeoutInSeconds = idleDisconnectTimeoutInSeconds;
    }

    /**
     * <p>
     * The amount of time in seconds a connection will stay active while idle.
     * </p>
     * 
     * @return The amount of time in seconds a connection will stay active while idle.
     */

    public Integer getIdleDisconnectTimeoutInSeconds() {
        return this.idleDisconnectTimeoutInSeconds;
    }

    /**
     * <p>
     * The amount of time in seconds a connection will stay active while idle.
     * </p>
     * 
     * @param idleDisconnectTimeoutInSeconds
     *        The amount of time in seconds a connection will stay active while idle.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public TimeoutSettings withIdleDisconnectTimeoutInSeconds(Integer idleDisconnectTimeoutInSeconds) {
        setIdleDisconnectTimeoutInSeconds(idleDisconnectTimeoutInSeconds);
        return this;
    }

    /**
     * <p>
     * Specifies the maximum amount of time, in seconds, that a streaming session can remain active. If users are still
     * connected to a streaming instance five minutes before this limit is reached, they are prompted to save any open
     * documents before being disconnected. After this time elapses, the instance is terminated and replaced by a new
     * instance.
     * </p>
     * 
     * @param maxUserDurationInSeconds
     *        Specifies the maximum amount of time, in seconds, that a streaming session can remain active. If users are
     *        still connected to a streaming instance five minutes before this limit is reached, they are prompted to
     *        save any open documents before being disconnected. After this time elapses, the instance is terminated and
     *        replaced by a new instance.
     */

    public void setMaxUserDurationInSeconds(Integer maxUserDurationInSeconds) {
        this.maxUserDurationInSeconds = maxUserDurationInSeconds;
    }

    /**
     * <p>
     * Specifies the maximum amount of time, in seconds, that a streaming session can remain active. If users are still
     * connected to a streaming instance five minutes before this limit is reached, they are prompted to save any open
     * documents before being disconnected. After this time elapses, the instance is terminated and replaced by a new
     * instance.
     * </p>
     * 
     * @return Specifies the maximum amount of time, in seconds, that a streaming session can remain active. If users
     *         are still connected to a streaming instance five minutes before this limit is reached, they are prompted
     *         to save any open documents before being disconnected. After this time elapses, the instance is terminated
     *         and replaced by a new instance.
     */

    public Integer getMaxUserDurationInSeconds() {
        return this.maxUserDurationInSeconds;
    }

    /**
     * <p>
     * Specifies the maximum amount of time, in seconds, that a streaming session can remain active. If users are still
     * connected to a streaming instance five minutes before this limit is reached, they are prompted to save any open
     * documents before being disconnected. After this time elapses, the instance is terminated and replaced by a new
     * instance.
     * </p>
     * 
     * @param maxUserDurationInSeconds
     *        Specifies the maximum amount of time, in seconds, that a streaming session can remain active. If users are
     *        still connected to a streaming instance five minutes before this limit is reached, they are prompted to
     *        save any open documents before being disconnected. After this time elapses, the instance is terminated and
     *        replaced by a new instance.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public TimeoutSettings withMaxUserDurationInSeconds(Integer maxUserDurationInSeconds) {
        setMaxUserDurationInSeconds(maxUserDurationInSeconds);
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
        if (getDisconnectTimeoutInSeconds() != null)
            sb.append("DisconnectTimeoutInSeconds: ").append(getDisconnectTimeoutInSeconds()).append(",");
        if (getIdleDisconnectTimeoutInSeconds() != null)
            sb.append("IdleDisconnectTimeoutInSeconds: ").append(getIdleDisconnectTimeoutInSeconds()).append(",");
        if (getMaxUserDurationInSeconds() != null)
            sb.append("MaxUserDurationInSeconds: ").append(getMaxUserDurationInSeconds());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof TimeoutSettings == false)
            return false;
        TimeoutSettings other = (TimeoutSettings) obj;
        if (other.getDisconnectTimeoutInSeconds() == null ^ this.getDisconnectTimeoutInSeconds() == null)
            return false;
        if (other.getDisconnectTimeoutInSeconds() != null && other.getDisconnectTimeoutInSeconds().equals(this.getDisconnectTimeoutInSeconds()) == false)
            return false;
        if (other.getIdleDisconnectTimeoutInSeconds() == null ^ this.getIdleDisconnectTimeoutInSeconds() == null)
            return false;
        if (other.getIdleDisconnectTimeoutInSeconds() != null
                && other.getIdleDisconnectTimeoutInSeconds().equals(this.getIdleDisconnectTimeoutInSeconds()) == false)
            return false;
        if (other.getMaxUserDurationInSeconds() == null ^ this.getMaxUserDurationInSeconds() == null)
            return false;
        if (other.getMaxUserDurationInSeconds() != null && other.getMaxUserDurationInSeconds().equals(this.getMaxUserDurationInSeconds()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getDisconnectTimeoutInSeconds() == null) ? 0 : getDisconnectTimeoutInSeconds().hashCode());
        hashCode = prime * hashCode + ((getIdleDisconnectTimeoutInSeconds() == null) ? 0 : getIdleDisconnectTimeoutInSeconds().hashCode());
        hashCode = prime * hashCode + ((getMaxUserDurationInSeconds() == null) ? 0 : getMaxUserDurationInSeconds().hashCode());
        return hashCode;
    }

    @Override
    public TimeoutSettings clone() {
        try {
            return (TimeoutSettings) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.workspaces.model.transform.TimeoutSettingsMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
