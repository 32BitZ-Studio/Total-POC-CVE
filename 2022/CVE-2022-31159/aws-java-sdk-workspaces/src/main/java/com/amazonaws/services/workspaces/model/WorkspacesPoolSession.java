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
 * Describes a pool session.
 * </p>
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/workspaces-2015-04-08/WorkspacesPoolSession" target="_top">AWS
 *      API Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class WorkspacesPoolSession implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * The authentication method. The user is authenticated using a WorkSpaces Pools URL (API) or SAML 2.0 federation
     * (SAML).
     * </p>
     */
    private String authenticationType;
    /**
     * <p>
     * Specifies whether a user is connected to the pool session.
     * </p>
     */
    private String connectionState;
    /**
     * <p>
     * The identifier of the session.
     * </p>
     */
    private String sessionId;
    /**
     * <p>
     * The identifier for the instance hosting the session.
     * </p>
     */
    private String instanceId;
    /**
     * <p>
     * The identifier of the pool.
     * </p>
     */
    private String poolId;
    /**
     * <p>
     * The time that the pool session ended.
     * </p>
     */
    private java.util.Date expirationTime;
    /**
     * <p>
     * Describes the network details of the pool.
     * </p>
     */
    private NetworkAccessConfiguration networkAccessConfiguration;
    /**
     * <p>
     * The time that the pool sission started.
     * </p>
     */
    private java.util.Date startTime;
    /**
     * <p>
     * The identifier of the user.
     * </p>
     */
    private String userId;

    /**
     * <p>
     * The authentication method. The user is authenticated using a WorkSpaces Pools URL (API) or SAML 2.0 federation
     * (SAML).
     * </p>
     * 
     * @param authenticationType
     *        The authentication method. The user is authenticated using a WorkSpaces Pools URL (API) or SAML 2.0
     *        federation (SAML).
     * @see AuthenticationType
     */

    public void setAuthenticationType(String authenticationType) {
        this.authenticationType = authenticationType;
    }

    /**
     * <p>
     * The authentication method. The user is authenticated using a WorkSpaces Pools URL (API) or SAML 2.0 federation
     * (SAML).
     * </p>
     * 
     * @return The authentication method. The user is authenticated using a WorkSpaces Pools URL (API) or SAML 2.0
     *         federation (SAML).
     * @see AuthenticationType
     */

    public String getAuthenticationType() {
        return this.authenticationType;
    }

    /**
     * <p>
     * The authentication method. The user is authenticated using a WorkSpaces Pools URL (API) or SAML 2.0 federation
     * (SAML).
     * </p>
     * 
     * @param authenticationType
     *        The authentication method. The user is authenticated using a WorkSpaces Pools URL (API) or SAML 2.0
     *        federation (SAML).
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see AuthenticationType
     */

    public WorkspacesPoolSession withAuthenticationType(String authenticationType) {
        setAuthenticationType(authenticationType);
        return this;
    }

    /**
     * <p>
     * The authentication method. The user is authenticated using a WorkSpaces Pools URL (API) or SAML 2.0 federation
     * (SAML).
     * </p>
     * 
     * @param authenticationType
     *        The authentication method. The user is authenticated using a WorkSpaces Pools URL (API) or SAML 2.0
     *        federation (SAML).
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see AuthenticationType
     */

    public WorkspacesPoolSession withAuthenticationType(AuthenticationType authenticationType) {
        this.authenticationType = authenticationType.toString();
        return this;
    }

    /**
     * <p>
     * Specifies whether a user is connected to the pool session.
     * </p>
     * 
     * @param connectionState
     *        Specifies whether a user is connected to the pool session.
     * @see SessionConnectionState
     */

    public void setConnectionState(String connectionState) {
        this.connectionState = connectionState;
    }

    /**
     * <p>
     * Specifies whether a user is connected to the pool session.
     * </p>
     * 
     * @return Specifies whether a user is connected to the pool session.
     * @see SessionConnectionState
     */

    public String getConnectionState() {
        return this.connectionState;
    }

    /**
     * <p>
     * Specifies whether a user is connected to the pool session.
     * </p>
     * 
     * @param connectionState
     *        Specifies whether a user is connected to the pool session.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see SessionConnectionState
     */

    public WorkspacesPoolSession withConnectionState(String connectionState) {
        setConnectionState(connectionState);
        return this;
    }

    /**
     * <p>
     * Specifies whether a user is connected to the pool session.
     * </p>
     * 
     * @param connectionState
     *        Specifies whether a user is connected to the pool session.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see SessionConnectionState
     */

    public WorkspacesPoolSession withConnectionState(SessionConnectionState connectionState) {
        this.connectionState = connectionState.toString();
        return this;
    }

    /**
     * <p>
     * The identifier of the session.
     * </p>
     * 
     * @param sessionId
     *        The identifier of the session.
     */

    public void setSessionId(String sessionId) {
        this.sessionId = sessionId;
    }

    /**
     * <p>
     * The identifier of the session.
     * </p>
     * 
     * @return The identifier of the session.
     */

    public String getSessionId() {
        return this.sessionId;
    }

    /**
     * <p>
     * The identifier of the session.
     * </p>
     * 
     * @param sessionId
     *        The identifier of the session.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public WorkspacesPoolSession withSessionId(String sessionId) {
        setSessionId(sessionId);
        return this;
    }

    /**
     * <p>
     * The identifier for the instance hosting the session.
     * </p>
     * 
     * @param instanceId
     *        The identifier for the instance hosting the session.
     */

    public void setInstanceId(String instanceId) {
        this.instanceId = instanceId;
    }

    /**
     * <p>
     * The identifier for the instance hosting the session.
     * </p>
     * 
     * @return The identifier for the instance hosting the session.
     */

    public String getInstanceId() {
        return this.instanceId;
    }

    /**
     * <p>
     * The identifier for the instance hosting the session.
     * </p>
     * 
     * @param instanceId
     *        The identifier for the instance hosting the session.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public WorkspacesPoolSession withInstanceId(String instanceId) {
        setInstanceId(instanceId);
        return this;
    }

    /**
     * <p>
     * The identifier of the pool.
     * </p>
     * 
     * @param poolId
     *        The identifier of the pool.
     */

    public void setPoolId(String poolId) {
        this.poolId = poolId;
    }

    /**
     * <p>
     * The identifier of the pool.
     * </p>
     * 
     * @return The identifier of the pool.
     */

    public String getPoolId() {
        return this.poolId;
    }

    /**
     * <p>
     * The identifier of the pool.
     * </p>
     * 
     * @param poolId
     *        The identifier of the pool.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public WorkspacesPoolSession withPoolId(String poolId) {
        setPoolId(poolId);
        return this;
    }

    /**
     * <p>
     * The time that the pool session ended.
     * </p>
     * 
     * @param expirationTime
     *        The time that the pool session ended.
     */

    public void setExpirationTime(java.util.Date expirationTime) {
        this.expirationTime = expirationTime;
    }

    /**
     * <p>
     * The time that the pool session ended.
     * </p>
     * 
     * @return The time that the pool session ended.
     */

    public java.util.Date getExpirationTime() {
        return this.expirationTime;
    }

    /**
     * <p>
     * The time that the pool session ended.
     * </p>
     * 
     * @param expirationTime
     *        The time that the pool session ended.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public WorkspacesPoolSession withExpirationTime(java.util.Date expirationTime) {
        setExpirationTime(expirationTime);
        return this;
    }

    /**
     * <p>
     * Describes the network details of the pool.
     * </p>
     * 
     * @param networkAccessConfiguration
     *        Describes the network details of the pool.
     */

    public void setNetworkAccessConfiguration(NetworkAccessConfiguration networkAccessConfiguration) {
        this.networkAccessConfiguration = networkAccessConfiguration;
    }

    /**
     * <p>
     * Describes the network details of the pool.
     * </p>
     * 
     * @return Describes the network details of the pool.
     */

    public NetworkAccessConfiguration getNetworkAccessConfiguration() {
        return this.networkAccessConfiguration;
    }

    /**
     * <p>
     * Describes the network details of the pool.
     * </p>
     * 
     * @param networkAccessConfiguration
     *        Describes the network details of the pool.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public WorkspacesPoolSession withNetworkAccessConfiguration(NetworkAccessConfiguration networkAccessConfiguration) {
        setNetworkAccessConfiguration(networkAccessConfiguration);
        return this;
    }

    /**
     * <p>
     * The time that the pool sission started.
     * </p>
     * 
     * @param startTime
     *        The time that the pool sission started.
     */

    public void setStartTime(java.util.Date startTime) {
        this.startTime = startTime;
    }

    /**
     * <p>
     * The time that the pool sission started.
     * </p>
     * 
     * @return The time that the pool sission started.
     */

    public java.util.Date getStartTime() {
        return this.startTime;
    }

    /**
     * <p>
     * The time that the pool sission started.
     * </p>
     * 
     * @param startTime
     *        The time that the pool sission started.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public WorkspacesPoolSession withStartTime(java.util.Date startTime) {
        setStartTime(startTime);
        return this;
    }

    /**
     * <p>
     * The identifier of the user.
     * </p>
     * 
     * @param userId
     *        The identifier of the user.
     */

    public void setUserId(String userId) {
        this.userId = userId;
    }

    /**
     * <p>
     * The identifier of the user.
     * </p>
     * 
     * @return The identifier of the user.
     */

    public String getUserId() {
        return this.userId;
    }

    /**
     * <p>
     * The identifier of the user.
     * </p>
     * 
     * @param userId
     *        The identifier of the user.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public WorkspacesPoolSession withUserId(String userId) {
        setUserId(userId);
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
        if (getAuthenticationType() != null)
            sb.append("AuthenticationType: ").append(getAuthenticationType()).append(",");
        if (getConnectionState() != null)
            sb.append("ConnectionState: ").append(getConnectionState()).append(",");
        if (getSessionId() != null)
            sb.append("SessionId: ").append(getSessionId()).append(",");
        if (getInstanceId() != null)
            sb.append("InstanceId: ").append(getInstanceId()).append(",");
        if (getPoolId() != null)
            sb.append("PoolId: ").append(getPoolId()).append(",");
        if (getExpirationTime() != null)
            sb.append("ExpirationTime: ").append(getExpirationTime()).append(",");
        if (getNetworkAccessConfiguration() != null)
            sb.append("NetworkAccessConfiguration: ").append(getNetworkAccessConfiguration()).append(",");
        if (getStartTime() != null)
            sb.append("StartTime: ").append(getStartTime()).append(",");
        if (getUserId() != null)
            sb.append("UserId: ").append(getUserId());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof WorkspacesPoolSession == false)
            return false;
        WorkspacesPoolSession other = (WorkspacesPoolSession) obj;
        if (other.getAuthenticationType() == null ^ this.getAuthenticationType() == null)
            return false;
        if (other.getAuthenticationType() != null && other.getAuthenticationType().equals(this.getAuthenticationType()) == false)
            return false;
        if (other.getConnectionState() == null ^ this.getConnectionState() == null)
            return false;
        if (other.getConnectionState() != null && other.getConnectionState().equals(this.getConnectionState()) == false)
            return false;
        if (other.getSessionId() == null ^ this.getSessionId() == null)
            return false;
        if (other.getSessionId() != null && other.getSessionId().equals(this.getSessionId()) == false)
            return false;
        if (other.getInstanceId() == null ^ this.getInstanceId() == null)
            return false;
        if (other.getInstanceId() != null && other.getInstanceId().equals(this.getInstanceId()) == false)
            return false;
        if (other.getPoolId() == null ^ this.getPoolId() == null)
            return false;
        if (other.getPoolId() != null && other.getPoolId().equals(this.getPoolId()) == false)
            return false;
        if (other.getExpirationTime() == null ^ this.getExpirationTime() == null)
            return false;
        if (other.getExpirationTime() != null && other.getExpirationTime().equals(this.getExpirationTime()) == false)
            return false;
        if (other.getNetworkAccessConfiguration() == null ^ this.getNetworkAccessConfiguration() == null)
            return false;
        if (other.getNetworkAccessConfiguration() != null && other.getNetworkAccessConfiguration().equals(this.getNetworkAccessConfiguration()) == false)
            return false;
        if (other.getStartTime() == null ^ this.getStartTime() == null)
            return false;
        if (other.getStartTime() != null && other.getStartTime().equals(this.getStartTime()) == false)
            return false;
        if (other.getUserId() == null ^ this.getUserId() == null)
            return false;
        if (other.getUserId() != null && other.getUserId().equals(this.getUserId()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getAuthenticationType() == null) ? 0 : getAuthenticationType().hashCode());
        hashCode = prime * hashCode + ((getConnectionState() == null) ? 0 : getConnectionState().hashCode());
        hashCode = prime * hashCode + ((getSessionId() == null) ? 0 : getSessionId().hashCode());
        hashCode = prime * hashCode + ((getInstanceId() == null) ? 0 : getInstanceId().hashCode());
        hashCode = prime * hashCode + ((getPoolId() == null) ? 0 : getPoolId().hashCode());
        hashCode = prime * hashCode + ((getExpirationTime() == null) ? 0 : getExpirationTime().hashCode());
        hashCode = prime * hashCode + ((getNetworkAccessConfiguration() == null) ? 0 : getNetworkAccessConfiguration().hashCode());
        hashCode = prime * hashCode + ((getStartTime() == null) ? 0 : getStartTime().hashCode());
        hashCode = prime * hashCode + ((getUserId() == null) ? 0 : getUserId().hashCode());
        return hashCode;
    }

    @Override
    public WorkspacesPoolSession clone() {
        try {
            return (WorkspacesPoolSession) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.workspaces.model.transform.WorkspacesPoolSessionMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
