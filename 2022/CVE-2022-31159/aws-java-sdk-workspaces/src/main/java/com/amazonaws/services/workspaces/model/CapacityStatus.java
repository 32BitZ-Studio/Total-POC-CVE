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
 * Describes the capacity status for a pool of WorkSpaces.
 * </p>
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/workspaces-2015-04-08/CapacityStatus" target="_top">AWS API
 *      Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class CapacityStatus implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * The number of user sessions currently available for streaming from your pool.
     * </p>
     * <p>
     * AvailableUserSessions = ActualUserSessions - ActiveUserSessions
     * </p>
     */
    private Integer availableUserSessions;
    /**
     * <p>
     * The total number of sessions slots that are either running or pending. This represents the total number of
     * concurrent streaming sessions your pool can support in a steady state.
     * </p>
     */
    private Integer desiredUserSessions;
    /**
     * <p>
     * The total number of user sessions that are available for streaming or are currently streaming in your pool.
     * </p>
     * <p>
     * ActualUserSessions = AvailableUserSessions + ActiveUserSessions
     * </p>
     */
    private Integer actualUserSessions;
    /**
     * <p>
     * The number of user sessions currently being used for your pool.
     * </p>
     */
    private Integer activeUserSessions;

    /**
     * <p>
     * The number of user sessions currently available for streaming from your pool.
     * </p>
     * <p>
     * AvailableUserSessions = ActualUserSessions - ActiveUserSessions
     * </p>
     * 
     * @param availableUserSessions
     *        The number of user sessions currently available for streaming from your pool.</p>
     *        <p>
     *        AvailableUserSessions = ActualUserSessions - ActiveUserSessions
     */

    public void setAvailableUserSessions(Integer availableUserSessions) {
        this.availableUserSessions = availableUserSessions;
    }

    /**
     * <p>
     * The number of user sessions currently available for streaming from your pool.
     * </p>
     * <p>
     * AvailableUserSessions = ActualUserSessions - ActiveUserSessions
     * </p>
     * 
     * @return The number of user sessions currently available for streaming from your pool.</p>
     *         <p>
     *         AvailableUserSessions = ActualUserSessions - ActiveUserSessions
     */

    public Integer getAvailableUserSessions() {
        return this.availableUserSessions;
    }

    /**
     * <p>
     * The number of user sessions currently available for streaming from your pool.
     * </p>
     * <p>
     * AvailableUserSessions = ActualUserSessions - ActiveUserSessions
     * </p>
     * 
     * @param availableUserSessions
     *        The number of user sessions currently available for streaming from your pool.</p>
     *        <p>
     *        AvailableUserSessions = ActualUserSessions - ActiveUserSessions
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public CapacityStatus withAvailableUserSessions(Integer availableUserSessions) {
        setAvailableUserSessions(availableUserSessions);
        return this;
    }

    /**
     * <p>
     * The total number of sessions slots that are either running or pending. This represents the total number of
     * concurrent streaming sessions your pool can support in a steady state.
     * </p>
     * 
     * @param desiredUserSessions
     *        The total number of sessions slots that are either running or pending. This represents the total number of
     *        concurrent streaming sessions your pool can support in a steady state.
     */

    public void setDesiredUserSessions(Integer desiredUserSessions) {
        this.desiredUserSessions = desiredUserSessions;
    }

    /**
     * <p>
     * The total number of sessions slots that are either running or pending. This represents the total number of
     * concurrent streaming sessions your pool can support in a steady state.
     * </p>
     * 
     * @return The total number of sessions slots that are either running or pending. This represents the total number
     *         of concurrent streaming sessions your pool can support in a steady state.
     */

    public Integer getDesiredUserSessions() {
        return this.desiredUserSessions;
    }

    /**
     * <p>
     * The total number of sessions slots that are either running or pending. This represents the total number of
     * concurrent streaming sessions your pool can support in a steady state.
     * </p>
     * 
     * @param desiredUserSessions
     *        The total number of sessions slots that are either running or pending. This represents the total number of
     *        concurrent streaming sessions your pool can support in a steady state.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public CapacityStatus withDesiredUserSessions(Integer desiredUserSessions) {
        setDesiredUserSessions(desiredUserSessions);
        return this;
    }

    /**
     * <p>
     * The total number of user sessions that are available for streaming or are currently streaming in your pool.
     * </p>
     * <p>
     * ActualUserSessions = AvailableUserSessions + ActiveUserSessions
     * </p>
     * 
     * @param actualUserSessions
     *        The total number of user sessions that are available for streaming or are currently streaming in your
     *        pool.</p>
     *        <p>
     *        ActualUserSessions = AvailableUserSessions + ActiveUserSessions
     */

    public void setActualUserSessions(Integer actualUserSessions) {
        this.actualUserSessions = actualUserSessions;
    }

    /**
     * <p>
     * The total number of user sessions that are available for streaming or are currently streaming in your pool.
     * </p>
     * <p>
     * ActualUserSessions = AvailableUserSessions + ActiveUserSessions
     * </p>
     * 
     * @return The total number of user sessions that are available for streaming or are currently streaming in your
     *         pool.</p>
     *         <p>
     *         ActualUserSessions = AvailableUserSessions + ActiveUserSessions
     */

    public Integer getActualUserSessions() {
        return this.actualUserSessions;
    }

    /**
     * <p>
     * The total number of user sessions that are available for streaming or are currently streaming in your pool.
     * </p>
     * <p>
     * ActualUserSessions = AvailableUserSessions + ActiveUserSessions
     * </p>
     * 
     * @param actualUserSessions
     *        The total number of user sessions that are available for streaming or are currently streaming in your
     *        pool.</p>
     *        <p>
     *        ActualUserSessions = AvailableUserSessions + ActiveUserSessions
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public CapacityStatus withActualUserSessions(Integer actualUserSessions) {
        setActualUserSessions(actualUserSessions);
        return this;
    }

    /**
     * <p>
     * The number of user sessions currently being used for your pool.
     * </p>
     * 
     * @param activeUserSessions
     *        The number of user sessions currently being used for your pool.
     */

    public void setActiveUserSessions(Integer activeUserSessions) {
        this.activeUserSessions = activeUserSessions;
    }

    /**
     * <p>
     * The number of user sessions currently being used for your pool.
     * </p>
     * 
     * @return The number of user sessions currently being used for your pool.
     */

    public Integer getActiveUserSessions() {
        return this.activeUserSessions;
    }

    /**
     * <p>
     * The number of user sessions currently being used for your pool.
     * </p>
     * 
     * @param activeUserSessions
     *        The number of user sessions currently being used for your pool.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public CapacityStatus withActiveUserSessions(Integer activeUserSessions) {
        setActiveUserSessions(activeUserSessions);
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
        if (getAvailableUserSessions() != null)
            sb.append("AvailableUserSessions: ").append(getAvailableUserSessions()).append(",");
        if (getDesiredUserSessions() != null)
            sb.append("DesiredUserSessions: ").append(getDesiredUserSessions()).append(",");
        if (getActualUserSessions() != null)
            sb.append("ActualUserSessions: ").append(getActualUserSessions()).append(",");
        if (getActiveUserSessions() != null)
            sb.append("ActiveUserSessions: ").append(getActiveUserSessions());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof CapacityStatus == false)
            return false;
        CapacityStatus other = (CapacityStatus) obj;
        if (other.getAvailableUserSessions() == null ^ this.getAvailableUserSessions() == null)
            return false;
        if (other.getAvailableUserSessions() != null && other.getAvailableUserSessions().equals(this.getAvailableUserSessions()) == false)
            return false;
        if (other.getDesiredUserSessions() == null ^ this.getDesiredUserSessions() == null)
            return false;
        if (other.getDesiredUserSessions() != null && other.getDesiredUserSessions().equals(this.getDesiredUserSessions()) == false)
            return false;
        if (other.getActualUserSessions() == null ^ this.getActualUserSessions() == null)
            return false;
        if (other.getActualUserSessions() != null && other.getActualUserSessions().equals(this.getActualUserSessions()) == false)
            return false;
        if (other.getActiveUserSessions() == null ^ this.getActiveUserSessions() == null)
            return false;
        if (other.getActiveUserSessions() != null && other.getActiveUserSessions().equals(this.getActiveUserSessions()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getAvailableUserSessions() == null) ? 0 : getAvailableUserSessions().hashCode());
        hashCode = prime * hashCode + ((getDesiredUserSessions() == null) ? 0 : getDesiredUserSessions().hashCode());
        hashCode = prime * hashCode + ((getActualUserSessions() == null) ? 0 : getActualUserSessions().hashCode());
        hashCode = prime * hashCode + ((getActiveUserSessions() == null) ? 0 : getActiveUserSessions().hashCode());
        return hashCode;
    }

    @Override
    public CapacityStatus clone() {
        try {
            return (CapacityStatus) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.workspaces.model.transform.CapacityStatusMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
