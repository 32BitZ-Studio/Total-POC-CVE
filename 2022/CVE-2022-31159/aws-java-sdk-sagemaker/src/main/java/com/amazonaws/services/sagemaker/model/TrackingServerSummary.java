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
package com.amazonaws.services.sagemaker.model;

import java.io.Serializable;
import javax.annotation.Generated;
import com.amazonaws.protocol.StructuredPojo;
import com.amazonaws.protocol.ProtocolMarshaller;

/**
 * <p>
 * The summary of the tracking server to list.
 * </p>
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/sagemaker-2017-07-24/TrackingServerSummary" target="_top">AWS
 *      API Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class TrackingServerSummary implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * The ARN of a listed tracking server.
     * </p>
     */
    private String trackingServerArn;
    /**
     * <p>
     * The name of a listed tracking server.
     * </p>
     */
    private String trackingServerName;
    /**
     * <p>
     * The creation time of a listed tracking server.
     * </p>
     */
    private java.util.Date creationTime;
    /**
     * <p>
     * The last modified time of a listed tracking server.
     * </p>
     */
    private java.util.Date lastModifiedTime;
    /**
     * <p>
     * The creation status of a listed tracking server.
     * </p>
     */
    private String trackingServerStatus;
    /**
     * <p>
     * The activity status of a listed tracking server.
     * </p>
     */
    private String isActive;
    /**
     * <p>
     * The MLflow version used for a listed tracking server.
     * </p>
     */
    private String mlflowVersion;

    /**
     * <p>
     * The ARN of a listed tracking server.
     * </p>
     * 
     * @param trackingServerArn
     *        The ARN of a listed tracking server.
     */

    public void setTrackingServerArn(String trackingServerArn) {
        this.trackingServerArn = trackingServerArn;
    }

    /**
     * <p>
     * The ARN of a listed tracking server.
     * </p>
     * 
     * @return The ARN of a listed tracking server.
     */

    public String getTrackingServerArn() {
        return this.trackingServerArn;
    }

    /**
     * <p>
     * The ARN of a listed tracking server.
     * </p>
     * 
     * @param trackingServerArn
     *        The ARN of a listed tracking server.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public TrackingServerSummary withTrackingServerArn(String trackingServerArn) {
        setTrackingServerArn(trackingServerArn);
        return this;
    }

    /**
     * <p>
     * The name of a listed tracking server.
     * </p>
     * 
     * @param trackingServerName
     *        The name of a listed tracking server.
     */

    public void setTrackingServerName(String trackingServerName) {
        this.trackingServerName = trackingServerName;
    }

    /**
     * <p>
     * The name of a listed tracking server.
     * </p>
     * 
     * @return The name of a listed tracking server.
     */

    public String getTrackingServerName() {
        return this.trackingServerName;
    }

    /**
     * <p>
     * The name of a listed tracking server.
     * </p>
     * 
     * @param trackingServerName
     *        The name of a listed tracking server.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public TrackingServerSummary withTrackingServerName(String trackingServerName) {
        setTrackingServerName(trackingServerName);
        return this;
    }

    /**
     * <p>
     * The creation time of a listed tracking server.
     * </p>
     * 
     * @param creationTime
     *        The creation time of a listed tracking server.
     */

    public void setCreationTime(java.util.Date creationTime) {
        this.creationTime = creationTime;
    }

    /**
     * <p>
     * The creation time of a listed tracking server.
     * </p>
     * 
     * @return The creation time of a listed tracking server.
     */

    public java.util.Date getCreationTime() {
        return this.creationTime;
    }

    /**
     * <p>
     * The creation time of a listed tracking server.
     * </p>
     * 
     * @param creationTime
     *        The creation time of a listed tracking server.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public TrackingServerSummary withCreationTime(java.util.Date creationTime) {
        setCreationTime(creationTime);
        return this;
    }

    /**
     * <p>
     * The last modified time of a listed tracking server.
     * </p>
     * 
     * @param lastModifiedTime
     *        The last modified time of a listed tracking server.
     */

    public void setLastModifiedTime(java.util.Date lastModifiedTime) {
        this.lastModifiedTime = lastModifiedTime;
    }

    /**
     * <p>
     * The last modified time of a listed tracking server.
     * </p>
     * 
     * @return The last modified time of a listed tracking server.
     */

    public java.util.Date getLastModifiedTime() {
        return this.lastModifiedTime;
    }

    /**
     * <p>
     * The last modified time of a listed tracking server.
     * </p>
     * 
     * @param lastModifiedTime
     *        The last modified time of a listed tracking server.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public TrackingServerSummary withLastModifiedTime(java.util.Date lastModifiedTime) {
        setLastModifiedTime(lastModifiedTime);
        return this;
    }

    /**
     * <p>
     * The creation status of a listed tracking server.
     * </p>
     * 
     * @param trackingServerStatus
     *        The creation status of a listed tracking server.
     * @see TrackingServerStatus
     */

    public void setTrackingServerStatus(String trackingServerStatus) {
        this.trackingServerStatus = trackingServerStatus;
    }

    /**
     * <p>
     * The creation status of a listed tracking server.
     * </p>
     * 
     * @return The creation status of a listed tracking server.
     * @see TrackingServerStatus
     */

    public String getTrackingServerStatus() {
        return this.trackingServerStatus;
    }

    /**
     * <p>
     * The creation status of a listed tracking server.
     * </p>
     * 
     * @param trackingServerStatus
     *        The creation status of a listed tracking server.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see TrackingServerStatus
     */

    public TrackingServerSummary withTrackingServerStatus(String trackingServerStatus) {
        setTrackingServerStatus(trackingServerStatus);
        return this;
    }

    /**
     * <p>
     * The creation status of a listed tracking server.
     * </p>
     * 
     * @param trackingServerStatus
     *        The creation status of a listed tracking server.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see TrackingServerStatus
     */

    public TrackingServerSummary withTrackingServerStatus(TrackingServerStatus trackingServerStatus) {
        this.trackingServerStatus = trackingServerStatus.toString();
        return this;
    }

    /**
     * <p>
     * The activity status of a listed tracking server.
     * </p>
     * 
     * @param isActive
     *        The activity status of a listed tracking server.
     * @see IsTrackingServerActive
     */

    public void setIsActive(String isActive) {
        this.isActive = isActive;
    }

    /**
     * <p>
     * The activity status of a listed tracking server.
     * </p>
     * 
     * @return The activity status of a listed tracking server.
     * @see IsTrackingServerActive
     */

    public String getIsActive() {
        return this.isActive;
    }

    /**
     * <p>
     * The activity status of a listed tracking server.
     * </p>
     * 
     * @param isActive
     *        The activity status of a listed tracking server.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see IsTrackingServerActive
     */

    public TrackingServerSummary withIsActive(String isActive) {
        setIsActive(isActive);
        return this;
    }

    /**
     * <p>
     * The activity status of a listed tracking server.
     * </p>
     * 
     * @param isActive
     *        The activity status of a listed tracking server.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see IsTrackingServerActive
     */

    public TrackingServerSummary withIsActive(IsTrackingServerActive isActive) {
        this.isActive = isActive.toString();
        return this;
    }

    /**
     * <p>
     * The MLflow version used for a listed tracking server.
     * </p>
     * 
     * @param mlflowVersion
     *        The MLflow version used for a listed tracking server.
     */

    public void setMlflowVersion(String mlflowVersion) {
        this.mlflowVersion = mlflowVersion;
    }

    /**
     * <p>
     * The MLflow version used for a listed tracking server.
     * </p>
     * 
     * @return The MLflow version used for a listed tracking server.
     */

    public String getMlflowVersion() {
        return this.mlflowVersion;
    }

    /**
     * <p>
     * The MLflow version used for a listed tracking server.
     * </p>
     * 
     * @param mlflowVersion
     *        The MLflow version used for a listed tracking server.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public TrackingServerSummary withMlflowVersion(String mlflowVersion) {
        setMlflowVersion(mlflowVersion);
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
        if (getTrackingServerArn() != null)
            sb.append("TrackingServerArn: ").append(getTrackingServerArn()).append(",");
        if (getTrackingServerName() != null)
            sb.append("TrackingServerName: ").append(getTrackingServerName()).append(",");
        if (getCreationTime() != null)
            sb.append("CreationTime: ").append(getCreationTime()).append(",");
        if (getLastModifiedTime() != null)
            sb.append("LastModifiedTime: ").append(getLastModifiedTime()).append(",");
        if (getTrackingServerStatus() != null)
            sb.append("TrackingServerStatus: ").append(getTrackingServerStatus()).append(",");
        if (getIsActive() != null)
            sb.append("IsActive: ").append(getIsActive()).append(",");
        if (getMlflowVersion() != null)
            sb.append("MlflowVersion: ").append(getMlflowVersion());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof TrackingServerSummary == false)
            return false;
        TrackingServerSummary other = (TrackingServerSummary) obj;
        if (other.getTrackingServerArn() == null ^ this.getTrackingServerArn() == null)
            return false;
        if (other.getTrackingServerArn() != null && other.getTrackingServerArn().equals(this.getTrackingServerArn()) == false)
            return false;
        if (other.getTrackingServerName() == null ^ this.getTrackingServerName() == null)
            return false;
        if (other.getTrackingServerName() != null && other.getTrackingServerName().equals(this.getTrackingServerName()) == false)
            return false;
        if (other.getCreationTime() == null ^ this.getCreationTime() == null)
            return false;
        if (other.getCreationTime() != null && other.getCreationTime().equals(this.getCreationTime()) == false)
            return false;
        if (other.getLastModifiedTime() == null ^ this.getLastModifiedTime() == null)
            return false;
        if (other.getLastModifiedTime() != null && other.getLastModifiedTime().equals(this.getLastModifiedTime()) == false)
            return false;
        if (other.getTrackingServerStatus() == null ^ this.getTrackingServerStatus() == null)
            return false;
        if (other.getTrackingServerStatus() != null && other.getTrackingServerStatus().equals(this.getTrackingServerStatus()) == false)
            return false;
        if (other.getIsActive() == null ^ this.getIsActive() == null)
            return false;
        if (other.getIsActive() != null && other.getIsActive().equals(this.getIsActive()) == false)
            return false;
        if (other.getMlflowVersion() == null ^ this.getMlflowVersion() == null)
            return false;
        if (other.getMlflowVersion() != null && other.getMlflowVersion().equals(this.getMlflowVersion()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getTrackingServerArn() == null) ? 0 : getTrackingServerArn().hashCode());
        hashCode = prime * hashCode + ((getTrackingServerName() == null) ? 0 : getTrackingServerName().hashCode());
        hashCode = prime * hashCode + ((getCreationTime() == null) ? 0 : getCreationTime().hashCode());
        hashCode = prime * hashCode + ((getLastModifiedTime() == null) ? 0 : getLastModifiedTime().hashCode());
        hashCode = prime * hashCode + ((getTrackingServerStatus() == null) ? 0 : getTrackingServerStatus().hashCode());
        hashCode = prime * hashCode + ((getIsActive() == null) ? 0 : getIsActive().hashCode());
        hashCode = prime * hashCode + ((getMlflowVersion() == null) ? 0 : getMlflowVersion().hashCode());
        return hashCode;
    }

    @Override
    public TrackingServerSummary clone() {
        try {
            return (TrackingServerSummary) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.sagemaker.model.transform.TrackingServerSummaryMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
