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

/**
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/sagemaker-2017-07-24/DescribeMlflowTrackingServer"
 *      target="_top">AWS API Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class DescribeMlflowTrackingServerResult extends com.amazonaws.AmazonWebServiceResult<com.amazonaws.ResponseMetadata> implements Serializable, Cloneable {

    /**
     * <p>
     * The ARN of the described tracking server.
     * </p>
     */
    private String trackingServerArn;
    /**
     * <p>
     * The name of the described tracking server.
     * </p>
     */
    private String trackingServerName;
    /**
     * <p>
     * The S3 URI of the general purpose bucket used as the MLflow Tracking Server artifact store.
     * </p>
     */
    private String artifactStoreUri;
    /**
     * <p>
     * The size of the described tracking server.
     * </p>
     */
    private String trackingServerSize;
    /**
     * <p>
     * The MLflow version used for the described tracking server.
     * </p>
     */
    private String mlflowVersion;
    /**
     * <p>
     * The Amazon Resource Name (ARN) for an IAM role in your account that the described MLflow Tracking Server uses to
     * access the artifact store in Amazon S3.
     * </p>
     */
    private String roleArn;
    /**
     * <p>
     * The current creation status of the described MLflow Tracking Server.
     * </p>
     */
    private String trackingServerStatus;
    /**
     * <p>
     * Whether the described MLflow Tracking Server is currently active.
     * </p>
     */
    private String isActive;
    /**
     * <p>
     * The URL to connect to the MLflow user interface for the described tracking server.
     * </p>
     */
    private String trackingServerUrl;
    /**
     * <p>
     * The day and time of the week when weekly maintenance occurs on the described tracking server.
     * </p>
     */
    private String weeklyMaintenanceWindowStart;
    /**
     * <p>
     * Whether automatic registration of new MLflow models to the SageMaker Model Registry is enabled.
     * </p>
     */
    private Boolean automaticModelRegistration;
    /**
     * <p>
     * The timestamp of when the described MLflow Tracking Server was created.
     * </p>
     */
    private java.util.Date creationTime;

    private UserContext createdBy;
    /**
     * <p>
     * The timestamp of when the described MLflow Tracking Server was last modified.
     * </p>
     */
    private java.util.Date lastModifiedTime;

    private UserContext lastModifiedBy;

    /**
     * <p>
     * The ARN of the described tracking server.
     * </p>
     * 
     * @param trackingServerArn
     *        The ARN of the described tracking server.
     */

    public void setTrackingServerArn(String trackingServerArn) {
        this.trackingServerArn = trackingServerArn;
    }

    /**
     * <p>
     * The ARN of the described tracking server.
     * </p>
     * 
     * @return The ARN of the described tracking server.
     */

    public String getTrackingServerArn() {
        return this.trackingServerArn;
    }

    /**
     * <p>
     * The ARN of the described tracking server.
     * </p>
     * 
     * @param trackingServerArn
     *        The ARN of the described tracking server.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public DescribeMlflowTrackingServerResult withTrackingServerArn(String trackingServerArn) {
        setTrackingServerArn(trackingServerArn);
        return this;
    }

    /**
     * <p>
     * The name of the described tracking server.
     * </p>
     * 
     * @param trackingServerName
     *        The name of the described tracking server.
     */

    public void setTrackingServerName(String trackingServerName) {
        this.trackingServerName = trackingServerName;
    }

    /**
     * <p>
     * The name of the described tracking server.
     * </p>
     * 
     * @return The name of the described tracking server.
     */

    public String getTrackingServerName() {
        return this.trackingServerName;
    }

    /**
     * <p>
     * The name of the described tracking server.
     * </p>
     * 
     * @param trackingServerName
     *        The name of the described tracking server.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public DescribeMlflowTrackingServerResult withTrackingServerName(String trackingServerName) {
        setTrackingServerName(trackingServerName);
        return this;
    }

    /**
     * <p>
     * The S3 URI of the general purpose bucket used as the MLflow Tracking Server artifact store.
     * </p>
     * 
     * @param artifactStoreUri
     *        The S3 URI of the general purpose bucket used as the MLflow Tracking Server artifact store.
     */

    public void setArtifactStoreUri(String artifactStoreUri) {
        this.artifactStoreUri = artifactStoreUri;
    }

    /**
     * <p>
     * The S3 URI of the general purpose bucket used as the MLflow Tracking Server artifact store.
     * </p>
     * 
     * @return The S3 URI of the general purpose bucket used as the MLflow Tracking Server artifact store.
     */

    public String getArtifactStoreUri() {
        return this.artifactStoreUri;
    }

    /**
     * <p>
     * The S3 URI of the general purpose bucket used as the MLflow Tracking Server artifact store.
     * </p>
     * 
     * @param artifactStoreUri
     *        The S3 URI of the general purpose bucket used as the MLflow Tracking Server artifact store.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public DescribeMlflowTrackingServerResult withArtifactStoreUri(String artifactStoreUri) {
        setArtifactStoreUri(artifactStoreUri);
        return this;
    }

    /**
     * <p>
     * The size of the described tracking server.
     * </p>
     * 
     * @param trackingServerSize
     *        The size of the described tracking server.
     * @see TrackingServerSize
     */

    public void setTrackingServerSize(String trackingServerSize) {
        this.trackingServerSize = trackingServerSize;
    }

    /**
     * <p>
     * The size of the described tracking server.
     * </p>
     * 
     * @return The size of the described tracking server.
     * @see TrackingServerSize
     */

    public String getTrackingServerSize() {
        return this.trackingServerSize;
    }

    /**
     * <p>
     * The size of the described tracking server.
     * </p>
     * 
     * @param trackingServerSize
     *        The size of the described tracking server.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see TrackingServerSize
     */

    public DescribeMlflowTrackingServerResult withTrackingServerSize(String trackingServerSize) {
        setTrackingServerSize(trackingServerSize);
        return this;
    }

    /**
     * <p>
     * The size of the described tracking server.
     * </p>
     * 
     * @param trackingServerSize
     *        The size of the described tracking server.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see TrackingServerSize
     */

    public DescribeMlflowTrackingServerResult withTrackingServerSize(TrackingServerSize trackingServerSize) {
        this.trackingServerSize = trackingServerSize.toString();
        return this;
    }

    /**
     * <p>
     * The MLflow version used for the described tracking server.
     * </p>
     * 
     * @param mlflowVersion
     *        The MLflow version used for the described tracking server.
     */

    public void setMlflowVersion(String mlflowVersion) {
        this.mlflowVersion = mlflowVersion;
    }

    /**
     * <p>
     * The MLflow version used for the described tracking server.
     * </p>
     * 
     * @return The MLflow version used for the described tracking server.
     */

    public String getMlflowVersion() {
        return this.mlflowVersion;
    }

    /**
     * <p>
     * The MLflow version used for the described tracking server.
     * </p>
     * 
     * @param mlflowVersion
     *        The MLflow version used for the described tracking server.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public DescribeMlflowTrackingServerResult withMlflowVersion(String mlflowVersion) {
        setMlflowVersion(mlflowVersion);
        return this;
    }

    /**
     * <p>
     * The Amazon Resource Name (ARN) for an IAM role in your account that the described MLflow Tracking Server uses to
     * access the artifact store in Amazon S3.
     * </p>
     * 
     * @param roleArn
     *        The Amazon Resource Name (ARN) for an IAM role in your account that the described MLflow Tracking Server
     *        uses to access the artifact store in Amazon S3.
     */

    public void setRoleArn(String roleArn) {
        this.roleArn = roleArn;
    }

    /**
     * <p>
     * The Amazon Resource Name (ARN) for an IAM role in your account that the described MLflow Tracking Server uses to
     * access the artifact store in Amazon S3.
     * </p>
     * 
     * @return The Amazon Resource Name (ARN) for an IAM role in your account that the described MLflow Tracking Server
     *         uses to access the artifact store in Amazon S3.
     */

    public String getRoleArn() {
        return this.roleArn;
    }

    /**
     * <p>
     * The Amazon Resource Name (ARN) for an IAM role in your account that the described MLflow Tracking Server uses to
     * access the artifact store in Amazon S3.
     * </p>
     * 
     * @param roleArn
     *        The Amazon Resource Name (ARN) for an IAM role in your account that the described MLflow Tracking Server
     *        uses to access the artifact store in Amazon S3.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public DescribeMlflowTrackingServerResult withRoleArn(String roleArn) {
        setRoleArn(roleArn);
        return this;
    }

    /**
     * <p>
     * The current creation status of the described MLflow Tracking Server.
     * </p>
     * 
     * @param trackingServerStatus
     *        The current creation status of the described MLflow Tracking Server.
     * @see TrackingServerStatus
     */

    public void setTrackingServerStatus(String trackingServerStatus) {
        this.trackingServerStatus = trackingServerStatus;
    }

    /**
     * <p>
     * The current creation status of the described MLflow Tracking Server.
     * </p>
     * 
     * @return The current creation status of the described MLflow Tracking Server.
     * @see TrackingServerStatus
     */

    public String getTrackingServerStatus() {
        return this.trackingServerStatus;
    }

    /**
     * <p>
     * The current creation status of the described MLflow Tracking Server.
     * </p>
     * 
     * @param trackingServerStatus
     *        The current creation status of the described MLflow Tracking Server.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see TrackingServerStatus
     */

    public DescribeMlflowTrackingServerResult withTrackingServerStatus(String trackingServerStatus) {
        setTrackingServerStatus(trackingServerStatus);
        return this;
    }

    /**
     * <p>
     * The current creation status of the described MLflow Tracking Server.
     * </p>
     * 
     * @param trackingServerStatus
     *        The current creation status of the described MLflow Tracking Server.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see TrackingServerStatus
     */

    public DescribeMlflowTrackingServerResult withTrackingServerStatus(TrackingServerStatus trackingServerStatus) {
        this.trackingServerStatus = trackingServerStatus.toString();
        return this;
    }

    /**
     * <p>
     * Whether the described MLflow Tracking Server is currently active.
     * </p>
     * 
     * @param isActive
     *        Whether the described MLflow Tracking Server is currently active.
     * @see IsTrackingServerActive
     */

    public void setIsActive(String isActive) {
        this.isActive = isActive;
    }

    /**
     * <p>
     * Whether the described MLflow Tracking Server is currently active.
     * </p>
     * 
     * @return Whether the described MLflow Tracking Server is currently active.
     * @see IsTrackingServerActive
     */

    public String getIsActive() {
        return this.isActive;
    }

    /**
     * <p>
     * Whether the described MLflow Tracking Server is currently active.
     * </p>
     * 
     * @param isActive
     *        Whether the described MLflow Tracking Server is currently active.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see IsTrackingServerActive
     */

    public DescribeMlflowTrackingServerResult withIsActive(String isActive) {
        setIsActive(isActive);
        return this;
    }

    /**
     * <p>
     * Whether the described MLflow Tracking Server is currently active.
     * </p>
     * 
     * @param isActive
     *        Whether the described MLflow Tracking Server is currently active.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see IsTrackingServerActive
     */

    public DescribeMlflowTrackingServerResult withIsActive(IsTrackingServerActive isActive) {
        this.isActive = isActive.toString();
        return this;
    }

    /**
     * <p>
     * The URL to connect to the MLflow user interface for the described tracking server.
     * </p>
     * 
     * @param trackingServerUrl
     *        The URL to connect to the MLflow user interface for the described tracking server.
     */

    public void setTrackingServerUrl(String trackingServerUrl) {
        this.trackingServerUrl = trackingServerUrl;
    }

    /**
     * <p>
     * The URL to connect to the MLflow user interface for the described tracking server.
     * </p>
     * 
     * @return The URL to connect to the MLflow user interface for the described tracking server.
     */

    public String getTrackingServerUrl() {
        return this.trackingServerUrl;
    }

    /**
     * <p>
     * The URL to connect to the MLflow user interface for the described tracking server.
     * </p>
     * 
     * @param trackingServerUrl
     *        The URL to connect to the MLflow user interface for the described tracking server.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public DescribeMlflowTrackingServerResult withTrackingServerUrl(String trackingServerUrl) {
        setTrackingServerUrl(trackingServerUrl);
        return this;
    }

    /**
     * <p>
     * The day and time of the week when weekly maintenance occurs on the described tracking server.
     * </p>
     * 
     * @param weeklyMaintenanceWindowStart
     *        The day and time of the week when weekly maintenance occurs on the described tracking server.
     */

    public void setWeeklyMaintenanceWindowStart(String weeklyMaintenanceWindowStart) {
        this.weeklyMaintenanceWindowStart = weeklyMaintenanceWindowStart;
    }

    /**
     * <p>
     * The day and time of the week when weekly maintenance occurs on the described tracking server.
     * </p>
     * 
     * @return The day and time of the week when weekly maintenance occurs on the described tracking server.
     */

    public String getWeeklyMaintenanceWindowStart() {
        return this.weeklyMaintenanceWindowStart;
    }

    /**
     * <p>
     * The day and time of the week when weekly maintenance occurs on the described tracking server.
     * </p>
     * 
     * @param weeklyMaintenanceWindowStart
     *        The day and time of the week when weekly maintenance occurs on the described tracking server.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public DescribeMlflowTrackingServerResult withWeeklyMaintenanceWindowStart(String weeklyMaintenanceWindowStart) {
        setWeeklyMaintenanceWindowStart(weeklyMaintenanceWindowStart);
        return this;
    }

    /**
     * <p>
     * Whether automatic registration of new MLflow models to the SageMaker Model Registry is enabled.
     * </p>
     * 
     * @param automaticModelRegistration
     *        Whether automatic registration of new MLflow models to the SageMaker Model Registry is enabled.
     */

    public void setAutomaticModelRegistration(Boolean automaticModelRegistration) {
        this.automaticModelRegistration = automaticModelRegistration;
    }

    /**
     * <p>
     * Whether automatic registration of new MLflow models to the SageMaker Model Registry is enabled.
     * </p>
     * 
     * @return Whether automatic registration of new MLflow models to the SageMaker Model Registry is enabled.
     */

    public Boolean getAutomaticModelRegistration() {
        return this.automaticModelRegistration;
    }

    /**
     * <p>
     * Whether automatic registration of new MLflow models to the SageMaker Model Registry is enabled.
     * </p>
     * 
     * @param automaticModelRegistration
     *        Whether automatic registration of new MLflow models to the SageMaker Model Registry is enabled.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public DescribeMlflowTrackingServerResult withAutomaticModelRegistration(Boolean automaticModelRegistration) {
        setAutomaticModelRegistration(automaticModelRegistration);
        return this;
    }

    /**
     * <p>
     * Whether automatic registration of new MLflow models to the SageMaker Model Registry is enabled.
     * </p>
     * 
     * @return Whether automatic registration of new MLflow models to the SageMaker Model Registry is enabled.
     */

    public Boolean isAutomaticModelRegistration() {
        return this.automaticModelRegistration;
    }

    /**
     * <p>
     * The timestamp of when the described MLflow Tracking Server was created.
     * </p>
     * 
     * @param creationTime
     *        The timestamp of when the described MLflow Tracking Server was created.
     */

    public void setCreationTime(java.util.Date creationTime) {
        this.creationTime = creationTime;
    }

    /**
     * <p>
     * The timestamp of when the described MLflow Tracking Server was created.
     * </p>
     * 
     * @return The timestamp of when the described MLflow Tracking Server was created.
     */

    public java.util.Date getCreationTime() {
        return this.creationTime;
    }

    /**
     * <p>
     * The timestamp of when the described MLflow Tracking Server was created.
     * </p>
     * 
     * @param creationTime
     *        The timestamp of when the described MLflow Tracking Server was created.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public DescribeMlflowTrackingServerResult withCreationTime(java.util.Date creationTime) {
        setCreationTime(creationTime);
        return this;
    }

    /**
     * @param createdBy
     */

    public void setCreatedBy(UserContext createdBy) {
        this.createdBy = createdBy;
    }

    /**
     * @return
     */

    public UserContext getCreatedBy() {
        return this.createdBy;
    }

    /**
     * @param createdBy
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public DescribeMlflowTrackingServerResult withCreatedBy(UserContext createdBy) {
        setCreatedBy(createdBy);
        return this;
    }

    /**
     * <p>
     * The timestamp of when the described MLflow Tracking Server was last modified.
     * </p>
     * 
     * @param lastModifiedTime
     *        The timestamp of when the described MLflow Tracking Server was last modified.
     */

    public void setLastModifiedTime(java.util.Date lastModifiedTime) {
        this.lastModifiedTime = lastModifiedTime;
    }

    /**
     * <p>
     * The timestamp of when the described MLflow Tracking Server was last modified.
     * </p>
     * 
     * @return The timestamp of when the described MLflow Tracking Server was last modified.
     */

    public java.util.Date getLastModifiedTime() {
        return this.lastModifiedTime;
    }

    /**
     * <p>
     * The timestamp of when the described MLflow Tracking Server was last modified.
     * </p>
     * 
     * @param lastModifiedTime
     *        The timestamp of when the described MLflow Tracking Server was last modified.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public DescribeMlflowTrackingServerResult withLastModifiedTime(java.util.Date lastModifiedTime) {
        setLastModifiedTime(lastModifiedTime);
        return this;
    }

    /**
     * @param lastModifiedBy
     */

    public void setLastModifiedBy(UserContext lastModifiedBy) {
        this.lastModifiedBy = lastModifiedBy;
    }

    /**
     * @return
     */

    public UserContext getLastModifiedBy() {
        return this.lastModifiedBy;
    }

    /**
     * @param lastModifiedBy
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public DescribeMlflowTrackingServerResult withLastModifiedBy(UserContext lastModifiedBy) {
        setLastModifiedBy(lastModifiedBy);
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
        if (getArtifactStoreUri() != null)
            sb.append("ArtifactStoreUri: ").append(getArtifactStoreUri()).append(",");
        if (getTrackingServerSize() != null)
            sb.append("TrackingServerSize: ").append(getTrackingServerSize()).append(",");
        if (getMlflowVersion() != null)
            sb.append("MlflowVersion: ").append(getMlflowVersion()).append(",");
        if (getRoleArn() != null)
            sb.append("RoleArn: ").append(getRoleArn()).append(",");
        if (getTrackingServerStatus() != null)
            sb.append("TrackingServerStatus: ").append(getTrackingServerStatus()).append(",");
        if (getIsActive() != null)
            sb.append("IsActive: ").append(getIsActive()).append(",");
        if (getTrackingServerUrl() != null)
            sb.append("TrackingServerUrl: ").append(getTrackingServerUrl()).append(",");
        if (getWeeklyMaintenanceWindowStart() != null)
            sb.append("WeeklyMaintenanceWindowStart: ").append(getWeeklyMaintenanceWindowStart()).append(",");
        if (getAutomaticModelRegistration() != null)
            sb.append("AutomaticModelRegistration: ").append(getAutomaticModelRegistration()).append(",");
        if (getCreationTime() != null)
            sb.append("CreationTime: ").append(getCreationTime()).append(",");
        if (getCreatedBy() != null)
            sb.append("CreatedBy: ").append(getCreatedBy()).append(",");
        if (getLastModifiedTime() != null)
            sb.append("LastModifiedTime: ").append(getLastModifiedTime()).append(",");
        if (getLastModifiedBy() != null)
            sb.append("LastModifiedBy: ").append(getLastModifiedBy());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof DescribeMlflowTrackingServerResult == false)
            return false;
        DescribeMlflowTrackingServerResult other = (DescribeMlflowTrackingServerResult) obj;
        if (other.getTrackingServerArn() == null ^ this.getTrackingServerArn() == null)
            return false;
        if (other.getTrackingServerArn() != null && other.getTrackingServerArn().equals(this.getTrackingServerArn()) == false)
            return false;
        if (other.getTrackingServerName() == null ^ this.getTrackingServerName() == null)
            return false;
        if (other.getTrackingServerName() != null && other.getTrackingServerName().equals(this.getTrackingServerName()) == false)
            return false;
        if (other.getArtifactStoreUri() == null ^ this.getArtifactStoreUri() == null)
            return false;
        if (other.getArtifactStoreUri() != null && other.getArtifactStoreUri().equals(this.getArtifactStoreUri()) == false)
            return false;
        if (other.getTrackingServerSize() == null ^ this.getTrackingServerSize() == null)
            return false;
        if (other.getTrackingServerSize() != null && other.getTrackingServerSize().equals(this.getTrackingServerSize()) == false)
            return false;
        if (other.getMlflowVersion() == null ^ this.getMlflowVersion() == null)
            return false;
        if (other.getMlflowVersion() != null && other.getMlflowVersion().equals(this.getMlflowVersion()) == false)
            return false;
        if (other.getRoleArn() == null ^ this.getRoleArn() == null)
            return false;
        if (other.getRoleArn() != null && other.getRoleArn().equals(this.getRoleArn()) == false)
            return false;
        if (other.getTrackingServerStatus() == null ^ this.getTrackingServerStatus() == null)
            return false;
        if (other.getTrackingServerStatus() != null && other.getTrackingServerStatus().equals(this.getTrackingServerStatus()) == false)
            return false;
        if (other.getIsActive() == null ^ this.getIsActive() == null)
            return false;
        if (other.getIsActive() != null && other.getIsActive().equals(this.getIsActive()) == false)
            return false;
        if (other.getTrackingServerUrl() == null ^ this.getTrackingServerUrl() == null)
            return false;
        if (other.getTrackingServerUrl() != null && other.getTrackingServerUrl().equals(this.getTrackingServerUrl()) == false)
            return false;
        if (other.getWeeklyMaintenanceWindowStart() == null ^ this.getWeeklyMaintenanceWindowStart() == null)
            return false;
        if (other.getWeeklyMaintenanceWindowStart() != null && other.getWeeklyMaintenanceWindowStart().equals(this.getWeeklyMaintenanceWindowStart()) == false)
            return false;
        if (other.getAutomaticModelRegistration() == null ^ this.getAutomaticModelRegistration() == null)
            return false;
        if (other.getAutomaticModelRegistration() != null && other.getAutomaticModelRegistration().equals(this.getAutomaticModelRegistration()) == false)
            return false;
        if (other.getCreationTime() == null ^ this.getCreationTime() == null)
            return false;
        if (other.getCreationTime() != null && other.getCreationTime().equals(this.getCreationTime()) == false)
            return false;
        if (other.getCreatedBy() == null ^ this.getCreatedBy() == null)
            return false;
        if (other.getCreatedBy() != null && other.getCreatedBy().equals(this.getCreatedBy()) == false)
            return false;
        if (other.getLastModifiedTime() == null ^ this.getLastModifiedTime() == null)
            return false;
        if (other.getLastModifiedTime() != null && other.getLastModifiedTime().equals(this.getLastModifiedTime()) == false)
            return false;
        if (other.getLastModifiedBy() == null ^ this.getLastModifiedBy() == null)
            return false;
        if (other.getLastModifiedBy() != null && other.getLastModifiedBy().equals(this.getLastModifiedBy()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getTrackingServerArn() == null) ? 0 : getTrackingServerArn().hashCode());
        hashCode = prime * hashCode + ((getTrackingServerName() == null) ? 0 : getTrackingServerName().hashCode());
        hashCode = prime * hashCode + ((getArtifactStoreUri() == null) ? 0 : getArtifactStoreUri().hashCode());
        hashCode = prime * hashCode + ((getTrackingServerSize() == null) ? 0 : getTrackingServerSize().hashCode());
        hashCode = prime * hashCode + ((getMlflowVersion() == null) ? 0 : getMlflowVersion().hashCode());
        hashCode = prime * hashCode + ((getRoleArn() == null) ? 0 : getRoleArn().hashCode());
        hashCode = prime * hashCode + ((getTrackingServerStatus() == null) ? 0 : getTrackingServerStatus().hashCode());
        hashCode = prime * hashCode + ((getIsActive() == null) ? 0 : getIsActive().hashCode());
        hashCode = prime * hashCode + ((getTrackingServerUrl() == null) ? 0 : getTrackingServerUrl().hashCode());
        hashCode = prime * hashCode + ((getWeeklyMaintenanceWindowStart() == null) ? 0 : getWeeklyMaintenanceWindowStart().hashCode());
        hashCode = prime * hashCode + ((getAutomaticModelRegistration() == null) ? 0 : getAutomaticModelRegistration().hashCode());
        hashCode = prime * hashCode + ((getCreationTime() == null) ? 0 : getCreationTime().hashCode());
        hashCode = prime * hashCode + ((getCreatedBy() == null) ? 0 : getCreatedBy().hashCode());
        hashCode = prime * hashCode + ((getLastModifiedTime() == null) ? 0 : getLastModifiedTime().hashCode());
        hashCode = prime * hashCode + ((getLastModifiedBy() == null) ? 0 : getLastModifiedBy().hashCode());
        return hashCode;
    }

    @Override
    public DescribeMlflowTrackingServerResult clone() {
        try {
            return (DescribeMlflowTrackingServerResult) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

}
