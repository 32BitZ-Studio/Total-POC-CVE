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

import com.amazonaws.AmazonWebServiceRequest;

/**
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/sagemaker-2017-07-24/UpdateMlflowTrackingServer"
 *      target="_top">AWS API Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class UpdateMlflowTrackingServerRequest extends com.amazonaws.AmazonWebServiceRequest implements Serializable, Cloneable {

    /**
     * <p>
     * The name of the MLflow Tracking Server to update.
     * </p>
     */
    private String trackingServerName;
    /**
     * <p>
     * The new S3 URI for the general purpose bucket to use as the artifact store for the MLflow Tracking Server.
     * </p>
     */
    private String artifactStoreUri;
    /**
     * <p>
     * The new size for the MLflow Tracking Server.
     * </p>
     */
    private String trackingServerSize;
    /**
     * <p>
     * Whether to enable or disable automatic registration of new MLflow models to the SageMaker Model Registry. To
     * enable automatic model registration, set this value to <code>True</code>. To disable automatic model
     * registration, set this value to <code>False</code>. If not specified, <code>AutomaticModelRegistration</code>
     * defaults to <code>False</code>
     * </p>
     */
    private Boolean automaticModelRegistration;
    /**
     * <p>
     * The new weekly maintenance window start day and time to update. The maintenance window day and time should be in
     * Coordinated Universal Time (UTC) 24-hour standard time. For example: TUE:03:30.
     * </p>
     */
    private String weeklyMaintenanceWindowStart;

    /**
     * <p>
     * The name of the MLflow Tracking Server to update.
     * </p>
     * 
     * @param trackingServerName
     *        The name of the MLflow Tracking Server to update.
     */

    public void setTrackingServerName(String trackingServerName) {
        this.trackingServerName = trackingServerName;
    }

    /**
     * <p>
     * The name of the MLflow Tracking Server to update.
     * </p>
     * 
     * @return The name of the MLflow Tracking Server to update.
     */

    public String getTrackingServerName() {
        return this.trackingServerName;
    }

    /**
     * <p>
     * The name of the MLflow Tracking Server to update.
     * </p>
     * 
     * @param trackingServerName
     *        The name of the MLflow Tracking Server to update.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public UpdateMlflowTrackingServerRequest withTrackingServerName(String trackingServerName) {
        setTrackingServerName(trackingServerName);
        return this;
    }

    /**
     * <p>
     * The new S3 URI for the general purpose bucket to use as the artifact store for the MLflow Tracking Server.
     * </p>
     * 
     * @param artifactStoreUri
     *        The new S3 URI for the general purpose bucket to use as the artifact store for the MLflow Tracking Server.
     */

    public void setArtifactStoreUri(String artifactStoreUri) {
        this.artifactStoreUri = artifactStoreUri;
    }

    /**
     * <p>
     * The new S3 URI for the general purpose bucket to use as the artifact store for the MLflow Tracking Server.
     * </p>
     * 
     * @return The new S3 URI for the general purpose bucket to use as the artifact store for the MLflow Tracking
     *         Server.
     */

    public String getArtifactStoreUri() {
        return this.artifactStoreUri;
    }

    /**
     * <p>
     * The new S3 URI for the general purpose bucket to use as the artifact store for the MLflow Tracking Server.
     * </p>
     * 
     * @param artifactStoreUri
     *        The new S3 URI for the general purpose bucket to use as the artifact store for the MLflow Tracking Server.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public UpdateMlflowTrackingServerRequest withArtifactStoreUri(String artifactStoreUri) {
        setArtifactStoreUri(artifactStoreUri);
        return this;
    }

    /**
     * <p>
     * The new size for the MLflow Tracking Server.
     * </p>
     * 
     * @param trackingServerSize
     *        The new size for the MLflow Tracking Server.
     * @see TrackingServerSize
     */

    public void setTrackingServerSize(String trackingServerSize) {
        this.trackingServerSize = trackingServerSize;
    }

    /**
     * <p>
     * The new size for the MLflow Tracking Server.
     * </p>
     * 
     * @return The new size for the MLflow Tracking Server.
     * @see TrackingServerSize
     */

    public String getTrackingServerSize() {
        return this.trackingServerSize;
    }

    /**
     * <p>
     * The new size for the MLflow Tracking Server.
     * </p>
     * 
     * @param trackingServerSize
     *        The new size for the MLflow Tracking Server.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see TrackingServerSize
     */

    public UpdateMlflowTrackingServerRequest withTrackingServerSize(String trackingServerSize) {
        setTrackingServerSize(trackingServerSize);
        return this;
    }

    /**
     * <p>
     * The new size for the MLflow Tracking Server.
     * </p>
     * 
     * @param trackingServerSize
     *        The new size for the MLflow Tracking Server.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see TrackingServerSize
     */

    public UpdateMlflowTrackingServerRequest withTrackingServerSize(TrackingServerSize trackingServerSize) {
        this.trackingServerSize = trackingServerSize.toString();
        return this;
    }

    /**
     * <p>
     * Whether to enable or disable automatic registration of new MLflow models to the SageMaker Model Registry. To
     * enable automatic model registration, set this value to <code>True</code>. To disable automatic model
     * registration, set this value to <code>False</code>. If not specified, <code>AutomaticModelRegistration</code>
     * defaults to <code>False</code>
     * </p>
     * 
     * @param automaticModelRegistration
     *        Whether to enable or disable automatic registration of new MLflow models to the SageMaker Model Registry.
     *        To enable automatic model registration, set this value to <code>True</code>. To disable automatic model
     *        registration, set this value to <code>False</code>. If not specified,
     *        <code>AutomaticModelRegistration</code> defaults to <code>False</code>
     */

    public void setAutomaticModelRegistration(Boolean automaticModelRegistration) {
        this.automaticModelRegistration = automaticModelRegistration;
    }

    /**
     * <p>
     * Whether to enable or disable automatic registration of new MLflow models to the SageMaker Model Registry. To
     * enable automatic model registration, set this value to <code>True</code>. To disable automatic model
     * registration, set this value to <code>False</code>. If not specified, <code>AutomaticModelRegistration</code>
     * defaults to <code>False</code>
     * </p>
     * 
     * @return Whether to enable or disable automatic registration of new MLflow models to the SageMaker Model Registry.
     *         To enable automatic model registration, set this value to <code>True</code>. To disable automatic model
     *         registration, set this value to <code>False</code>. If not specified,
     *         <code>AutomaticModelRegistration</code> defaults to <code>False</code>
     */

    public Boolean getAutomaticModelRegistration() {
        return this.automaticModelRegistration;
    }

    /**
     * <p>
     * Whether to enable or disable automatic registration of new MLflow models to the SageMaker Model Registry. To
     * enable automatic model registration, set this value to <code>True</code>. To disable automatic model
     * registration, set this value to <code>False</code>. If not specified, <code>AutomaticModelRegistration</code>
     * defaults to <code>False</code>
     * </p>
     * 
     * @param automaticModelRegistration
     *        Whether to enable or disable automatic registration of new MLflow models to the SageMaker Model Registry.
     *        To enable automatic model registration, set this value to <code>True</code>. To disable automatic model
     *        registration, set this value to <code>False</code>. If not specified,
     *        <code>AutomaticModelRegistration</code> defaults to <code>False</code>
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public UpdateMlflowTrackingServerRequest withAutomaticModelRegistration(Boolean automaticModelRegistration) {
        setAutomaticModelRegistration(automaticModelRegistration);
        return this;
    }

    /**
     * <p>
     * Whether to enable or disable automatic registration of new MLflow models to the SageMaker Model Registry. To
     * enable automatic model registration, set this value to <code>True</code>. To disable automatic model
     * registration, set this value to <code>False</code>. If not specified, <code>AutomaticModelRegistration</code>
     * defaults to <code>False</code>
     * </p>
     * 
     * @return Whether to enable or disable automatic registration of new MLflow models to the SageMaker Model Registry.
     *         To enable automatic model registration, set this value to <code>True</code>. To disable automatic model
     *         registration, set this value to <code>False</code>. If not specified,
     *         <code>AutomaticModelRegistration</code> defaults to <code>False</code>
     */

    public Boolean isAutomaticModelRegistration() {
        return this.automaticModelRegistration;
    }

    /**
     * <p>
     * The new weekly maintenance window start day and time to update. The maintenance window day and time should be in
     * Coordinated Universal Time (UTC) 24-hour standard time. For example: TUE:03:30.
     * </p>
     * 
     * @param weeklyMaintenanceWindowStart
     *        The new weekly maintenance window start day and time to update. The maintenance window day and time should
     *        be in Coordinated Universal Time (UTC) 24-hour standard time. For example: TUE:03:30.
     */

    public void setWeeklyMaintenanceWindowStart(String weeklyMaintenanceWindowStart) {
        this.weeklyMaintenanceWindowStart = weeklyMaintenanceWindowStart;
    }

    /**
     * <p>
     * The new weekly maintenance window start day and time to update. The maintenance window day and time should be in
     * Coordinated Universal Time (UTC) 24-hour standard time. For example: TUE:03:30.
     * </p>
     * 
     * @return The new weekly maintenance window start day and time to update. The maintenance window day and time
     *         should be in Coordinated Universal Time (UTC) 24-hour standard time. For example: TUE:03:30.
     */

    public String getWeeklyMaintenanceWindowStart() {
        return this.weeklyMaintenanceWindowStart;
    }

    /**
     * <p>
     * The new weekly maintenance window start day and time to update. The maintenance window day and time should be in
     * Coordinated Universal Time (UTC) 24-hour standard time. For example: TUE:03:30.
     * </p>
     * 
     * @param weeklyMaintenanceWindowStart
     *        The new weekly maintenance window start day and time to update. The maintenance window day and time should
     *        be in Coordinated Universal Time (UTC) 24-hour standard time. For example: TUE:03:30.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public UpdateMlflowTrackingServerRequest withWeeklyMaintenanceWindowStart(String weeklyMaintenanceWindowStart) {
        setWeeklyMaintenanceWindowStart(weeklyMaintenanceWindowStart);
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
        if (getTrackingServerName() != null)
            sb.append("TrackingServerName: ").append(getTrackingServerName()).append(",");
        if (getArtifactStoreUri() != null)
            sb.append("ArtifactStoreUri: ").append(getArtifactStoreUri()).append(",");
        if (getTrackingServerSize() != null)
            sb.append("TrackingServerSize: ").append(getTrackingServerSize()).append(",");
        if (getAutomaticModelRegistration() != null)
            sb.append("AutomaticModelRegistration: ").append(getAutomaticModelRegistration()).append(",");
        if (getWeeklyMaintenanceWindowStart() != null)
            sb.append("WeeklyMaintenanceWindowStart: ").append(getWeeklyMaintenanceWindowStart());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof UpdateMlflowTrackingServerRequest == false)
            return false;
        UpdateMlflowTrackingServerRequest other = (UpdateMlflowTrackingServerRequest) obj;
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
        if (other.getAutomaticModelRegistration() == null ^ this.getAutomaticModelRegistration() == null)
            return false;
        if (other.getAutomaticModelRegistration() != null && other.getAutomaticModelRegistration().equals(this.getAutomaticModelRegistration()) == false)
            return false;
        if (other.getWeeklyMaintenanceWindowStart() == null ^ this.getWeeklyMaintenanceWindowStart() == null)
            return false;
        if (other.getWeeklyMaintenanceWindowStart() != null && other.getWeeklyMaintenanceWindowStart().equals(this.getWeeklyMaintenanceWindowStart()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getTrackingServerName() == null) ? 0 : getTrackingServerName().hashCode());
        hashCode = prime * hashCode + ((getArtifactStoreUri() == null) ? 0 : getArtifactStoreUri().hashCode());
        hashCode = prime * hashCode + ((getTrackingServerSize() == null) ? 0 : getTrackingServerSize().hashCode());
        hashCode = prime * hashCode + ((getAutomaticModelRegistration() == null) ? 0 : getAutomaticModelRegistration().hashCode());
        hashCode = prime * hashCode + ((getWeeklyMaintenanceWindowStart() == null) ? 0 : getWeeklyMaintenanceWindowStart().hashCode());
        return hashCode;
    }

    @Override
    public UpdateMlflowTrackingServerRequest clone() {
        return (UpdateMlflowTrackingServerRequest) super.clone();
    }

}
