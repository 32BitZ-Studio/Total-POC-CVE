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
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/sagemaker-2017-07-24/CreateMlflowTrackingServer"
 *      target="_top">AWS API Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class CreateMlflowTrackingServerRequest extends com.amazonaws.AmazonWebServiceRequest implements Serializable, Cloneable {

    /**
     * <p>
     * A unique string identifying the tracking server name. This string is part of the tracking server ARN.
     * </p>
     */
    private String trackingServerName;
    /**
     * <p>
     * The S3 URI for a general purpose bucket to use as the MLflow Tracking Server artifact store.
     * </p>
     */
    private String artifactStoreUri;
    /**
     * <p>
     * The size of the tracking server you want to create. You can choose between <code>"Small"</code>,
     * <code>"Medium"</code>, and <code>"Large"</code>. The default MLflow Tracking Server configuration size is
     * <code>"Small"</code>. You can choose a size depending on the projected use of the tracking server such as the
     * volume of data logged, number of users, and frequency of use.
     * </p>
     * <p>
     * We recommend using a small tracking server for teams of up to 25 users, a medium tracking server for teams of up
     * to 50 users, and a large tracking server for teams of up to 100 users.
     * </p>
     */
    private String trackingServerSize;
    /**
     * <p>
     * The version of MLflow that the tracking server uses. To see which MLflow versions are available to use, see <a
     * href="https://docs.aws.amazon.com/sagemaker/latest/dg/mlflow.html#mlflow-create-tracking-server-how-it-works">How
     * it works</a>.
     * </p>
     */
    private String mlflowVersion;
    /**
     * <p>
     * The Amazon Resource Name (ARN) for an IAM role in your account that the MLflow Tracking Server uses to access the
     * artifact store in Amazon S3. The role should have <code>AmazonS3FullAccess</code> permissions. For more
     * information on IAM permissions for tracking server creation, see <a
     * href="https://docs.aws.amazon.com/sagemaker/latest/dg/mlflow-create-tracking-server-iam.html">Set up IAM
     * permissions for MLflow</a>.
     * </p>
     */
    private String roleArn;
    /**
     * <p>
     * Whether to enable or disable automatic registration of new MLflow models to the SageMaker Model Registry. To
     * enable automatic model registration, set this value to <code>True</code>. To disable automatic model
     * registration, set this value to <code>False</code>. If not specified, <code>AutomaticModelRegistration</code>
     * defaults to <code>False</code>.
     * </p>
     */
    private Boolean automaticModelRegistration;
    /**
     * <p>
     * The day and time of the week in Coordinated Universal Time (UTC) 24-hour standard time that weekly maintenance
     * updates are scheduled. For example: TUE:03:30.
     * </p>
     */
    private String weeklyMaintenanceWindowStart;
    /**
     * <p>
     * Tags consisting of key-value pairs used to manage metadata for the tracking server.
     * </p>
     */
    private java.util.List<Tag> tags;

    /**
     * <p>
     * A unique string identifying the tracking server name. This string is part of the tracking server ARN.
     * </p>
     * 
     * @param trackingServerName
     *        A unique string identifying the tracking server name. This string is part of the tracking server ARN.
     */

    public void setTrackingServerName(String trackingServerName) {
        this.trackingServerName = trackingServerName;
    }

    /**
     * <p>
     * A unique string identifying the tracking server name. This string is part of the tracking server ARN.
     * </p>
     * 
     * @return A unique string identifying the tracking server name. This string is part of the tracking server ARN.
     */

    public String getTrackingServerName() {
        return this.trackingServerName;
    }

    /**
     * <p>
     * A unique string identifying the tracking server name. This string is part of the tracking server ARN.
     * </p>
     * 
     * @param trackingServerName
     *        A unique string identifying the tracking server name. This string is part of the tracking server ARN.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public CreateMlflowTrackingServerRequest withTrackingServerName(String trackingServerName) {
        setTrackingServerName(trackingServerName);
        return this;
    }

    /**
     * <p>
     * The S3 URI for a general purpose bucket to use as the MLflow Tracking Server artifact store.
     * </p>
     * 
     * @param artifactStoreUri
     *        The S3 URI for a general purpose bucket to use as the MLflow Tracking Server artifact store.
     */

    public void setArtifactStoreUri(String artifactStoreUri) {
        this.artifactStoreUri = artifactStoreUri;
    }

    /**
     * <p>
     * The S3 URI for a general purpose bucket to use as the MLflow Tracking Server artifact store.
     * </p>
     * 
     * @return The S3 URI for a general purpose bucket to use as the MLflow Tracking Server artifact store.
     */

    public String getArtifactStoreUri() {
        return this.artifactStoreUri;
    }

    /**
     * <p>
     * The S3 URI for a general purpose bucket to use as the MLflow Tracking Server artifact store.
     * </p>
     * 
     * @param artifactStoreUri
     *        The S3 URI for a general purpose bucket to use as the MLflow Tracking Server artifact store.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public CreateMlflowTrackingServerRequest withArtifactStoreUri(String artifactStoreUri) {
        setArtifactStoreUri(artifactStoreUri);
        return this;
    }

    /**
     * <p>
     * The size of the tracking server you want to create. You can choose between <code>"Small"</code>,
     * <code>"Medium"</code>, and <code>"Large"</code>. The default MLflow Tracking Server configuration size is
     * <code>"Small"</code>. You can choose a size depending on the projected use of the tracking server such as the
     * volume of data logged, number of users, and frequency of use.
     * </p>
     * <p>
     * We recommend using a small tracking server for teams of up to 25 users, a medium tracking server for teams of up
     * to 50 users, and a large tracking server for teams of up to 100 users.
     * </p>
     * 
     * @param trackingServerSize
     *        The size of the tracking server you want to create. You can choose between <code>"Small"</code>,
     *        <code>"Medium"</code>, and <code>"Large"</code>. The default MLflow Tracking Server configuration size is
     *        <code>"Small"</code>. You can choose a size depending on the projected use of the tracking server such as
     *        the volume of data logged, number of users, and frequency of use. </p>
     *        <p>
     *        We recommend using a small tracking server for teams of up to 25 users, a medium tracking server for teams
     *        of up to 50 users, and a large tracking server for teams of up to 100 users.
     * @see TrackingServerSize
     */

    public void setTrackingServerSize(String trackingServerSize) {
        this.trackingServerSize = trackingServerSize;
    }

    /**
     * <p>
     * The size of the tracking server you want to create. You can choose between <code>"Small"</code>,
     * <code>"Medium"</code>, and <code>"Large"</code>. The default MLflow Tracking Server configuration size is
     * <code>"Small"</code>. You can choose a size depending on the projected use of the tracking server such as the
     * volume of data logged, number of users, and frequency of use.
     * </p>
     * <p>
     * We recommend using a small tracking server for teams of up to 25 users, a medium tracking server for teams of up
     * to 50 users, and a large tracking server for teams of up to 100 users.
     * </p>
     * 
     * @return The size of the tracking server you want to create. You can choose between <code>"Small"</code>,
     *         <code>"Medium"</code>, and <code>"Large"</code>. The default MLflow Tracking Server configuration size is
     *         <code>"Small"</code>. You can choose a size depending on the projected use of the tracking server such as
     *         the volume of data logged, number of users, and frequency of use. </p>
     *         <p>
     *         We recommend using a small tracking server for teams of up to 25 users, a medium tracking server for
     *         teams of up to 50 users, and a large tracking server for teams of up to 100 users.
     * @see TrackingServerSize
     */

    public String getTrackingServerSize() {
        return this.trackingServerSize;
    }

    /**
     * <p>
     * The size of the tracking server you want to create. You can choose between <code>"Small"</code>,
     * <code>"Medium"</code>, and <code>"Large"</code>. The default MLflow Tracking Server configuration size is
     * <code>"Small"</code>. You can choose a size depending on the projected use of the tracking server such as the
     * volume of data logged, number of users, and frequency of use.
     * </p>
     * <p>
     * We recommend using a small tracking server for teams of up to 25 users, a medium tracking server for teams of up
     * to 50 users, and a large tracking server for teams of up to 100 users.
     * </p>
     * 
     * @param trackingServerSize
     *        The size of the tracking server you want to create. You can choose between <code>"Small"</code>,
     *        <code>"Medium"</code>, and <code>"Large"</code>. The default MLflow Tracking Server configuration size is
     *        <code>"Small"</code>. You can choose a size depending on the projected use of the tracking server such as
     *        the volume of data logged, number of users, and frequency of use. </p>
     *        <p>
     *        We recommend using a small tracking server for teams of up to 25 users, a medium tracking server for teams
     *        of up to 50 users, and a large tracking server for teams of up to 100 users.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see TrackingServerSize
     */

    public CreateMlflowTrackingServerRequest withTrackingServerSize(String trackingServerSize) {
        setTrackingServerSize(trackingServerSize);
        return this;
    }

    /**
     * <p>
     * The size of the tracking server you want to create. You can choose between <code>"Small"</code>,
     * <code>"Medium"</code>, and <code>"Large"</code>. The default MLflow Tracking Server configuration size is
     * <code>"Small"</code>. You can choose a size depending on the projected use of the tracking server such as the
     * volume of data logged, number of users, and frequency of use.
     * </p>
     * <p>
     * We recommend using a small tracking server for teams of up to 25 users, a medium tracking server for teams of up
     * to 50 users, and a large tracking server for teams of up to 100 users.
     * </p>
     * 
     * @param trackingServerSize
     *        The size of the tracking server you want to create. You can choose between <code>"Small"</code>,
     *        <code>"Medium"</code>, and <code>"Large"</code>. The default MLflow Tracking Server configuration size is
     *        <code>"Small"</code>. You can choose a size depending on the projected use of the tracking server such as
     *        the volume of data logged, number of users, and frequency of use. </p>
     *        <p>
     *        We recommend using a small tracking server for teams of up to 25 users, a medium tracking server for teams
     *        of up to 50 users, and a large tracking server for teams of up to 100 users.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see TrackingServerSize
     */

    public CreateMlflowTrackingServerRequest withTrackingServerSize(TrackingServerSize trackingServerSize) {
        this.trackingServerSize = trackingServerSize.toString();
        return this;
    }

    /**
     * <p>
     * The version of MLflow that the tracking server uses. To see which MLflow versions are available to use, see <a
     * href="https://docs.aws.amazon.com/sagemaker/latest/dg/mlflow.html#mlflow-create-tracking-server-how-it-works">How
     * it works</a>.
     * </p>
     * 
     * @param mlflowVersion
     *        The version of MLflow that the tracking server uses. To see which MLflow versions are available to use,
     *        see <a href=
     *        "https://docs.aws.amazon.com/sagemaker/latest/dg/mlflow.html#mlflow-create-tracking-server-how-it-works"
     *        >How it works</a>.
     */

    public void setMlflowVersion(String mlflowVersion) {
        this.mlflowVersion = mlflowVersion;
    }

    /**
     * <p>
     * The version of MLflow that the tracking server uses. To see which MLflow versions are available to use, see <a
     * href="https://docs.aws.amazon.com/sagemaker/latest/dg/mlflow.html#mlflow-create-tracking-server-how-it-works">How
     * it works</a>.
     * </p>
     * 
     * @return The version of MLflow that the tracking server uses. To see which MLflow versions are available to use,
     *         see <a href=
     *         "https://docs.aws.amazon.com/sagemaker/latest/dg/mlflow.html#mlflow-create-tracking-server-how-it-works"
     *         >How it works</a>.
     */

    public String getMlflowVersion() {
        return this.mlflowVersion;
    }

    /**
     * <p>
     * The version of MLflow that the tracking server uses. To see which MLflow versions are available to use, see <a
     * href="https://docs.aws.amazon.com/sagemaker/latest/dg/mlflow.html#mlflow-create-tracking-server-how-it-works">How
     * it works</a>.
     * </p>
     * 
     * @param mlflowVersion
     *        The version of MLflow that the tracking server uses. To see which MLflow versions are available to use,
     *        see <a href=
     *        "https://docs.aws.amazon.com/sagemaker/latest/dg/mlflow.html#mlflow-create-tracking-server-how-it-works"
     *        >How it works</a>.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public CreateMlflowTrackingServerRequest withMlflowVersion(String mlflowVersion) {
        setMlflowVersion(mlflowVersion);
        return this;
    }

    /**
     * <p>
     * The Amazon Resource Name (ARN) for an IAM role in your account that the MLflow Tracking Server uses to access the
     * artifact store in Amazon S3. The role should have <code>AmazonS3FullAccess</code> permissions. For more
     * information on IAM permissions for tracking server creation, see <a
     * href="https://docs.aws.amazon.com/sagemaker/latest/dg/mlflow-create-tracking-server-iam.html">Set up IAM
     * permissions for MLflow</a>.
     * </p>
     * 
     * @param roleArn
     *        The Amazon Resource Name (ARN) for an IAM role in your account that the MLflow Tracking Server uses to
     *        access the artifact store in Amazon S3. The role should have <code>AmazonS3FullAccess</code> permissions.
     *        For more information on IAM permissions for tracking server creation, see <a
     *        href="https://docs.aws.amazon.com/sagemaker/latest/dg/mlflow-create-tracking-server-iam.html">Set up IAM
     *        permissions for MLflow</a>.
     */

    public void setRoleArn(String roleArn) {
        this.roleArn = roleArn;
    }

    /**
     * <p>
     * The Amazon Resource Name (ARN) for an IAM role in your account that the MLflow Tracking Server uses to access the
     * artifact store in Amazon S3. The role should have <code>AmazonS3FullAccess</code> permissions. For more
     * information on IAM permissions for tracking server creation, see <a
     * href="https://docs.aws.amazon.com/sagemaker/latest/dg/mlflow-create-tracking-server-iam.html">Set up IAM
     * permissions for MLflow</a>.
     * </p>
     * 
     * @return The Amazon Resource Name (ARN) for an IAM role in your account that the MLflow Tracking Server uses to
     *         access the artifact store in Amazon S3. The role should have <code>AmazonS3FullAccess</code> permissions.
     *         For more information on IAM permissions for tracking server creation, see <a
     *         href="https://docs.aws.amazon.com/sagemaker/latest/dg/mlflow-create-tracking-server-iam.html">Set up IAM
     *         permissions for MLflow</a>.
     */

    public String getRoleArn() {
        return this.roleArn;
    }

    /**
     * <p>
     * The Amazon Resource Name (ARN) for an IAM role in your account that the MLflow Tracking Server uses to access the
     * artifact store in Amazon S3. The role should have <code>AmazonS3FullAccess</code> permissions. For more
     * information on IAM permissions for tracking server creation, see <a
     * href="https://docs.aws.amazon.com/sagemaker/latest/dg/mlflow-create-tracking-server-iam.html">Set up IAM
     * permissions for MLflow</a>.
     * </p>
     * 
     * @param roleArn
     *        The Amazon Resource Name (ARN) for an IAM role in your account that the MLflow Tracking Server uses to
     *        access the artifact store in Amazon S3. The role should have <code>AmazonS3FullAccess</code> permissions.
     *        For more information on IAM permissions for tracking server creation, see <a
     *        href="https://docs.aws.amazon.com/sagemaker/latest/dg/mlflow-create-tracking-server-iam.html">Set up IAM
     *        permissions for MLflow</a>.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public CreateMlflowTrackingServerRequest withRoleArn(String roleArn) {
        setRoleArn(roleArn);
        return this;
    }

    /**
     * <p>
     * Whether to enable or disable automatic registration of new MLflow models to the SageMaker Model Registry. To
     * enable automatic model registration, set this value to <code>True</code>. To disable automatic model
     * registration, set this value to <code>False</code>. If not specified, <code>AutomaticModelRegistration</code>
     * defaults to <code>False</code>.
     * </p>
     * 
     * @param automaticModelRegistration
     *        Whether to enable or disable automatic registration of new MLflow models to the SageMaker Model Registry.
     *        To enable automatic model registration, set this value to <code>True</code>. To disable automatic model
     *        registration, set this value to <code>False</code>. If not specified,
     *        <code>AutomaticModelRegistration</code> defaults to <code>False</code>.
     */

    public void setAutomaticModelRegistration(Boolean automaticModelRegistration) {
        this.automaticModelRegistration = automaticModelRegistration;
    }

    /**
     * <p>
     * Whether to enable or disable automatic registration of new MLflow models to the SageMaker Model Registry. To
     * enable automatic model registration, set this value to <code>True</code>. To disable automatic model
     * registration, set this value to <code>False</code>. If not specified, <code>AutomaticModelRegistration</code>
     * defaults to <code>False</code>.
     * </p>
     * 
     * @return Whether to enable or disable automatic registration of new MLflow models to the SageMaker Model Registry.
     *         To enable automatic model registration, set this value to <code>True</code>. To disable automatic model
     *         registration, set this value to <code>False</code>. If not specified,
     *         <code>AutomaticModelRegistration</code> defaults to <code>False</code>.
     */

    public Boolean getAutomaticModelRegistration() {
        return this.automaticModelRegistration;
    }

    /**
     * <p>
     * Whether to enable or disable automatic registration of new MLflow models to the SageMaker Model Registry. To
     * enable automatic model registration, set this value to <code>True</code>. To disable automatic model
     * registration, set this value to <code>False</code>. If not specified, <code>AutomaticModelRegistration</code>
     * defaults to <code>False</code>.
     * </p>
     * 
     * @param automaticModelRegistration
     *        Whether to enable or disable automatic registration of new MLflow models to the SageMaker Model Registry.
     *        To enable automatic model registration, set this value to <code>True</code>. To disable automatic model
     *        registration, set this value to <code>False</code>. If not specified,
     *        <code>AutomaticModelRegistration</code> defaults to <code>False</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public CreateMlflowTrackingServerRequest withAutomaticModelRegistration(Boolean automaticModelRegistration) {
        setAutomaticModelRegistration(automaticModelRegistration);
        return this;
    }

    /**
     * <p>
     * Whether to enable or disable automatic registration of new MLflow models to the SageMaker Model Registry. To
     * enable automatic model registration, set this value to <code>True</code>. To disable automatic model
     * registration, set this value to <code>False</code>. If not specified, <code>AutomaticModelRegistration</code>
     * defaults to <code>False</code>.
     * </p>
     * 
     * @return Whether to enable or disable automatic registration of new MLflow models to the SageMaker Model Registry.
     *         To enable automatic model registration, set this value to <code>True</code>. To disable automatic model
     *         registration, set this value to <code>False</code>. If not specified,
     *         <code>AutomaticModelRegistration</code> defaults to <code>False</code>.
     */

    public Boolean isAutomaticModelRegistration() {
        return this.automaticModelRegistration;
    }

    /**
     * <p>
     * The day and time of the week in Coordinated Universal Time (UTC) 24-hour standard time that weekly maintenance
     * updates are scheduled. For example: TUE:03:30.
     * </p>
     * 
     * @param weeklyMaintenanceWindowStart
     *        The day and time of the week in Coordinated Universal Time (UTC) 24-hour standard time that weekly
     *        maintenance updates are scheduled. For example: TUE:03:30.
     */

    public void setWeeklyMaintenanceWindowStart(String weeklyMaintenanceWindowStart) {
        this.weeklyMaintenanceWindowStart = weeklyMaintenanceWindowStart;
    }

    /**
     * <p>
     * The day and time of the week in Coordinated Universal Time (UTC) 24-hour standard time that weekly maintenance
     * updates are scheduled. For example: TUE:03:30.
     * </p>
     * 
     * @return The day and time of the week in Coordinated Universal Time (UTC) 24-hour standard time that weekly
     *         maintenance updates are scheduled. For example: TUE:03:30.
     */

    public String getWeeklyMaintenanceWindowStart() {
        return this.weeklyMaintenanceWindowStart;
    }

    /**
     * <p>
     * The day and time of the week in Coordinated Universal Time (UTC) 24-hour standard time that weekly maintenance
     * updates are scheduled. For example: TUE:03:30.
     * </p>
     * 
     * @param weeklyMaintenanceWindowStart
     *        The day and time of the week in Coordinated Universal Time (UTC) 24-hour standard time that weekly
     *        maintenance updates are scheduled. For example: TUE:03:30.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public CreateMlflowTrackingServerRequest withWeeklyMaintenanceWindowStart(String weeklyMaintenanceWindowStart) {
        setWeeklyMaintenanceWindowStart(weeklyMaintenanceWindowStart);
        return this;
    }

    /**
     * <p>
     * Tags consisting of key-value pairs used to manage metadata for the tracking server.
     * </p>
     * 
     * @return Tags consisting of key-value pairs used to manage metadata for the tracking server.
     */

    public java.util.List<Tag> getTags() {
        return tags;
    }

    /**
     * <p>
     * Tags consisting of key-value pairs used to manage metadata for the tracking server.
     * </p>
     * 
     * @param tags
     *        Tags consisting of key-value pairs used to manage metadata for the tracking server.
     */

    public void setTags(java.util.Collection<Tag> tags) {
        if (tags == null) {
            this.tags = null;
            return;
        }

        this.tags = new java.util.ArrayList<Tag>(tags);
    }

    /**
     * <p>
     * Tags consisting of key-value pairs used to manage metadata for the tracking server.
     * </p>
     * <p>
     * <b>NOTE:</b> This method appends the values to the existing list (if any). Use
     * {@link #setTags(java.util.Collection)} or {@link #withTags(java.util.Collection)} if you want to override the
     * existing values.
     * </p>
     * 
     * @param tags
     *        Tags consisting of key-value pairs used to manage metadata for the tracking server.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public CreateMlflowTrackingServerRequest withTags(Tag... tags) {
        if (this.tags == null) {
            setTags(new java.util.ArrayList<Tag>(tags.length));
        }
        for (Tag ele : tags) {
            this.tags.add(ele);
        }
        return this;
    }

    /**
     * <p>
     * Tags consisting of key-value pairs used to manage metadata for the tracking server.
     * </p>
     * 
     * @param tags
     *        Tags consisting of key-value pairs used to manage metadata for the tracking server.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public CreateMlflowTrackingServerRequest withTags(java.util.Collection<Tag> tags) {
        setTags(tags);
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
        if (getMlflowVersion() != null)
            sb.append("MlflowVersion: ").append(getMlflowVersion()).append(",");
        if (getRoleArn() != null)
            sb.append("RoleArn: ").append(getRoleArn()).append(",");
        if (getAutomaticModelRegistration() != null)
            sb.append("AutomaticModelRegistration: ").append(getAutomaticModelRegistration()).append(",");
        if (getWeeklyMaintenanceWindowStart() != null)
            sb.append("WeeklyMaintenanceWindowStart: ").append(getWeeklyMaintenanceWindowStart()).append(",");
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

        if (obj instanceof CreateMlflowTrackingServerRequest == false)
            return false;
        CreateMlflowTrackingServerRequest other = (CreateMlflowTrackingServerRequest) obj;
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
        if (other.getAutomaticModelRegistration() == null ^ this.getAutomaticModelRegistration() == null)
            return false;
        if (other.getAutomaticModelRegistration() != null && other.getAutomaticModelRegistration().equals(this.getAutomaticModelRegistration()) == false)
            return false;
        if (other.getWeeklyMaintenanceWindowStart() == null ^ this.getWeeklyMaintenanceWindowStart() == null)
            return false;
        if (other.getWeeklyMaintenanceWindowStart() != null && other.getWeeklyMaintenanceWindowStart().equals(this.getWeeklyMaintenanceWindowStart()) == false)
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

        hashCode = prime * hashCode + ((getTrackingServerName() == null) ? 0 : getTrackingServerName().hashCode());
        hashCode = prime * hashCode + ((getArtifactStoreUri() == null) ? 0 : getArtifactStoreUri().hashCode());
        hashCode = prime * hashCode + ((getTrackingServerSize() == null) ? 0 : getTrackingServerSize().hashCode());
        hashCode = prime * hashCode + ((getMlflowVersion() == null) ? 0 : getMlflowVersion().hashCode());
        hashCode = prime * hashCode + ((getRoleArn() == null) ? 0 : getRoleArn().hashCode());
        hashCode = prime * hashCode + ((getAutomaticModelRegistration() == null) ? 0 : getAutomaticModelRegistration().hashCode());
        hashCode = prime * hashCode + ((getWeeklyMaintenanceWindowStart() == null) ? 0 : getWeeklyMaintenanceWindowStart().hashCode());
        hashCode = prime * hashCode + ((getTags() == null) ? 0 : getTags().hashCode());
        return hashCode;
    }

    @Override
    public CreateMlflowTrackingServerRequest clone() {
        return (CreateMlflowTrackingServerRequest) super.clone();
    }

}
