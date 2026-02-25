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
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/sagemaker-2017-07-24/CreatePresignedMlflowTrackingServerUrl"
 *      target="_top">AWS API Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class CreatePresignedMlflowTrackingServerUrlRequest extends com.amazonaws.AmazonWebServiceRequest implements Serializable, Cloneable {

    /**
     * <p>
     * The name of the tracking server to connect to your MLflow UI.
     * </p>
     */
    private String trackingServerName;
    /**
     * <p>
     * The duration in seconds that your presigned URL is valid. The presigned URL can be used only once.
     * </p>
     */
    private Integer expiresInSeconds;
    /**
     * <p>
     * The duration in seconds that your MLflow UI session is valid.
     * </p>
     */
    private Integer sessionExpirationDurationInSeconds;

    /**
     * <p>
     * The name of the tracking server to connect to your MLflow UI.
     * </p>
     * 
     * @param trackingServerName
     *        The name of the tracking server to connect to your MLflow UI.
     */

    public void setTrackingServerName(String trackingServerName) {
        this.trackingServerName = trackingServerName;
    }

    /**
     * <p>
     * The name of the tracking server to connect to your MLflow UI.
     * </p>
     * 
     * @return The name of the tracking server to connect to your MLflow UI.
     */

    public String getTrackingServerName() {
        return this.trackingServerName;
    }

    /**
     * <p>
     * The name of the tracking server to connect to your MLflow UI.
     * </p>
     * 
     * @param trackingServerName
     *        The name of the tracking server to connect to your MLflow UI.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public CreatePresignedMlflowTrackingServerUrlRequest withTrackingServerName(String trackingServerName) {
        setTrackingServerName(trackingServerName);
        return this;
    }

    /**
     * <p>
     * The duration in seconds that your presigned URL is valid. The presigned URL can be used only once.
     * </p>
     * 
     * @param expiresInSeconds
     *        The duration in seconds that your presigned URL is valid. The presigned URL can be used only once.
     */

    public void setExpiresInSeconds(Integer expiresInSeconds) {
        this.expiresInSeconds = expiresInSeconds;
    }

    /**
     * <p>
     * The duration in seconds that your presigned URL is valid. The presigned URL can be used only once.
     * </p>
     * 
     * @return The duration in seconds that your presigned URL is valid. The presigned URL can be used only once.
     */

    public Integer getExpiresInSeconds() {
        return this.expiresInSeconds;
    }

    /**
     * <p>
     * The duration in seconds that your presigned URL is valid. The presigned URL can be used only once.
     * </p>
     * 
     * @param expiresInSeconds
     *        The duration in seconds that your presigned URL is valid. The presigned URL can be used only once.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public CreatePresignedMlflowTrackingServerUrlRequest withExpiresInSeconds(Integer expiresInSeconds) {
        setExpiresInSeconds(expiresInSeconds);
        return this;
    }

    /**
     * <p>
     * The duration in seconds that your MLflow UI session is valid.
     * </p>
     * 
     * @param sessionExpirationDurationInSeconds
     *        The duration in seconds that your MLflow UI session is valid.
     */

    public void setSessionExpirationDurationInSeconds(Integer sessionExpirationDurationInSeconds) {
        this.sessionExpirationDurationInSeconds = sessionExpirationDurationInSeconds;
    }

    /**
     * <p>
     * The duration in seconds that your MLflow UI session is valid.
     * </p>
     * 
     * @return The duration in seconds that your MLflow UI session is valid.
     */

    public Integer getSessionExpirationDurationInSeconds() {
        return this.sessionExpirationDurationInSeconds;
    }

    /**
     * <p>
     * The duration in seconds that your MLflow UI session is valid.
     * </p>
     * 
     * @param sessionExpirationDurationInSeconds
     *        The duration in seconds that your MLflow UI session is valid.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public CreatePresignedMlflowTrackingServerUrlRequest withSessionExpirationDurationInSeconds(Integer sessionExpirationDurationInSeconds) {
        setSessionExpirationDurationInSeconds(sessionExpirationDurationInSeconds);
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
        if (getExpiresInSeconds() != null)
            sb.append("ExpiresInSeconds: ").append(getExpiresInSeconds()).append(",");
        if (getSessionExpirationDurationInSeconds() != null)
            sb.append("SessionExpirationDurationInSeconds: ").append(getSessionExpirationDurationInSeconds());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof CreatePresignedMlflowTrackingServerUrlRequest == false)
            return false;
        CreatePresignedMlflowTrackingServerUrlRequest other = (CreatePresignedMlflowTrackingServerUrlRequest) obj;
        if (other.getTrackingServerName() == null ^ this.getTrackingServerName() == null)
            return false;
        if (other.getTrackingServerName() != null && other.getTrackingServerName().equals(this.getTrackingServerName()) == false)
            return false;
        if (other.getExpiresInSeconds() == null ^ this.getExpiresInSeconds() == null)
            return false;
        if (other.getExpiresInSeconds() != null && other.getExpiresInSeconds().equals(this.getExpiresInSeconds()) == false)
            return false;
        if (other.getSessionExpirationDurationInSeconds() == null ^ this.getSessionExpirationDurationInSeconds() == null)
            return false;
        if (other.getSessionExpirationDurationInSeconds() != null
                && other.getSessionExpirationDurationInSeconds().equals(this.getSessionExpirationDurationInSeconds()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getTrackingServerName() == null) ? 0 : getTrackingServerName().hashCode());
        hashCode = prime * hashCode + ((getExpiresInSeconds() == null) ? 0 : getExpiresInSeconds().hashCode());
        hashCode = prime * hashCode + ((getSessionExpirationDurationInSeconds() == null) ? 0 : getSessionExpirationDurationInSeconds().hashCode());
        return hashCode;
    }

    @Override
    public CreatePresignedMlflowTrackingServerUrlRequest clone() {
        return (CreatePresignedMlflowTrackingServerUrlRequest) super.clone();
    }

}
