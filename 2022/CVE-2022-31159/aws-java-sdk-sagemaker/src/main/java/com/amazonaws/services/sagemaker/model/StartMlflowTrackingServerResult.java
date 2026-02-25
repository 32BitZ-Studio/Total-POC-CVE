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
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/sagemaker-2017-07-24/StartMlflowTrackingServer"
 *      target="_top">AWS API Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class StartMlflowTrackingServerResult extends com.amazonaws.AmazonWebServiceResult<com.amazonaws.ResponseMetadata> implements Serializable, Cloneable {

    /**
     * <p>
     * The ARN of the started tracking server.
     * </p>
     */
    private String trackingServerArn;

    /**
     * <p>
     * The ARN of the started tracking server.
     * </p>
     * 
     * @param trackingServerArn
     *        The ARN of the started tracking server.
     */

    public void setTrackingServerArn(String trackingServerArn) {
        this.trackingServerArn = trackingServerArn;
    }

    /**
     * <p>
     * The ARN of the started tracking server.
     * </p>
     * 
     * @return The ARN of the started tracking server.
     */

    public String getTrackingServerArn() {
        return this.trackingServerArn;
    }

    /**
     * <p>
     * The ARN of the started tracking server.
     * </p>
     * 
     * @param trackingServerArn
     *        The ARN of the started tracking server.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public StartMlflowTrackingServerResult withTrackingServerArn(String trackingServerArn) {
        setTrackingServerArn(trackingServerArn);
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
            sb.append("TrackingServerArn: ").append(getTrackingServerArn());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof StartMlflowTrackingServerResult == false)
            return false;
        StartMlflowTrackingServerResult other = (StartMlflowTrackingServerResult) obj;
        if (other.getTrackingServerArn() == null ^ this.getTrackingServerArn() == null)
            return false;
        if (other.getTrackingServerArn() != null && other.getTrackingServerArn().equals(this.getTrackingServerArn()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getTrackingServerArn() == null) ? 0 : getTrackingServerArn().hashCode());
        return hashCode;
    }

    @Override
    public StartMlflowTrackingServerResult clone() {
        try {
            return (StartMlflowTrackingServerResult) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

}
