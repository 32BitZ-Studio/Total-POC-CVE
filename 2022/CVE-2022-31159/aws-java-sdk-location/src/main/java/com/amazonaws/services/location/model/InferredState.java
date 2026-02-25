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
package com.amazonaws.services.location.model;

import java.io.Serializable;
import javax.annotation.Generated;
import com.amazonaws.protocol.StructuredPojo;
import com.amazonaws.protocol.ProtocolMarshaller;

/**
 * <p>
 * The inferred state of the device, given the provided position, IP address, cellular signals, and Wi-Fi- access
 * points.
 * </p>
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/location-2020-11-19/InferredState" target="_top">AWS API
 *      Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class InferredState implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * The device position inferred by the provided position, IP address, cellular signals, and Wi-Fi- access points.
     * </p>
     */
    private java.util.List<Double> position;
    /**
     * <p>
     * The level of certainty of the inferred position.
     * </p>
     */
    private PositionalAccuracy accuracy;
    /**
     * <p>
     * The distance between the inferred position and the device's self-reported position.
     * </p>
     */
    private Double deviationDistance;
    /**
     * <p>
     * Indicates if a proxy was used.
     * </p>
     */
    private Boolean proxyDetected;

    /**
     * <p>
     * The device position inferred by the provided position, IP address, cellular signals, and Wi-Fi- access points.
     * </p>
     * 
     * @return The device position inferred by the provided position, IP address, cellular signals, and Wi-Fi- access
     *         points.
     */

    public java.util.List<Double> getPosition() {
        return position;
    }

    /**
     * <p>
     * The device position inferred by the provided position, IP address, cellular signals, and Wi-Fi- access points.
     * </p>
     * 
     * @param position
     *        The device position inferred by the provided position, IP address, cellular signals, and Wi-Fi- access
     *        points.
     */

    public void setPosition(java.util.Collection<Double> position) {
        if (position == null) {
            this.position = null;
            return;
        }

        this.position = new java.util.ArrayList<Double>(position);
    }

    /**
     * <p>
     * The device position inferred by the provided position, IP address, cellular signals, and Wi-Fi- access points.
     * </p>
     * <p>
     * <b>NOTE:</b> This method appends the values to the existing list (if any). Use
     * {@link #setPosition(java.util.Collection)} or {@link #withPosition(java.util.Collection)} if you want to override
     * the existing values.
     * </p>
     * 
     * @param position
     *        The device position inferred by the provided position, IP address, cellular signals, and Wi-Fi- access
     *        points.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public InferredState withPosition(Double... position) {
        if (this.position == null) {
            setPosition(new java.util.ArrayList<Double>(position.length));
        }
        for (Double ele : position) {
            this.position.add(ele);
        }
        return this;
    }

    /**
     * <p>
     * The device position inferred by the provided position, IP address, cellular signals, and Wi-Fi- access points.
     * </p>
     * 
     * @param position
     *        The device position inferred by the provided position, IP address, cellular signals, and Wi-Fi- access
     *        points.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public InferredState withPosition(java.util.Collection<Double> position) {
        setPosition(position);
        return this;
    }

    /**
     * <p>
     * The level of certainty of the inferred position.
     * </p>
     * 
     * @param accuracy
     *        The level of certainty of the inferred position.
     */

    public void setAccuracy(PositionalAccuracy accuracy) {
        this.accuracy = accuracy;
    }

    /**
     * <p>
     * The level of certainty of the inferred position.
     * </p>
     * 
     * @return The level of certainty of the inferred position.
     */

    public PositionalAccuracy getAccuracy() {
        return this.accuracy;
    }

    /**
     * <p>
     * The level of certainty of the inferred position.
     * </p>
     * 
     * @param accuracy
     *        The level of certainty of the inferred position.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public InferredState withAccuracy(PositionalAccuracy accuracy) {
        setAccuracy(accuracy);
        return this;
    }

    /**
     * <p>
     * The distance between the inferred position and the device's self-reported position.
     * </p>
     * 
     * @param deviationDistance
     *        The distance between the inferred position and the device's self-reported position.
     */

    public void setDeviationDistance(Double deviationDistance) {
        this.deviationDistance = deviationDistance;
    }

    /**
     * <p>
     * The distance between the inferred position and the device's self-reported position.
     * </p>
     * 
     * @return The distance between the inferred position and the device's self-reported position.
     */

    public Double getDeviationDistance() {
        return this.deviationDistance;
    }

    /**
     * <p>
     * The distance between the inferred position and the device's self-reported position.
     * </p>
     * 
     * @param deviationDistance
     *        The distance between the inferred position and the device's self-reported position.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public InferredState withDeviationDistance(Double deviationDistance) {
        setDeviationDistance(deviationDistance);
        return this;
    }

    /**
     * <p>
     * Indicates if a proxy was used.
     * </p>
     * 
     * @param proxyDetected
     *        Indicates if a proxy was used.
     */

    public void setProxyDetected(Boolean proxyDetected) {
        this.proxyDetected = proxyDetected;
    }

    /**
     * <p>
     * Indicates if a proxy was used.
     * </p>
     * 
     * @return Indicates if a proxy was used.
     */

    public Boolean getProxyDetected() {
        return this.proxyDetected;
    }

    /**
     * <p>
     * Indicates if a proxy was used.
     * </p>
     * 
     * @param proxyDetected
     *        Indicates if a proxy was used.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public InferredState withProxyDetected(Boolean proxyDetected) {
        setProxyDetected(proxyDetected);
        return this;
    }

    /**
     * <p>
     * Indicates if a proxy was used.
     * </p>
     * 
     * @return Indicates if a proxy was used.
     */

    public Boolean isProxyDetected() {
        return this.proxyDetected;
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
        if (getPosition() != null)
            sb.append("Position: ").append("***Sensitive Data Redacted***").append(",");
        if (getAccuracy() != null)
            sb.append("Accuracy: ").append(getAccuracy()).append(",");
        if (getDeviationDistance() != null)
            sb.append("DeviationDistance: ").append(getDeviationDistance()).append(",");
        if (getProxyDetected() != null)
            sb.append("ProxyDetected: ").append(getProxyDetected());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof InferredState == false)
            return false;
        InferredState other = (InferredState) obj;
        if (other.getPosition() == null ^ this.getPosition() == null)
            return false;
        if (other.getPosition() != null && other.getPosition().equals(this.getPosition()) == false)
            return false;
        if (other.getAccuracy() == null ^ this.getAccuracy() == null)
            return false;
        if (other.getAccuracy() != null && other.getAccuracy().equals(this.getAccuracy()) == false)
            return false;
        if (other.getDeviationDistance() == null ^ this.getDeviationDistance() == null)
            return false;
        if (other.getDeviationDistance() != null && other.getDeviationDistance().equals(this.getDeviationDistance()) == false)
            return false;
        if (other.getProxyDetected() == null ^ this.getProxyDetected() == null)
            return false;
        if (other.getProxyDetected() != null && other.getProxyDetected().equals(this.getProxyDetected()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getPosition() == null) ? 0 : getPosition().hashCode());
        hashCode = prime * hashCode + ((getAccuracy() == null) ? 0 : getAccuracy().hashCode());
        hashCode = prime * hashCode + ((getDeviationDistance() == null) ? 0 : getDeviationDistance().hashCode());
        hashCode = prime * hashCode + ((getProxyDetected() == null) ? 0 : getProxyDetected().hashCode());
        return hashCode;
    }

    @Override
    public InferredState clone() {
        try {
            return (InferredState) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.location.model.transform.InferredStateMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
