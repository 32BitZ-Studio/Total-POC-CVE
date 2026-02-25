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

/**
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/location-2020-11-19/VerifyDevicePosition" target="_top">AWS API
 *      Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class VerifyDevicePositionResult extends com.amazonaws.AmazonWebServiceResult<com.amazonaws.ResponseMetadata> implements Serializable, Cloneable {

    /**
     * <p>
     * The inferred state of the device, given the provided position, IP address, cellular signals, and Wi-Fi- access
     * points.
     * </p>
     */
    private InferredState inferredState;
    /**
     * <p>
     * The device identifier.
     * </p>
     */
    private String deviceId;
    /**
     * <p>
     * The timestamp at which the device's position was determined. Uses <a
     * href="https://www.iso.org/iso-8601-date-and-time-format.html"> ISO 8601 </a> format:
     * <code>YYYY-MM-DDThh:mm:ss.sssZ</code>.
     * </p>
     */
    private java.util.Date sampleTime;
    /**
     * <p>
     * The timestamp for when the tracker resource received the device position in <a
     * href="https://www.iso.org/iso-8601-date-and-time-format.html"> ISO 8601 </a> format:
     * <code>YYYY-MM-DDThh:mm:ss.sssZ</code>.
     * </p>
     */
    private java.util.Date receivedTime;
    /**
     * <p>
     * The distance unit for the verification response.
     * </p>
     */
    private String distanceUnit;

    /**
     * <p>
     * The inferred state of the device, given the provided position, IP address, cellular signals, and Wi-Fi- access
     * points.
     * </p>
     * 
     * @param inferredState
     *        The inferred state of the device, given the provided position, IP address, cellular signals, and Wi-Fi-
     *        access points.
     */

    public void setInferredState(InferredState inferredState) {
        this.inferredState = inferredState;
    }

    /**
     * <p>
     * The inferred state of the device, given the provided position, IP address, cellular signals, and Wi-Fi- access
     * points.
     * </p>
     * 
     * @return The inferred state of the device, given the provided position, IP address, cellular signals, and Wi-Fi-
     *         access points.
     */

    public InferredState getInferredState() {
        return this.inferredState;
    }

    /**
     * <p>
     * The inferred state of the device, given the provided position, IP address, cellular signals, and Wi-Fi- access
     * points.
     * </p>
     * 
     * @param inferredState
     *        The inferred state of the device, given the provided position, IP address, cellular signals, and Wi-Fi-
     *        access points.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public VerifyDevicePositionResult withInferredState(InferredState inferredState) {
        setInferredState(inferredState);
        return this;
    }

    /**
     * <p>
     * The device identifier.
     * </p>
     * 
     * @param deviceId
     *        The device identifier.
     */

    public void setDeviceId(String deviceId) {
        this.deviceId = deviceId;
    }

    /**
     * <p>
     * The device identifier.
     * </p>
     * 
     * @return The device identifier.
     */

    public String getDeviceId() {
        return this.deviceId;
    }

    /**
     * <p>
     * The device identifier.
     * </p>
     * 
     * @param deviceId
     *        The device identifier.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public VerifyDevicePositionResult withDeviceId(String deviceId) {
        setDeviceId(deviceId);
        return this;
    }

    /**
     * <p>
     * The timestamp at which the device's position was determined. Uses <a
     * href="https://www.iso.org/iso-8601-date-and-time-format.html"> ISO 8601 </a> format:
     * <code>YYYY-MM-DDThh:mm:ss.sssZ</code>.
     * </p>
     * 
     * @param sampleTime
     *        The timestamp at which the device's position was determined. Uses <a
     *        href="https://www.iso.org/iso-8601-date-and-time-format.html"> ISO 8601 </a> format:
     *        <code>YYYY-MM-DDThh:mm:ss.sssZ</code>.
     */

    public void setSampleTime(java.util.Date sampleTime) {
        this.sampleTime = sampleTime;
    }

    /**
     * <p>
     * The timestamp at which the device's position was determined. Uses <a
     * href="https://www.iso.org/iso-8601-date-and-time-format.html"> ISO 8601 </a> format:
     * <code>YYYY-MM-DDThh:mm:ss.sssZ</code>.
     * </p>
     * 
     * @return The timestamp at which the device's position was determined. Uses <a
     *         href="https://www.iso.org/iso-8601-date-and-time-format.html"> ISO 8601 </a> format:
     *         <code>YYYY-MM-DDThh:mm:ss.sssZ</code>.
     */

    public java.util.Date getSampleTime() {
        return this.sampleTime;
    }

    /**
     * <p>
     * The timestamp at which the device's position was determined. Uses <a
     * href="https://www.iso.org/iso-8601-date-and-time-format.html"> ISO 8601 </a> format:
     * <code>YYYY-MM-DDThh:mm:ss.sssZ</code>.
     * </p>
     * 
     * @param sampleTime
     *        The timestamp at which the device's position was determined. Uses <a
     *        href="https://www.iso.org/iso-8601-date-and-time-format.html"> ISO 8601 </a> format:
     *        <code>YYYY-MM-DDThh:mm:ss.sssZ</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public VerifyDevicePositionResult withSampleTime(java.util.Date sampleTime) {
        setSampleTime(sampleTime);
        return this;
    }

    /**
     * <p>
     * The timestamp for when the tracker resource received the device position in <a
     * href="https://www.iso.org/iso-8601-date-and-time-format.html"> ISO 8601 </a> format:
     * <code>YYYY-MM-DDThh:mm:ss.sssZ</code>.
     * </p>
     * 
     * @param receivedTime
     *        The timestamp for when the tracker resource received the device position in <a
     *        href="https://www.iso.org/iso-8601-date-and-time-format.html"> ISO 8601 </a> format:
     *        <code>YYYY-MM-DDThh:mm:ss.sssZ</code>.
     */

    public void setReceivedTime(java.util.Date receivedTime) {
        this.receivedTime = receivedTime;
    }

    /**
     * <p>
     * The timestamp for when the tracker resource received the device position in <a
     * href="https://www.iso.org/iso-8601-date-and-time-format.html"> ISO 8601 </a> format:
     * <code>YYYY-MM-DDThh:mm:ss.sssZ</code>.
     * </p>
     * 
     * @return The timestamp for when the tracker resource received the device position in <a
     *         href="https://www.iso.org/iso-8601-date-and-time-format.html"> ISO 8601 </a> format:
     *         <code>YYYY-MM-DDThh:mm:ss.sssZ</code>.
     */

    public java.util.Date getReceivedTime() {
        return this.receivedTime;
    }

    /**
     * <p>
     * The timestamp for when the tracker resource received the device position in <a
     * href="https://www.iso.org/iso-8601-date-and-time-format.html"> ISO 8601 </a> format:
     * <code>YYYY-MM-DDThh:mm:ss.sssZ</code>.
     * </p>
     * 
     * @param receivedTime
     *        The timestamp for when the tracker resource received the device position in <a
     *        href="https://www.iso.org/iso-8601-date-and-time-format.html"> ISO 8601 </a> format:
     *        <code>YYYY-MM-DDThh:mm:ss.sssZ</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public VerifyDevicePositionResult withReceivedTime(java.util.Date receivedTime) {
        setReceivedTime(receivedTime);
        return this;
    }

    /**
     * <p>
     * The distance unit for the verification response.
     * </p>
     * 
     * @param distanceUnit
     *        The distance unit for the verification response.
     * @see DistanceUnit
     */

    public void setDistanceUnit(String distanceUnit) {
        this.distanceUnit = distanceUnit;
    }

    /**
     * <p>
     * The distance unit for the verification response.
     * </p>
     * 
     * @return The distance unit for the verification response.
     * @see DistanceUnit
     */

    public String getDistanceUnit() {
        return this.distanceUnit;
    }

    /**
     * <p>
     * The distance unit for the verification response.
     * </p>
     * 
     * @param distanceUnit
     *        The distance unit for the verification response.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see DistanceUnit
     */

    public VerifyDevicePositionResult withDistanceUnit(String distanceUnit) {
        setDistanceUnit(distanceUnit);
        return this;
    }

    /**
     * <p>
     * The distance unit for the verification response.
     * </p>
     * 
     * @param distanceUnit
     *        The distance unit for the verification response.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see DistanceUnit
     */

    public VerifyDevicePositionResult withDistanceUnit(DistanceUnit distanceUnit) {
        this.distanceUnit = distanceUnit.toString();
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
        if (getInferredState() != null)
            sb.append("InferredState: ").append(getInferredState()).append(",");
        if (getDeviceId() != null)
            sb.append("DeviceId: ").append(getDeviceId()).append(",");
        if (getSampleTime() != null)
            sb.append("SampleTime: ").append(getSampleTime()).append(",");
        if (getReceivedTime() != null)
            sb.append("ReceivedTime: ").append(getReceivedTime()).append(",");
        if (getDistanceUnit() != null)
            sb.append("DistanceUnit: ").append(getDistanceUnit());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof VerifyDevicePositionResult == false)
            return false;
        VerifyDevicePositionResult other = (VerifyDevicePositionResult) obj;
        if (other.getInferredState() == null ^ this.getInferredState() == null)
            return false;
        if (other.getInferredState() != null && other.getInferredState().equals(this.getInferredState()) == false)
            return false;
        if (other.getDeviceId() == null ^ this.getDeviceId() == null)
            return false;
        if (other.getDeviceId() != null && other.getDeviceId().equals(this.getDeviceId()) == false)
            return false;
        if (other.getSampleTime() == null ^ this.getSampleTime() == null)
            return false;
        if (other.getSampleTime() != null && other.getSampleTime().equals(this.getSampleTime()) == false)
            return false;
        if (other.getReceivedTime() == null ^ this.getReceivedTime() == null)
            return false;
        if (other.getReceivedTime() != null && other.getReceivedTime().equals(this.getReceivedTime()) == false)
            return false;
        if (other.getDistanceUnit() == null ^ this.getDistanceUnit() == null)
            return false;
        if (other.getDistanceUnit() != null && other.getDistanceUnit().equals(this.getDistanceUnit()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getInferredState() == null) ? 0 : getInferredState().hashCode());
        hashCode = prime * hashCode + ((getDeviceId() == null) ? 0 : getDeviceId().hashCode());
        hashCode = prime * hashCode + ((getSampleTime() == null) ? 0 : getSampleTime().hashCode());
        hashCode = prime * hashCode + ((getReceivedTime() == null) ? 0 : getReceivedTime().hashCode());
        hashCode = prime * hashCode + ((getDistanceUnit() == null) ? 0 : getDistanceUnit().hashCode());
        return hashCode;
    }

    @Override
    public VerifyDevicePositionResult clone() {
        try {
            return (VerifyDevicePositionResult) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

}
