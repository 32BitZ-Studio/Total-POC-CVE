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

import com.amazonaws.AmazonWebServiceRequest;

/**
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/location-2020-11-19/VerifyDevicePosition" target="_top">AWS API
 *      Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class VerifyDevicePositionRequest extends com.amazonaws.AmazonWebServiceRequest implements Serializable, Cloneable {

    /**
     * <p>
     * The name of the tracker resource to be associated with verification request.
     * </p>
     */
    private String trackerName;
    /**
     * <p>
     * The device's state, including position, IP address, cell signals and Wi-Fi access points.
     * </p>
     */
    private DeviceState deviceState;
    /**
     * <p>
     * The distance unit for the verification request.
     * </p>
     * <p>
     * Default Value: <code>Kilometers</code>
     * </p>
     */
    private String distanceUnit;

    /**
     * <p>
     * The name of the tracker resource to be associated with verification request.
     * </p>
     * 
     * @param trackerName
     *        The name of the tracker resource to be associated with verification request.
     */

    public void setTrackerName(String trackerName) {
        this.trackerName = trackerName;
    }

    /**
     * <p>
     * The name of the tracker resource to be associated with verification request.
     * </p>
     * 
     * @return The name of the tracker resource to be associated with verification request.
     */

    public String getTrackerName() {
        return this.trackerName;
    }

    /**
     * <p>
     * The name of the tracker resource to be associated with verification request.
     * </p>
     * 
     * @param trackerName
     *        The name of the tracker resource to be associated with verification request.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public VerifyDevicePositionRequest withTrackerName(String trackerName) {
        setTrackerName(trackerName);
        return this;
    }

    /**
     * <p>
     * The device's state, including position, IP address, cell signals and Wi-Fi access points.
     * </p>
     * 
     * @param deviceState
     *        The device's state, including position, IP address, cell signals and Wi-Fi access points.
     */

    public void setDeviceState(DeviceState deviceState) {
        this.deviceState = deviceState;
    }

    /**
     * <p>
     * The device's state, including position, IP address, cell signals and Wi-Fi access points.
     * </p>
     * 
     * @return The device's state, including position, IP address, cell signals and Wi-Fi access points.
     */

    public DeviceState getDeviceState() {
        return this.deviceState;
    }

    /**
     * <p>
     * The device's state, including position, IP address, cell signals and Wi-Fi access points.
     * </p>
     * 
     * @param deviceState
     *        The device's state, including position, IP address, cell signals and Wi-Fi access points.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public VerifyDevicePositionRequest withDeviceState(DeviceState deviceState) {
        setDeviceState(deviceState);
        return this;
    }

    /**
     * <p>
     * The distance unit for the verification request.
     * </p>
     * <p>
     * Default Value: <code>Kilometers</code>
     * </p>
     * 
     * @param distanceUnit
     *        The distance unit for the verification request.</p>
     *        <p>
     *        Default Value: <code>Kilometers</code>
     * @see DistanceUnit
     */

    public void setDistanceUnit(String distanceUnit) {
        this.distanceUnit = distanceUnit;
    }

    /**
     * <p>
     * The distance unit for the verification request.
     * </p>
     * <p>
     * Default Value: <code>Kilometers</code>
     * </p>
     * 
     * @return The distance unit for the verification request.</p>
     *         <p>
     *         Default Value: <code>Kilometers</code>
     * @see DistanceUnit
     */

    public String getDistanceUnit() {
        return this.distanceUnit;
    }

    /**
     * <p>
     * The distance unit for the verification request.
     * </p>
     * <p>
     * Default Value: <code>Kilometers</code>
     * </p>
     * 
     * @param distanceUnit
     *        The distance unit for the verification request.</p>
     *        <p>
     *        Default Value: <code>Kilometers</code>
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see DistanceUnit
     */

    public VerifyDevicePositionRequest withDistanceUnit(String distanceUnit) {
        setDistanceUnit(distanceUnit);
        return this;
    }

    /**
     * <p>
     * The distance unit for the verification request.
     * </p>
     * <p>
     * Default Value: <code>Kilometers</code>
     * </p>
     * 
     * @param distanceUnit
     *        The distance unit for the verification request.</p>
     *        <p>
     *        Default Value: <code>Kilometers</code>
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see DistanceUnit
     */

    public VerifyDevicePositionRequest withDistanceUnit(DistanceUnit distanceUnit) {
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
        if (getTrackerName() != null)
            sb.append("TrackerName: ").append(getTrackerName()).append(",");
        if (getDeviceState() != null)
            sb.append("DeviceState: ").append(getDeviceState()).append(",");
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

        if (obj instanceof VerifyDevicePositionRequest == false)
            return false;
        VerifyDevicePositionRequest other = (VerifyDevicePositionRequest) obj;
        if (other.getTrackerName() == null ^ this.getTrackerName() == null)
            return false;
        if (other.getTrackerName() != null && other.getTrackerName().equals(this.getTrackerName()) == false)
            return false;
        if (other.getDeviceState() == null ^ this.getDeviceState() == null)
            return false;
        if (other.getDeviceState() != null && other.getDeviceState().equals(this.getDeviceState()) == false)
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

        hashCode = prime * hashCode + ((getTrackerName() == null) ? 0 : getTrackerName().hashCode());
        hashCode = prime * hashCode + ((getDeviceState() == null) ? 0 : getDeviceState().hashCode());
        hashCode = prime * hashCode + ((getDistanceUnit() == null) ? 0 : getDistanceUnit().hashCode());
        return hashCode;
    }

    @Override
    public VerifyDevicePositionRequest clone() {
        return (VerifyDevicePositionRequest) super.clone();
    }

}
