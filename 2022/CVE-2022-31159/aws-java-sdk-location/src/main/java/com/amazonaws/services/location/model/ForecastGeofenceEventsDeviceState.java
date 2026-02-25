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
 * The device's position, IP address, and WiFi access points.
 * </p>
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/location-2020-11-19/ForecastGeofenceEventsDeviceState"
 *      target="_top">AWS API Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class ForecastGeofenceEventsDeviceState implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * The device's position.
     * </p>
     */
    private java.util.List<Double> position;
    /**
     * <p>
     * The device's speed.
     * </p>
     */
    private Double speed;

    /**
     * <p>
     * The device's position.
     * </p>
     * 
     * @return The device's position.
     */

    public java.util.List<Double> getPosition() {
        return position;
    }

    /**
     * <p>
     * The device's position.
     * </p>
     * 
     * @param position
     *        The device's position.
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
     * The device's position.
     * </p>
     * <p>
     * <b>NOTE:</b> This method appends the values to the existing list (if any). Use
     * {@link #setPosition(java.util.Collection)} or {@link #withPosition(java.util.Collection)} if you want to override
     * the existing values.
     * </p>
     * 
     * @param position
     *        The device's position.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ForecastGeofenceEventsDeviceState withPosition(Double... position) {
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
     * The device's position.
     * </p>
     * 
     * @param position
     *        The device's position.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ForecastGeofenceEventsDeviceState withPosition(java.util.Collection<Double> position) {
        setPosition(position);
        return this;
    }

    /**
     * <p>
     * The device's speed.
     * </p>
     * 
     * @param speed
     *        The device's speed.
     */

    public void setSpeed(Double speed) {
        this.speed = speed;
    }

    /**
     * <p>
     * The device's speed.
     * </p>
     * 
     * @return The device's speed.
     */

    public Double getSpeed() {
        return this.speed;
    }

    /**
     * <p>
     * The device's speed.
     * </p>
     * 
     * @param speed
     *        The device's speed.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ForecastGeofenceEventsDeviceState withSpeed(Double speed) {
        setSpeed(speed);
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
        if (getPosition() != null)
            sb.append("Position: ").append("***Sensitive Data Redacted***").append(",");
        if (getSpeed() != null)
            sb.append("Speed: ").append(getSpeed());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof ForecastGeofenceEventsDeviceState == false)
            return false;
        ForecastGeofenceEventsDeviceState other = (ForecastGeofenceEventsDeviceState) obj;
        if (other.getPosition() == null ^ this.getPosition() == null)
            return false;
        if (other.getPosition() != null && other.getPosition().equals(this.getPosition()) == false)
            return false;
        if (other.getSpeed() == null ^ this.getSpeed() == null)
            return false;
        if (other.getSpeed() != null && other.getSpeed().equals(this.getSpeed()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getPosition() == null) ? 0 : getPosition().hashCode());
        hashCode = prime * hashCode + ((getSpeed() == null) ? 0 : getSpeed().hashCode());
        return hashCode;
    }

    @Override
    public ForecastGeofenceEventsDeviceState clone() {
        try {
            return (ForecastGeofenceEventsDeviceState) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.location.model.transform.ForecastGeofenceEventsDeviceStateMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
