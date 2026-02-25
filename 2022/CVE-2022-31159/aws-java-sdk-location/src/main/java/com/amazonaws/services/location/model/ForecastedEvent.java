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
 * A forecasted event represents a geofence event in relation to the requested device state, that may occur given the
 * provided device state and time horizon.
 * </p>
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/location-2020-11-19/ForecastedEvent" target="_top">AWS API
 *      Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class ForecastedEvent implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * The forecasted event identifier.
     * </p>
     */
    private String eventId;
    /**
     * <p>
     * The geofence identifier pertaining to the forecasted event.
     * </p>
     */
    private String geofenceId;
    /**
     * <p>
     * Indicates if the device is located within the geofence.
     * </p>
     */
    private Boolean isDeviceInGeofence;
    /**
     * <p>
     * The closest distance from the device's position to the geofence.
     * </p>
     */
    private Double nearestDistance;
    /**
     * <p>
     * The event type, forecasting three states for which a device can be in relative to a geofence:
     * </p>
     * <p>
     * <code>ENTER</code>: If a device is outside of a geofence, but would breach the fence if the device is moving at
     * its current speed within time horizon window.
     * </p>
     * <p>
     * <code>EXIT</code>: If a device is inside of a geofence, but would breach the fence if the device is moving at its
     * current speed within time horizon window.
     * </p>
     * <p>
     * <code>IDLE</code>: If a device is inside of a geofence, and the device is not moving.
     * </p>
     */
    private String eventType;
    /**
     * <p>
     * The forecasted time the device will breach the geofence in <a
     * href="https://www.iso.org/iso-8601-date-and-time-format.html">ISO 8601</a> format:
     * <code>YYYY-MM-DDThh:mm:ss.sssZ</code>
     * </p>
     */
    private java.util.Date forecastedBreachTime;
    /**
     * <p>
     * The geofence properties.
     * </p>
     */
    private java.util.Map<String, String> geofenceProperties;

    /**
     * <p>
     * The forecasted event identifier.
     * </p>
     * 
     * @param eventId
     *        The forecasted event identifier.
     */

    public void setEventId(String eventId) {
        this.eventId = eventId;
    }

    /**
     * <p>
     * The forecasted event identifier.
     * </p>
     * 
     * @return The forecasted event identifier.
     */

    public String getEventId() {
        return this.eventId;
    }

    /**
     * <p>
     * The forecasted event identifier.
     * </p>
     * 
     * @param eventId
     *        The forecasted event identifier.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ForecastedEvent withEventId(String eventId) {
        setEventId(eventId);
        return this;
    }

    /**
     * <p>
     * The geofence identifier pertaining to the forecasted event.
     * </p>
     * 
     * @param geofenceId
     *        The geofence identifier pertaining to the forecasted event.
     */

    public void setGeofenceId(String geofenceId) {
        this.geofenceId = geofenceId;
    }

    /**
     * <p>
     * The geofence identifier pertaining to the forecasted event.
     * </p>
     * 
     * @return The geofence identifier pertaining to the forecasted event.
     */

    public String getGeofenceId() {
        return this.geofenceId;
    }

    /**
     * <p>
     * The geofence identifier pertaining to the forecasted event.
     * </p>
     * 
     * @param geofenceId
     *        The geofence identifier pertaining to the forecasted event.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ForecastedEvent withGeofenceId(String geofenceId) {
        setGeofenceId(geofenceId);
        return this;
    }

    /**
     * <p>
     * Indicates if the device is located within the geofence.
     * </p>
     * 
     * @param isDeviceInGeofence
     *        Indicates if the device is located within the geofence.
     */

    public void setIsDeviceInGeofence(Boolean isDeviceInGeofence) {
        this.isDeviceInGeofence = isDeviceInGeofence;
    }

    /**
     * <p>
     * Indicates if the device is located within the geofence.
     * </p>
     * 
     * @return Indicates if the device is located within the geofence.
     */

    public Boolean getIsDeviceInGeofence() {
        return this.isDeviceInGeofence;
    }

    /**
     * <p>
     * Indicates if the device is located within the geofence.
     * </p>
     * 
     * @param isDeviceInGeofence
     *        Indicates if the device is located within the geofence.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ForecastedEvent withIsDeviceInGeofence(Boolean isDeviceInGeofence) {
        setIsDeviceInGeofence(isDeviceInGeofence);
        return this;
    }

    /**
     * <p>
     * Indicates if the device is located within the geofence.
     * </p>
     * 
     * @return Indicates if the device is located within the geofence.
     */

    public Boolean isDeviceInGeofence() {
        return this.isDeviceInGeofence;
    }

    /**
     * <p>
     * The closest distance from the device's position to the geofence.
     * </p>
     * 
     * @param nearestDistance
     *        The closest distance from the device's position to the geofence.
     */

    public void setNearestDistance(Double nearestDistance) {
        this.nearestDistance = nearestDistance;
    }

    /**
     * <p>
     * The closest distance from the device's position to the geofence.
     * </p>
     * 
     * @return The closest distance from the device's position to the geofence.
     */

    public Double getNearestDistance() {
        return this.nearestDistance;
    }

    /**
     * <p>
     * The closest distance from the device's position to the geofence.
     * </p>
     * 
     * @param nearestDistance
     *        The closest distance from the device's position to the geofence.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ForecastedEvent withNearestDistance(Double nearestDistance) {
        setNearestDistance(nearestDistance);
        return this;
    }

    /**
     * <p>
     * The event type, forecasting three states for which a device can be in relative to a geofence:
     * </p>
     * <p>
     * <code>ENTER</code>: If a device is outside of a geofence, but would breach the fence if the device is moving at
     * its current speed within time horizon window.
     * </p>
     * <p>
     * <code>EXIT</code>: If a device is inside of a geofence, but would breach the fence if the device is moving at its
     * current speed within time horizon window.
     * </p>
     * <p>
     * <code>IDLE</code>: If a device is inside of a geofence, and the device is not moving.
     * </p>
     * 
     * @param eventType
     *        The event type, forecasting three states for which a device can be in relative to a geofence:</p>
     *        <p>
     *        <code>ENTER</code>: If a device is outside of a geofence, but would breach the fence if the device is
     *        moving at its current speed within time horizon window.
     *        </p>
     *        <p>
     *        <code>EXIT</code>: If a device is inside of a geofence, but would breach the fence if the device is moving
     *        at its current speed within time horizon window.
     *        </p>
     *        <p>
     *        <code>IDLE</code>: If a device is inside of a geofence, and the device is not moving.
     * @see ForecastedGeofenceEventType
     */

    public void setEventType(String eventType) {
        this.eventType = eventType;
    }

    /**
     * <p>
     * The event type, forecasting three states for which a device can be in relative to a geofence:
     * </p>
     * <p>
     * <code>ENTER</code>: If a device is outside of a geofence, but would breach the fence if the device is moving at
     * its current speed within time horizon window.
     * </p>
     * <p>
     * <code>EXIT</code>: If a device is inside of a geofence, but would breach the fence if the device is moving at its
     * current speed within time horizon window.
     * </p>
     * <p>
     * <code>IDLE</code>: If a device is inside of a geofence, and the device is not moving.
     * </p>
     * 
     * @return The event type, forecasting three states for which a device can be in relative to a geofence:</p>
     *         <p>
     *         <code>ENTER</code>: If a device is outside of a geofence, but would breach the fence if the device is
     *         moving at its current speed within time horizon window.
     *         </p>
     *         <p>
     *         <code>EXIT</code>: If a device is inside of a geofence, but would breach the fence if the device is
     *         moving at its current speed within time horizon window.
     *         </p>
     *         <p>
     *         <code>IDLE</code>: If a device is inside of a geofence, and the device is not moving.
     * @see ForecastedGeofenceEventType
     */

    public String getEventType() {
        return this.eventType;
    }

    /**
     * <p>
     * The event type, forecasting three states for which a device can be in relative to a geofence:
     * </p>
     * <p>
     * <code>ENTER</code>: If a device is outside of a geofence, but would breach the fence if the device is moving at
     * its current speed within time horizon window.
     * </p>
     * <p>
     * <code>EXIT</code>: If a device is inside of a geofence, but would breach the fence if the device is moving at its
     * current speed within time horizon window.
     * </p>
     * <p>
     * <code>IDLE</code>: If a device is inside of a geofence, and the device is not moving.
     * </p>
     * 
     * @param eventType
     *        The event type, forecasting three states for which a device can be in relative to a geofence:</p>
     *        <p>
     *        <code>ENTER</code>: If a device is outside of a geofence, but would breach the fence if the device is
     *        moving at its current speed within time horizon window.
     *        </p>
     *        <p>
     *        <code>EXIT</code>: If a device is inside of a geofence, but would breach the fence if the device is moving
     *        at its current speed within time horizon window.
     *        </p>
     *        <p>
     *        <code>IDLE</code>: If a device is inside of a geofence, and the device is not moving.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see ForecastedGeofenceEventType
     */

    public ForecastedEvent withEventType(String eventType) {
        setEventType(eventType);
        return this;
    }

    /**
     * <p>
     * The event type, forecasting three states for which a device can be in relative to a geofence:
     * </p>
     * <p>
     * <code>ENTER</code>: If a device is outside of a geofence, but would breach the fence if the device is moving at
     * its current speed within time horizon window.
     * </p>
     * <p>
     * <code>EXIT</code>: If a device is inside of a geofence, but would breach the fence if the device is moving at its
     * current speed within time horizon window.
     * </p>
     * <p>
     * <code>IDLE</code>: If a device is inside of a geofence, and the device is not moving.
     * </p>
     * 
     * @param eventType
     *        The event type, forecasting three states for which a device can be in relative to a geofence:</p>
     *        <p>
     *        <code>ENTER</code>: If a device is outside of a geofence, but would breach the fence if the device is
     *        moving at its current speed within time horizon window.
     *        </p>
     *        <p>
     *        <code>EXIT</code>: If a device is inside of a geofence, but would breach the fence if the device is moving
     *        at its current speed within time horizon window.
     *        </p>
     *        <p>
     *        <code>IDLE</code>: If a device is inside of a geofence, and the device is not moving.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see ForecastedGeofenceEventType
     */

    public ForecastedEvent withEventType(ForecastedGeofenceEventType eventType) {
        this.eventType = eventType.toString();
        return this;
    }

    /**
     * <p>
     * The forecasted time the device will breach the geofence in <a
     * href="https://www.iso.org/iso-8601-date-and-time-format.html">ISO 8601</a> format:
     * <code>YYYY-MM-DDThh:mm:ss.sssZ</code>
     * </p>
     * 
     * @param forecastedBreachTime
     *        The forecasted time the device will breach the geofence in <a
     *        href="https://www.iso.org/iso-8601-date-and-time-format.html">ISO 8601</a> format:
     *        <code>YYYY-MM-DDThh:mm:ss.sssZ</code>
     */

    public void setForecastedBreachTime(java.util.Date forecastedBreachTime) {
        this.forecastedBreachTime = forecastedBreachTime;
    }

    /**
     * <p>
     * The forecasted time the device will breach the geofence in <a
     * href="https://www.iso.org/iso-8601-date-and-time-format.html">ISO 8601</a> format:
     * <code>YYYY-MM-DDThh:mm:ss.sssZ</code>
     * </p>
     * 
     * @return The forecasted time the device will breach the geofence in <a
     *         href="https://www.iso.org/iso-8601-date-and-time-format.html">ISO 8601</a> format:
     *         <code>YYYY-MM-DDThh:mm:ss.sssZ</code>
     */

    public java.util.Date getForecastedBreachTime() {
        return this.forecastedBreachTime;
    }

    /**
     * <p>
     * The forecasted time the device will breach the geofence in <a
     * href="https://www.iso.org/iso-8601-date-and-time-format.html">ISO 8601</a> format:
     * <code>YYYY-MM-DDThh:mm:ss.sssZ</code>
     * </p>
     * 
     * @param forecastedBreachTime
     *        The forecasted time the device will breach the geofence in <a
     *        href="https://www.iso.org/iso-8601-date-and-time-format.html">ISO 8601</a> format:
     *        <code>YYYY-MM-DDThh:mm:ss.sssZ</code>
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ForecastedEvent withForecastedBreachTime(java.util.Date forecastedBreachTime) {
        setForecastedBreachTime(forecastedBreachTime);
        return this;
    }

    /**
     * <p>
     * The geofence properties.
     * </p>
     * 
     * @return The geofence properties.
     */

    public java.util.Map<String, String> getGeofenceProperties() {
        return geofenceProperties;
    }

    /**
     * <p>
     * The geofence properties.
     * </p>
     * 
     * @param geofenceProperties
     *        The geofence properties.
     */

    public void setGeofenceProperties(java.util.Map<String, String> geofenceProperties) {
        this.geofenceProperties = geofenceProperties;
    }

    /**
     * <p>
     * The geofence properties.
     * </p>
     * 
     * @param geofenceProperties
     *        The geofence properties.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ForecastedEvent withGeofenceProperties(java.util.Map<String, String> geofenceProperties) {
        setGeofenceProperties(geofenceProperties);
        return this;
    }

    /**
     * Add a single GeofenceProperties entry
     *
     * @see ForecastedEvent#withGeofenceProperties
     * @returns a reference to this object so that method calls can be chained together.
     */

    public ForecastedEvent addGeofencePropertiesEntry(String key, String value) {
        if (null == this.geofenceProperties) {
            this.geofenceProperties = new java.util.HashMap<String, String>();
        }
        if (this.geofenceProperties.containsKey(key))
            throw new IllegalArgumentException("Duplicated keys (" + key.toString() + ") are provided.");
        this.geofenceProperties.put(key, value);
        return this;
    }

    /**
     * Removes all the entries added into GeofenceProperties.
     *
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ForecastedEvent clearGeofencePropertiesEntries() {
        this.geofenceProperties = null;
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
        if (getEventId() != null)
            sb.append("EventId: ").append(getEventId()).append(",");
        if (getGeofenceId() != null)
            sb.append("GeofenceId: ").append(getGeofenceId()).append(",");
        if (getIsDeviceInGeofence() != null)
            sb.append("IsDeviceInGeofence: ").append(getIsDeviceInGeofence()).append(",");
        if (getNearestDistance() != null)
            sb.append("NearestDistance: ").append(getNearestDistance()).append(",");
        if (getEventType() != null)
            sb.append("EventType: ").append(getEventType()).append(",");
        if (getForecastedBreachTime() != null)
            sb.append("ForecastedBreachTime: ").append(getForecastedBreachTime()).append(",");
        if (getGeofenceProperties() != null)
            sb.append("GeofenceProperties: ").append("***Sensitive Data Redacted***");
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof ForecastedEvent == false)
            return false;
        ForecastedEvent other = (ForecastedEvent) obj;
        if (other.getEventId() == null ^ this.getEventId() == null)
            return false;
        if (other.getEventId() != null && other.getEventId().equals(this.getEventId()) == false)
            return false;
        if (other.getGeofenceId() == null ^ this.getGeofenceId() == null)
            return false;
        if (other.getGeofenceId() != null && other.getGeofenceId().equals(this.getGeofenceId()) == false)
            return false;
        if (other.getIsDeviceInGeofence() == null ^ this.getIsDeviceInGeofence() == null)
            return false;
        if (other.getIsDeviceInGeofence() != null && other.getIsDeviceInGeofence().equals(this.getIsDeviceInGeofence()) == false)
            return false;
        if (other.getNearestDistance() == null ^ this.getNearestDistance() == null)
            return false;
        if (other.getNearestDistance() != null && other.getNearestDistance().equals(this.getNearestDistance()) == false)
            return false;
        if (other.getEventType() == null ^ this.getEventType() == null)
            return false;
        if (other.getEventType() != null && other.getEventType().equals(this.getEventType()) == false)
            return false;
        if (other.getForecastedBreachTime() == null ^ this.getForecastedBreachTime() == null)
            return false;
        if (other.getForecastedBreachTime() != null && other.getForecastedBreachTime().equals(this.getForecastedBreachTime()) == false)
            return false;
        if (other.getGeofenceProperties() == null ^ this.getGeofenceProperties() == null)
            return false;
        if (other.getGeofenceProperties() != null && other.getGeofenceProperties().equals(this.getGeofenceProperties()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getEventId() == null) ? 0 : getEventId().hashCode());
        hashCode = prime * hashCode + ((getGeofenceId() == null) ? 0 : getGeofenceId().hashCode());
        hashCode = prime * hashCode + ((getIsDeviceInGeofence() == null) ? 0 : getIsDeviceInGeofence().hashCode());
        hashCode = prime * hashCode + ((getNearestDistance() == null) ? 0 : getNearestDistance().hashCode());
        hashCode = prime * hashCode + ((getEventType() == null) ? 0 : getEventType().hashCode());
        hashCode = prime * hashCode + ((getForecastedBreachTime() == null) ? 0 : getForecastedBreachTime().hashCode());
        hashCode = prime * hashCode + ((getGeofenceProperties() == null) ? 0 : getGeofenceProperties().hashCode());
        return hashCode;
    }

    @Override
    public ForecastedEvent clone() {
        try {
            return (ForecastedEvent) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.location.model.transform.ForecastedEventMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
