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
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/location-2020-11-19/ForecastGeofenceEvents" target="_top">AWS
 *      API Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class ForecastGeofenceEventsRequest extends com.amazonaws.AmazonWebServiceRequest implements Serializable, Cloneable {

    /**
     * <p>
     * The name of the geofence collection.
     * </p>
     */
    private String collectionName;
    /**
     * <p>
     * The device's state, including current position and speed.
     * </p>
     */
    private ForecastGeofenceEventsDeviceState deviceState;
    /**
     * <p>
     * Specifies the time horizon in minutes for the forecasted events.
     * </p>
     */
    private Double timeHorizonMinutes;
    /**
     * <p>
     * The distance unit used for the <code>NearestDistance</code> property returned in a forecasted event. The
     * measurement system must match for <code>DistanceUnit</code> and <code>SpeedUnit</code>; if
     * <code>Kilometers</code> is specified for <code>DistanceUnit</code>, then <code>SpeedUnit</code> must be
     * <code>KilometersPerHour</code>.
     * </p>
     * <p>
     * Default Value: <code>Kilometers</code>
     * </p>
     */
    private String distanceUnit;
    /**
     * <p>
     * The speed unit for the device captured by the device state. The measurement system must match for
     * <code>DistanceUnit</code> and <code>SpeedUnit</code>; if <code>Kilometers</code> is specified for
     * <code>DistanceUnit</code>, then <code>SpeedUnit</code> must be <code>KilometersPerHour</code>.
     * </p>
     * <p>
     * Default Value: <code>KilometersPerHour</code>.
     * </p>
     */
    private String speedUnit;
    /**
     * <p>
     * The pagination token specifying which page of results to return in the response. If no token is provided, the
     * default page is the first page.
     * </p>
     * <p>
     * Default value: <code>null</code>
     * </p>
     */
    private String nextToken;
    /**
     * <p>
     * An optional limit for the number of resources returned in a single call.
     * </p>
     * <p>
     * Default value: <code>20</code>
     * </p>
     */
    private Integer maxResults;

    /**
     * <p>
     * The name of the geofence collection.
     * </p>
     * 
     * @param collectionName
     *        The name of the geofence collection.
     */

    public void setCollectionName(String collectionName) {
        this.collectionName = collectionName;
    }

    /**
     * <p>
     * The name of the geofence collection.
     * </p>
     * 
     * @return The name of the geofence collection.
     */

    public String getCollectionName() {
        return this.collectionName;
    }

    /**
     * <p>
     * The name of the geofence collection.
     * </p>
     * 
     * @param collectionName
     *        The name of the geofence collection.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ForecastGeofenceEventsRequest withCollectionName(String collectionName) {
        setCollectionName(collectionName);
        return this;
    }

    /**
     * <p>
     * The device's state, including current position and speed.
     * </p>
     * 
     * @param deviceState
     *        The device's state, including current position and speed.
     */

    public void setDeviceState(ForecastGeofenceEventsDeviceState deviceState) {
        this.deviceState = deviceState;
    }

    /**
     * <p>
     * The device's state, including current position and speed.
     * </p>
     * 
     * @return The device's state, including current position and speed.
     */

    public ForecastGeofenceEventsDeviceState getDeviceState() {
        return this.deviceState;
    }

    /**
     * <p>
     * The device's state, including current position and speed.
     * </p>
     * 
     * @param deviceState
     *        The device's state, including current position and speed.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ForecastGeofenceEventsRequest withDeviceState(ForecastGeofenceEventsDeviceState deviceState) {
        setDeviceState(deviceState);
        return this;
    }

    /**
     * <p>
     * Specifies the time horizon in minutes for the forecasted events.
     * </p>
     * 
     * @param timeHorizonMinutes
     *        Specifies the time horizon in minutes for the forecasted events.
     */

    public void setTimeHorizonMinutes(Double timeHorizonMinutes) {
        this.timeHorizonMinutes = timeHorizonMinutes;
    }

    /**
     * <p>
     * Specifies the time horizon in minutes for the forecasted events.
     * </p>
     * 
     * @return Specifies the time horizon in minutes for the forecasted events.
     */

    public Double getTimeHorizonMinutes() {
        return this.timeHorizonMinutes;
    }

    /**
     * <p>
     * Specifies the time horizon in minutes for the forecasted events.
     * </p>
     * 
     * @param timeHorizonMinutes
     *        Specifies the time horizon in minutes for the forecasted events.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ForecastGeofenceEventsRequest withTimeHorizonMinutes(Double timeHorizonMinutes) {
        setTimeHorizonMinutes(timeHorizonMinutes);
        return this;
    }

    /**
     * <p>
     * The distance unit used for the <code>NearestDistance</code> property returned in a forecasted event. The
     * measurement system must match for <code>DistanceUnit</code> and <code>SpeedUnit</code>; if
     * <code>Kilometers</code> is specified for <code>DistanceUnit</code>, then <code>SpeedUnit</code> must be
     * <code>KilometersPerHour</code>.
     * </p>
     * <p>
     * Default Value: <code>Kilometers</code>
     * </p>
     * 
     * @param distanceUnit
     *        The distance unit used for the <code>NearestDistance</code> property returned in a forecasted event. The
     *        measurement system must match for <code>DistanceUnit</code> and <code>SpeedUnit</code>; if
     *        <code>Kilometers</code> is specified for <code>DistanceUnit</code>, then <code>SpeedUnit</code> must be
     *        <code>KilometersPerHour</code>. </p>
     *        <p>
     *        Default Value: <code>Kilometers</code>
     * @see DistanceUnit
     */

    public void setDistanceUnit(String distanceUnit) {
        this.distanceUnit = distanceUnit;
    }

    /**
     * <p>
     * The distance unit used for the <code>NearestDistance</code> property returned in a forecasted event. The
     * measurement system must match for <code>DistanceUnit</code> and <code>SpeedUnit</code>; if
     * <code>Kilometers</code> is specified for <code>DistanceUnit</code>, then <code>SpeedUnit</code> must be
     * <code>KilometersPerHour</code>.
     * </p>
     * <p>
     * Default Value: <code>Kilometers</code>
     * </p>
     * 
     * @return The distance unit used for the <code>NearestDistance</code> property returned in a forecasted event. The
     *         measurement system must match for <code>DistanceUnit</code> and <code>SpeedUnit</code>; if
     *         <code>Kilometers</code> is specified for <code>DistanceUnit</code>, then <code>SpeedUnit</code> must be
     *         <code>KilometersPerHour</code>. </p>
     *         <p>
     *         Default Value: <code>Kilometers</code>
     * @see DistanceUnit
     */

    public String getDistanceUnit() {
        return this.distanceUnit;
    }

    /**
     * <p>
     * The distance unit used for the <code>NearestDistance</code> property returned in a forecasted event. The
     * measurement system must match for <code>DistanceUnit</code> and <code>SpeedUnit</code>; if
     * <code>Kilometers</code> is specified for <code>DistanceUnit</code>, then <code>SpeedUnit</code> must be
     * <code>KilometersPerHour</code>.
     * </p>
     * <p>
     * Default Value: <code>Kilometers</code>
     * </p>
     * 
     * @param distanceUnit
     *        The distance unit used for the <code>NearestDistance</code> property returned in a forecasted event. The
     *        measurement system must match for <code>DistanceUnit</code> and <code>SpeedUnit</code>; if
     *        <code>Kilometers</code> is specified for <code>DistanceUnit</code>, then <code>SpeedUnit</code> must be
     *        <code>KilometersPerHour</code>. </p>
     *        <p>
     *        Default Value: <code>Kilometers</code>
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see DistanceUnit
     */

    public ForecastGeofenceEventsRequest withDistanceUnit(String distanceUnit) {
        setDistanceUnit(distanceUnit);
        return this;
    }

    /**
     * <p>
     * The distance unit used for the <code>NearestDistance</code> property returned in a forecasted event. The
     * measurement system must match for <code>DistanceUnit</code> and <code>SpeedUnit</code>; if
     * <code>Kilometers</code> is specified for <code>DistanceUnit</code>, then <code>SpeedUnit</code> must be
     * <code>KilometersPerHour</code>.
     * </p>
     * <p>
     * Default Value: <code>Kilometers</code>
     * </p>
     * 
     * @param distanceUnit
     *        The distance unit used for the <code>NearestDistance</code> property returned in a forecasted event. The
     *        measurement system must match for <code>DistanceUnit</code> and <code>SpeedUnit</code>; if
     *        <code>Kilometers</code> is specified for <code>DistanceUnit</code>, then <code>SpeedUnit</code> must be
     *        <code>KilometersPerHour</code>. </p>
     *        <p>
     *        Default Value: <code>Kilometers</code>
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see DistanceUnit
     */

    public ForecastGeofenceEventsRequest withDistanceUnit(DistanceUnit distanceUnit) {
        this.distanceUnit = distanceUnit.toString();
        return this;
    }

    /**
     * <p>
     * The speed unit for the device captured by the device state. The measurement system must match for
     * <code>DistanceUnit</code> and <code>SpeedUnit</code>; if <code>Kilometers</code> is specified for
     * <code>DistanceUnit</code>, then <code>SpeedUnit</code> must be <code>KilometersPerHour</code>.
     * </p>
     * <p>
     * Default Value: <code>KilometersPerHour</code>.
     * </p>
     * 
     * @param speedUnit
     *        The speed unit for the device captured by the device state. The measurement system must match for
     *        <code>DistanceUnit</code> and <code>SpeedUnit</code>; if <code>Kilometers</code> is specified for
     *        <code>DistanceUnit</code>, then <code>SpeedUnit</code> must be <code>KilometersPerHour</code>.</p>
     *        <p>
     *        Default Value: <code>KilometersPerHour</code>.
     * @see SpeedUnit
     */

    public void setSpeedUnit(String speedUnit) {
        this.speedUnit = speedUnit;
    }

    /**
     * <p>
     * The speed unit for the device captured by the device state. The measurement system must match for
     * <code>DistanceUnit</code> and <code>SpeedUnit</code>; if <code>Kilometers</code> is specified for
     * <code>DistanceUnit</code>, then <code>SpeedUnit</code> must be <code>KilometersPerHour</code>.
     * </p>
     * <p>
     * Default Value: <code>KilometersPerHour</code>.
     * </p>
     * 
     * @return The speed unit for the device captured by the device state. The measurement system must match for
     *         <code>DistanceUnit</code> and <code>SpeedUnit</code>; if <code>Kilometers</code> is specified for
     *         <code>DistanceUnit</code>, then <code>SpeedUnit</code> must be <code>KilometersPerHour</code>.</p>
     *         <p>
     *         Default Value: <code>KilometersPerHour</code>.
     * @see SpeedUnit
     */

    public String getSpeedUnit() {
        return this.speedUnit;
    }

    /**
     * <p>
     * The speed unit for the device captured by the device state. The measurement system must match for
     * <code>DistanceUnit</code> and <code>SpeedUnit</code>; if <code>Kilometers</code> is specified for
     * <code>DistanceUnit</code>, then <code>SpeedUnit</code> must be <code>KilometersPerHour</code>.
     * </p>
     * <p>
     * Default Value: <code>KilometersPerHour</code>.
     * </p>
     * 
     * @param speedUnit
     *        The speed unit for the device captured by the device state. The measurement system must match for
     *        <code>DistanceUnit</code> and <code>SpeedUnit</code>; if <code>Kilometers</code> is specified for
     *        <code>DistanceUnit</code>, then <code>SpeedUnit</code> must be <code>KilometersPerHour</code>.</p>
     *        <p>
     *        Default Value: <code>KilometersPerHour</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see SpeedUnit
     */

    public ForecastGeofenceEventsRequest withSpeedUnit(String speedUnit) {
        setSpeedUnit(speedUnit);
        return this;
    }

    /**
     * <p>
     * The speed unit for the device captured by the device state. The measurement system must match for
     * <code>DistanceUnit</code> and <code>SpeedUnit</code>; if <code>Kilometers</code> is specified for
     * <code>DistanceUnit</code>, then <code>SpeedUnit</code> must be <code>KilometersPerHour</code>.
     * </p>
     * <p>
     * Default Value: <code>KilometersPerHour</code>.
     * </p>
     * 
     * @param speedUnit
     *        The speed unit for the device captured by the device state. The measurement system must match for
     *        <code>DistanceUnit</code> and <code>SpeedUnit</code>; if <code>Kilometers</code> is specified for
     *        <code>DistanceUnit</code>, then <code>SpeedUnit</code> must be <code>KilometersPerHour</code>.</p>
     *        <p>
     *        Default Value: <code>KilometersPerHour</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see SpeedUnit
     */

    public ForecastGeofenceEventsRequest withSpeedUnit(SpeedUnit speedUnit) {
        this.speedUnit = speedUnit.toString();
        return this;
    }

    /**
     * <p>
     * The pagination token specifying which page of results to return in the response. If no token is provided, the
     * default page is the first page.
     * </p>
     * <p>
     * Default value: <code>null</code>
     * </p>
     * 
     * @param nextToken
     *        The pagination token specifying which page of results to return in the response. If no token is provided,
     *        the default page is the first page.</p>
     *        <p>
     *        Default value: <code>null</code>
     */

    public void setNextToken(String nextToken) {
        this.nextToken = nextToken;
    }

    /**
     * <p>
     * The pagination token specifying which page of results to return in the response. If no token is provided, the
     * default page is the first page.
     * </p>
     * <p>
     * Default value: <code>null</code>
     * </p>
     * 
     * @return The pagination token specifying which page of results to return in the response. If no token is provided,
     *         the default page is the first page.</p>
     *         <p>
     *         Default value: <code>null</code>
     */

    public String getNextToken() {
        return this.nextToken;
    }

    /**
     * <p>
     * The pagination token specifying which page of results to return in the response. If no token is provided, the
     * default page is the first page.
     * </p>
     * <p>
     * Default value: <code>null</code>
     * </p>
     * 
     * @param nextToken
     *        The pagination token specifying which page of results to return in the response. If no token is provided,
     *        the default page is the first page.</p>
     *        <p>
     *        Default value: <code>null</code>
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ForecastGeofenceEventsRequest withNextToken(String nextToken) {
        setNextToken(nextToken);
        return this;
    }

    /**
     * <p>
     * An optional limit for the number of resources returned in a single call.
     * </p>
     * <p>
     * Default value: <code>20</code>
     * </p>
     * 
     * @param maxResults
     *        An optional limit for the number of resources returned in a single call.</p>
     *        <p>
     *        Default value: <code>20</code>
     */

    public void setMaxResults(Integer maxResults) {
        this.maxResults = maxResults;
    }

    /**
     * <p>
     * An optional limit for the number of resources returned in a single call.
     * </p>
     * <p>
     * Default value: <code>20</code>
     * </p>
     * 
     * @return An optional limit for the number of resources returned in a single call.</p>
     *         <p>
     *         Default value: <code>20</code>
     */

    public Integer getMaxResults() {
        return this.maxResults;
    }

    /**
     * <p>
     * An optional limit for the number of resources returned in a single call.
     * </p>
     * <p>
     * Default value: <code>20</code>
     * </p>
     * 
     * @param maxResults
     *        An optional limit for the number of resources returned in a single call.</p>
     *        <p>
     *        Default value: <code>20</code>
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ForecastGeofenceEventsRequest withMaxResults(Integer maxResults) {
        setMaxResults(maxResults);
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
        if (getCollectionName() != null)
            sb.append("CollectionName: ").append(getCollectionName()).append(",");
        if (getDeviceState() != null)
            sb.append("DeviceState: ").append(getDeviceState()).append(",");
        if (getTimeHorizonMinutes() != null)
            sb.append("TimeHorizonMinutes: ").append(getTimeHorizonMinutes()).append(",");
        if (getDistanceUnit() != null)
            sb.append("DistanceUnit: ").append(getDistanceUnit()).append(",");
        if (getSpeedUnit() != null)
            sb.append("SpeedUnit: ").append(getSpeedUnit()).append(",");
        if (getNextToken() != null)
            sb.append("NextToken: ").append(getNextToken()).append(",");
        if (getMaxResults() != null)
            sb.append("MaxResults: ").append(getMaxResults());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof ForecastGeofenceEventsRequest == false)
            return false;
        ForecastGeofenceEventsRequest other = (ForecastGeofenceEventsRequest) obj;
        if (other.getCollectionName() == null ^ this.getCollectionName() == null)
            return false;
        if (other.getCollectionName() != null && other.getCollectionName().equals(this.getCollectionName()) == false)
            return false;
        if (other.getDeviceState() == null ^ this.getDeviceState() == null)
            return false;
        if (other.getDeviceState() != null && other.getDeviceState().equals(this.getDeviceState()) == false)
            return false;
        if (other.getTimeHorizonMinutes() == null ^ this.getTimeHorizonMinutes() == null)
            return false;
        if (other.getTimeHorizonMinutes() != null && other.getTimeHorizonMinutes().equals(this.getTimeHorizonMinutes()) == false)
            return false;
        if (other.getDistanceUnit() == null ^ this.getDistanceUnit() == null)
            return false;
        if (other.getDistanceUnit() != null && other.getDistanceUnit().equals(this.getDistanceUnit()) == false)
            return false;
        if (other.getSpeedUnit() == null ^ this.getSpeedUnit() == null)
            return false;
        if (other.getSpeedUnit() != null && other.getSpeedUnit().equals(this.getSpeedUnit()) == false)
            return false;
        if (other.getNextToken() == null ^ this.getNextToken() == null)
            return false;
        if (other.getNextToken() != null && other.getNextToken().equals(this.getNextToken()) == false)
            return false;
        if (other.getMaxResults() == null ^ this.getMaxResults() == null)
            return false;
        if (other.getMaxResults() != null && other.getMaxResults().equals(this.getMaxResults()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getCollectionName() == null) ? 0 : getCollectionName().hashCode());
        hashCode = prime * hashCode + ((getDeviceState() == null) ? 0 : getDeviceState().hashCode());
        hashCode = prime * hashCode + ((getTimeHorizonMinutes() == null) ? 0 : getTimeHorizonMinutes().hashCode());
        hashCode = prime * hashCode + ((getDistanceUnit() == null) ? 0 : getDistanceUnit().hashCode());
        hashCode = prime * hashCode + ((getSpeedUnit() == null) ? 0 : getSpeedUnit().hashCode());
        hashCode = prime * hashCode + ((getNextToken() == null) ? 0 : getNextToken().hashCode());
        hashCode = prime * hashCode + ((getMaxResults() == null) ? 0 : getMaxResults().hashCode());
        return hashCode;
    }

    @Override
    public ForecastGeofenceEventsRequest clone() {
        return (ForecastGeofenceEventsRequest) super.clone();
    }

}
