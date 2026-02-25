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
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/location-2020-11-19/ForecastGeofenceEvents" target="_top">AWS
 *      API Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class ForecastGeofenceEventsResult extends com.amazonaws.AmazonWebServiceResult<com.amazonaws.ResponseMetadata> implements Serializable, Cloneable {

    /**
     * <p>
     * The list of forecasted events.
     * </p>
     */
    private java.util.List<ForecastedEvent> forecastedEvents;
    /**
     * <p>
     * The pagination token specifying which page of results to return in the response. If no token is provided, the
     * default page is the first page.
     * </p>
     */
    private String nextToken;
    /**
     * <p>
     * The distance unit for the forecasted events.
     * </p>
     */
    private String distanceUnit;
    /**
     * <p>
     * The speed unit for the forecasted events.
     * </p>
     */
    private String speedUnit;

    /**
     * <p>
     * The list of forecasted events.
     * </p>
     * 
     * @return The list of forecasted events.
     */

    public java.util.List<ForecastedEvent> getForecastedEvents() {
        return forecastedEvents;
    }

    /**
     * <p>
     * The list of forecasted events.
     * </p>
     * 
     * @param forecastedEvents
     *        The list of forecasted events.
     */

    public void setForecastedEvents(java.util.Collection<ForecastedEvent> forecastedEvents) {
        if (forecastedEvents == null) {
            this.forecastedEvents = null;
            return;
        }

        this.forecastedEvents = new java.util.ArrayList<ForecastedEvent>(forecastedEvents);
    }

    /**
     * <p>
     * The list of forecasted events.
     * </p>
     * <p>
     * <b>NOTE:</b> This method appends the values to the existing list (if any). Use
     * {@link #setForecastedEvents(java.util.Collection)} or {@link #withForecastedEvents(java.util.Collection)} if you
     * want to override the existing values.
     * </p>
     * 
     * @param forecastedEvents
     *        The list of forecasted events.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ForecastGeofenceEventsResult withForecastedEvents(ForecastedEvent... forecastedEvents) {
        if (this.forecastedEvents == null) {
            setForecastedEvents(new java.util.ArrayList<ForecastedEvent>(forecastedEvents.length));
        }
        for (ForecastedEvent ele : forecastedEvents) {
            this.forecastedEvents.add(ele);
        }
        return this;
    }

    /**
     * <p>
     * The list of forecasted events.
     * </p>
     * 
     * @param forecastedEvents
     *        The list of forecasted events.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ForecastGeofenceEventsResult withForecastedEvents(java.util.Collection<ForecastedEvent> forecastedEvents) {
        setForecastedEvents(forecastedEvents);
        return this;
    }

    /**
     * <p>
     * The pagination token specifying which page of results to return in the response. If no token is provided, the
     * default page is the first page.
     * </p>
     * 
     * @param nextToken
     *        The pagination token specifying which page of results to return in the response. If no token is provided,
     *        the default page is the first page.
     */

    public void setNextToken(String nextToken) {
        this.nextToken = nextToken;
    }

    /**
     * <p>
     * The pagination token specifying which page of results to return in the response. If no token is provided, the
     * default page is the first page.
     * </p>
     * 
     * @return The pagination token specifying which page of results to return in the response. If no token is provided,
     *         the default page is the first page.
     */

    public String getNextToken() {
        return this.nextToken;
    }

    /**
     * <p>
     * The pagination token specifying which page of results to return in the response. If no token is provided, the
     * default page is the first page.
     * </p>
     * 
     * @param nextToken
     *        The pagination token specifying which page of results to return in the response. If no token is provided,
     *        the default page is the first page.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ForecastGeofenceEventsResult withNextToken(String nextToken) {
        setNextToken(nextToken);
        return this;
    }

    /**
     * <p>
     * The distance unit for the forecasted events.
     * </p>
     * 
     * @param distanceUnit
     *        The distance unit for the forecasted events.
     * @see DistanceUnit
     */

    public void setDistanceUnit(String distanceUnit) {
        this.distanceUnit = distanceUnit;
    }

    /**
     * <p>
     * The distance unit for the forecasted events.
     * </p>
     * 
     * @return The distance unit for the forecasted events.
     * @see DistanceUnit
     */

    public String getDistanceUnit() {
        return this.distanceUnit;
    }

    /**
     * <p>
     * The distance unit for the forecasted events.
     * </p>
     * 
     * @param distanceUnit
     *        The distance unit for the forecasted events.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see DistanceUnit
     */

    public ForecastGeofenceEventsResult withDistanceUnit(String distanceUnit) {
        setDistanceUnit(distanceUnit);
        return this;
    }

    /**
     * <p>
     * The distance unit for the forecasted events.
     * </p>
     * 
     * @param distanceUnit
     *        The distance unit for the forecasted events.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see DistanceUnit
     */

    public ForecastGeofenceEventsResult withDistanceUnit(DistanceUnit distanceUnit) {
        this.distanceUnit = distanceUnit.toString();
        return this;
    }

    /**
     * <p>
     * The speed unit for the forecasted events.
     * </p>
     * 
     * @param speedUnit
     *        The speed unit for the forecasted events.
     * @see SpeedUnit
     */

    public void setSpeedUnit(String speedUnit) {
        this.speedUnit = speedUnit;
    }

    /**
     * <p>
     * The speed unit for the forecasted events.
     * </p>
     * 
     * @return The speed unit for the forecasted events.
     * @see SpeedUnit
     */

    public String getSpeedUnit() {
        return this.speedUnit;
    }

    /**
     * <p>
     * The speed unit for the forecasted events.
     * </p>
     * 
     * @param speedUnit
     *        The speed unit for the forecasted events.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see SpeedUnit
     */

    public ForecastGeofenceEventsResult withSpeedUnit(String speedUnit) {
        setSpeedUnit(speedUnit);
        return this;
    }

    /**
     * <p>
     * The speed unit for the forecasted events.
     * </p>
     * 
     * @param speedUnit
     *        The speed unit for the forecasted events.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see SpeedUnit
     */

    public ForecastGeofenceEventsResult withSpeedUnit(SpeedUnit speedUnit) {
        this.speedUnit = speedUnit.toString();
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
        if (getForecastedEvents() != null)
            sb.append("ForecastedEvents: ").append(getForecastedEvents()).append(",");
        if (getNextToken() != null)
            sb.append("NextToken: ").append(getNextToken()).append(",");
        if (getDistanceUnit() != null)
            sb.append("DistanceUnit: ").append(getDistanceUnit()).append(",");
        if (getSpeedUnit() != null)
            sb.append("SpeedUnit: ").append(getSpeedUnit());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof ForecastGeofenceEventsResult == false)
            return false;
        ForecastGeofenceEventsResult other = (ForecastGeofenceEventsResult) obj;
        if (other.getForecastedEvents() == null ^ this.getForecastedEvents() == null)
            return false;
        if (other.getForecastedEvents() != null && other.getForecastedEvents().equals(this.getForecastedEvents()) == false)
            return false;
        if (other.getNextToken() == null ^ this.getNextToken() == null)
            return false;
        if (other.getNextToken() != null && other.getNextToken().equals(this.getNextToken()) == false)
            return false;
        if (other.getDistanceUnit() == null ^ this.getDistanceUnit() == null)
            return false;
        if (other.getDistanceUnit() != null && other.getDistanceUnit().equals(this.getDistanceUnit()) == false)
            return false;
        if (other.getSpeedUnit() == null ^ this.getSpeedUnit() == null)
            return false;
        if (other.getSpeedUnit() != null && other.getSpeedUnit().equals(this.getSpeedUnit()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getForecastedEvents() == null) ? 0 : getForecastedEvents().hashCode());
        hashCode = prime * hashCode + ((getNextToken() == null) ? 0 : getNextToken().hashCode());
        hashCode = prime * hashCode + ((getDistanceUnit() == null) ? 0 : getDistanceUnit().hashCode());
        hashCode = prime * hashCode + ((getSpeedUnit() == null) ? 0 : getSpeedUnit().hashCode());
        return hashCode;
    }

    @Override
    public ForecastGeofenceEventsResult clone() {
        try {
            return (ForecastGeofenceEventsResult) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

}
