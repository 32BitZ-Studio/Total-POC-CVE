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
package com.amazonaws.services.storagegateway.model;

import java.io.Serializable;
import javax.annotation.Generated;

/**
 * <p>
 * A JSON object containing the following fields:
 * </p>
 * <ul>
 * <li>
 * <p>
 * <a>DescribeMaintenanceStartTimeOutput$SoftwareUpdatePreferences</a>
 * </p>
 * </li>
 * <li>
 * <p>
 * <a>DescribeMaintenanceStartTimeOutput$DayOfMonth</a>
 * </p>
 * </li>
 * <li>
 * <p>
 * <a>DescribeMaintenanceStartTimeOutput$DayOfWeek</a>
 * </p>
 * </li>
 * <li>
 * <p>
 * <a>DescribeMaintenanceStartTimeOutput$HourOfDay</a>
 * </p>
 * </li>
 * <li>
 * <p>
 * <a>DescribeMaintenanceStartTimeOutput$MinuteOfHour</a>
 * </p>
 * </li>
 * <li>
 * <p>
 * <a>DescribeMaintenanceStartTimeOutput$Timezone</a>
 * </p>
 * </li>
 * </ul>
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/storagegateway-2013-06-30/DescribeMaintenanceStartTime"
 *      target="_top">AWS API Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class DescribeMaintenanceStartTimeResult extends com.amazonaws.AmazonWebServiceResult<com.amazonaws.ResponseMetadata> implements Serializable, Cloneable {

    private String gatewayARN;
    /**
     * <p>
     * The hour component of the maintenance start time represented as <i>hh</i>, where <i>hh</i> is the hour (0 to 23).
     * The hour of the day is in the time zone of the gateway.
     * </p>
     */
    private Integer hourOfDay;
    /**
     * <p>
     * The minute component of the maintenance start time represented as <i>mm</i>, where <i>mm</i> is the minute (0 to
     * 59). The minute of the hour is in the time zone of the gateway.
     * </p>
     */
    private Integer minuteOfHour;
    /**
     * <p>
     * An ordinal number between 0 and 6 that represents the day of the week, where 0 represents Sunday and 6 represents
     * Saturday. The day of week is in the time zone of the gateway.
     * </p>
     */
    private Integer dayOfWeek;
    /**
     * <p>
     * The day of the month component of the maintenance start time represented as an ordinal number from 1 to 28, where
     * 1 represents the first day of the month. It is not possible to set the maintenance schedule to start on days 29
     * through 31.
     * </p>
     */
    private Integer dayOfMonth;
    /**
     * <p>
     * A value that indicates the time zone that is set for the gateway. The start time and day of week specified should
     * be in the time zone of the gateway.
     * </p>
     */
    private String timezone;
    /**
     * <p>
     * A set of variables indicating the software update preferences for the gateway.
     * </p>
     * <p>
     * Includes <code>AutomaticUpdatePolicy</code> field with the following inputs:
     * </p>
     * <p>
     * <code>ALL_VERSIONS</code> - Enables regular gateway maintenance updates.
     * </p>
     * <p>
     * <code>EMERGENCY_VERSIONS_ONLY</code> - Disables regular gateway maintenance updates.
     * </p>
     */
    private SoftwareUpdatePreferences softwareUpdatePreferences;

    /**
     * @param gatewayARN
     */

    public void setGatewayARN(String gatewayARN) {
        this.gatewayARN = gatewayARN;
    }

    /**
     * @return
     */

    public String getGatewayARN() {
        return this.gatewayARN;
    }

    /**
     * @param gatewayARN
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public DescribeMaintenanceStartTimeResult withGatewayARN(String gatewayARN) {
        setGatewayARN(gatewayARN);
        return this;
    }

    /**
     * <p>
     * The hour component of the maintenance start time represented as <i>hh</i>, where <i>hh</i> is the hour (0 to 23).
     * The hour of the day is in the time zone of the gateway.
     * </p>
     * 
     * @param hourOfDay
     *        The hour component of the maintenance start time represented as <i>hh</i>, where <i>hh</i> is the hour (0
     *        to 23). The hour of the day is in the time zone of the gateway.
     */

    public void setHourOfDay(Integer hourOfDay) {
        this.hourOfDay = hourOfDay;
    }

    /**
     * <p>
     * The hour component of the maintenance start time represented as <i>hh</i>, where <i>hh</i> is the hour (0 to 23).
     * The hour of the day is in the time zone of the gateway.
     * </p>
     * 
     * @return The hour component of the maintenance start time represented as <i>hh</i>, where <i>hh</i> is the hour (0
     *         to 23). The hour of the day is in the time zone of the gateway.
     */

    public Integer getHourOfDay() {
        return this.hourOfDay;
    }

    /**
     * <p>
     * The hour component of the maintenance start time represented as <i>hh</i>, where <i>hh</i> is the hour (0 to 23).
     * The hour of the day is in the time zone of the gateway.
     * </p>
     * 
     * @param hourOfDay
     *        The hour component of the maintenance start time represented as <i>hh</i>, where <i>hh</i> is the hour (0
     *        to 23). The hour of the day is in the time zone of the gateway.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public DescribeMaintenanceStartTimeResult withHourOfDay(Integer hourOfDay) {
        setHourOfDay(hourOfDay);
        return this;
    }

    /**
     * <p>
     * The minute component of the maintenance start time represented as <i>mm</i>, where <i>mm</i> is the minute (0 to
     * 59). The minute of the hour is in the time zone of the gateway.
     * </p>
     * 
     * @param minuteOfHour
     *        The minute component of the maintenance start time represented as <i>mm</i>, where <i>mm</i> is the minute
     *        (0 to 59). The minute of the hour is in the time zone of the gateway.
     */

    public void setMinuteOfHour(Integer minuteOfHour) {
        this.minuteOfHour = minuteOfHour;
    }

    /**
     * <p>
     * The minute component of the maintenance start time represented as <i>mm</i>, where <i>mm</i> is the minute (0 to
     * 59). The minute of the hour is in the time zone of the gateway.
     * </p>
     * 
     * @return The minute component of the maintenance start time represented as <i>mm</i>, where <i>mm</i> is the
     *         minute (0 to 59). The minute of the hour is in the time zone of the gateway.
     */

    public Integer getMinuteOfHour() {
        return this.minuteOfHour;
    }

    /**
     * <p>
     * The minute component of the maintenance start time represented as <i>mm</i>, where <i>mm</i> is the minute (0 to
     * 59). The minute of the hour is in the time zone of the gateway.
     * </p>
     * 
     * @param minuteOfHour
     *        The minute component of the maintenance start time represented as <i>mm</i>, where <i>mm</i> is the minute
     *        (0 to 59). The minute of the hour is in the time zone of the gateway.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public DescribeMaintenanceStartTimeResult withMinuteOfHour(Integer minuteOfHour) {
        setMinuteOfHour(minuteOfHour);
        return this;
    }

    /**
     * <p>
     * An ordinal number between 0 and 6 that represents the day of the week, where 0 represents Sunday and 6 represents
     * Saturday. The day of week is in the time zone of the gateway.
     * </p>
     * 
     * @param dayOfWeek
     *        An ordinal number between 0 and 6 that represents the day of the week, where 0 represents Sunday and 6
     *        represents Saturday. The day of week is in the time zone of the gateway.
     */

    public void setDayOfWeek(Integer dayOfWeek) {
        this.dayOfWeek = dayOfWeek;
    }

    /**
     * <p>
     * An ordinal number between 0 and 6 that represents the day of the week, where 0 represents Sunday and 6 represents
     * Saturday. The day of week is in the time zone of the gateway.
     * </p>
     * 
     * @return An ordinal number between 0 and 6 that represents the day of the week, where 0 represents Sunday and 6
     *         represents Saturday. The day of week is in the time zone of the gateway.
     */

    public Integer getDayOfWeek() {
        return this.dayOfWeek;
    }

    /**
     * <p>
     * An ordinal number between 0 and 6 that represents the day of the week, where 0 represents Sunday and 6 represents
     * Saturday. The day of week is in the time zone of the gateway.
     * </p>
     * 
     * @param dayOfWeek
     *        An ordinal number between 0 and 6 that represents the day of the week, where 0 represents Sunday and 6
     *        represents Saturday. The day of week is in the time zone of the gateway.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public DescribeMaintenanceStartTimeResult withDayOfWeek(Integer dayOfWeek) {
        setDayOfWeek(dayOfWeek);
        return this;
    }

    /**
     * <p>
     * The day of the month component of the maintenance start time represented as an ordinal number from 1 to 28, where
     * 1 represents the first day of the month. It is not possible to set the maintenance schedule to start on days 29
     * through 31.
     * </p>
     * 
     * @param dayOfMonth
     *        The day of the month component of the maintenance start time represented as an ordinal number from 1 to
     *        28, where 1 represents the first day of the month. It is not possible to set the maintenance schedule to
     *        start on days 29 through 31.
     */

    public void setDayOfMonth(Integer dayOfMonth) {
        this.dayOfMonth = dayOfMonth;
    }

    /**
     * <p>
     * The day of the month component of the maintenance start time represented as an ordinal number from 1 to 28, where
     * 1 represents the first day of the month. It is not possible to set the maintenance schedule to start on days 29
     * through 31.
     * </p>
     * 
     * @return The day of the month component of the maintenance start time represented as an ordinal number from 1 to
     *         28, where 1 represents the first day of the month. It is not possible to set the maintenance schedule to
     *         start on days 29 through 31.
     */

    public Integer getDayOfMonth() {
        return this.dayOfMonth;
    }

    /**
     * <p>
     * The day of the month component of the maintenance start time represented as an ordinal number from 1 to 28, where
     * 1 represents the first day of the month. It is not possible to set the maintenance schedule to start on days 29
     * through 31.
     * </p>
     * 
     * @param dayOfMonth
     *        The day of the month component of the maintenance start time represented as an ordinal number from 1 to
     *        28, where 1 represents the first day of the month. It is not possible to set the maintenance schedule to
     *        start on days 29 through 31.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public DescribeMaintenanceStartTimeResult withDayOfMonth(Integer dayOfMonth) {
        setDayOfMonth(dayOfMonth);
        return this;
    }

    /**
     * <p>
     * A value that indicates the time zone that is set for the gateway. The start time and day of week specified should
     * be in the time zone of the gateway.
     * </p>
     * 
     * @param timezone
     *        A value that indicates the time zone that is set for the gateway. The start time and day of week specified
     *        should be in the time zone of the gateway.
     */

    public void setTimezone(String timezone) {
        this.timezone = timezone;
    }

    /**
     * <p>
     * A value that indicates the time zone that is set for the gateway. The start time and day of week specified should
     * be in the time zone of the gateway.
     * </p>
     * 
     * @return A value that indicates the time zone that is set for the gateway. The start time and day of week
     *         specified should be in the time zone of the gateway.
     */

    public String getTimezone() {
        return this.timezone;
    }

    /**
     * <p>
     * A value that indicates the time zone that is set for the gateway. The start time and day of week specified should
     * be in the time zone of the gateway.
     * </p>
     * 
     * @param timezone
     *        A value that indicates the time zone that is set for the gateway. The start time and day of week specified
     *        should be in the time zone of the gateway.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public DescribeMaintenanceStartTimeResult withTimezone(String timezone) {
        setTimezone(timezone);
        return this;
    }

    /**
     * <p>
     * A set of variables indicating the software update preferences for the gateway.
     * </p>
     * <p>
     * Includes <code>AutomaticUpdatePolicy</code> field with the following inputs:
     * </p>
     * <p>
     * <code>ALL_VERSIONS</code> - Enables regular gateway maintenance updates.
     * </p>
     * <p>
     * <code>EMERGENCY_VERSIONS_ONLY</code> - Disables regular gateway maintenance updates.
     * </p>
     * 
     * @param softwareUpdatePreferences
     *        A set of variables indicating the software update preferences for the gateway.</p>
     *        <p>
     *        Includes <code>AutomaticUpdatePolicy</code> field with the following inputs:
     *        </p>
     *        <p>
     *        <code>ALL_VERSIONS</code> - Enables regular gateway maintenance updates.
     *        </p>
     *        <p>
     *        <code>EMERGENCY_VERSIONS_ONLY</code> - Disables regular gateway maintenance updates.
     */

    public void setSoftwareUpdatePreferences(SoftwareUpdatePreferences softwareUpdatePreferences) {
        this.softwareUpdatePreferences = softwareUpdatePreferences;
    }

    /**
     * <p>
     * A set of variables indicating the software update preferences for the gateway.
     * </p>
     * <p>
     * Includes <code>AutomaticUpdatePolicy</code> field with the following inputs:
     * </p>
     * <p>
     * <code>ALL_VERSIONS</code> - Enables regular gateway maintenance updates.
     * </p>
     * <p>
     * <code>EMERGENCY_VERSIONS_ONLY</code> - Disables regular gateway maintenance updates.
     * </p>
     * 
     * @return A set of variables indicating the software update preferences for the gateway.</p>
     *         <p>
     *         Includes <code>AutomaticUpdatePolicy</code> field with the following inputs:
     *         </p>
     *         <p>
     *         <code>ALL_VERSIONS</code> - Enables regular gateway maintenance updates.
     *         </p>
     *         <p>
     *         <code>EMERGENCY_VERSIONS_ONLY</code> - Disables regular gateway maintenance updates.
     */

    public SoftwareUpdatePreferences getSoftwareUpdatePreferences() {
        return this.softwareUpdatePreferences;
    }

    /**
     * <p>
     * A set of variables indicating the software update preferences for the gateway.
     * </p>
     * <p>
     * Includes <code>AutomaticUpdatePolicy</code> field with the following inputs:
     * </p>
     * <p>
     * <code>ALL_VERSIONS</code> - Enables regular gateway maintenance updates.
     * </p>
     * <p>
     * <code>EMERGENCY_VERSIONS_ONLY</code> - Disables regular gateway maintenance updates.
     * </p>
     * 
     * @param softwareUpdatePreferences
     *        A set of variables indicating the software update preferences for the gateway.</p>
     *        <p>
     *        Includes <code>AutomaticUpdatePolicy</code> field with the following inputs:
     *        </p>
     *        <p>
     *        <code>ALL_VERSIONS</code> - Enables regular gateway maintenance updates.
     *        </p>
     *        <p>
     *        <code>EMERGENCY_VERSIONS_ONLY</code> - Disables regular gateway maintenance updates.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public DescribeMaintenanceStartTimeResult withSoftwareUpdatePreferences(SoftwareUpdatePreferences softwareUpdatePreferences) {
        setSoftwareUpdatePreferences(softwareUpdatePreferences);
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
        if (getGatewayARN() != null)
            sb.append("GatewayARN: ").append(getGatewayARN()).append(",");
        if (getHourOfDay() != null)
            sb.append("HourOfDay: ").append(getHourOfDay()).append(",");
        if (getMinuteOfHour() != null)
            sb.append("MinuteOfHour: ").append(getMinuteOfHour()).append(",");
        if (getDayOfWeek() != null)
            sb.append("DayOfWeek: ").append(getDayOfWeek()).append(",");
        if (getDayOfMonth() != null)
            sb.append("DayOfMonth: ").append(getDayOfMonth()).append(",");
        if (getTimezone() != null)
            sb.append("Timezone: ").append(getTimezone()).append(",");
        if (getSoftwareUpdatePreferences() != null)
            sb.append("SoftwareUpdatePreferences: ").append(getSoftwareUpdatePreferences());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof DescribeMaintenanceStartTimeResult == false)
            return false;
        DescribeMaintenanceStartTimeResult other = (DescribeMaintenanceStartTimeResult) obj;
        if (other.getGatewayARN() == null ^ this.getGatewayARN() == null)
            return false;
        if (other.getGatewayARN() != null && other.getGatewayARN().equals(this.getGatewayARN()) == false)
            return false;
        if (other.getHourOfDay() == null ^ this.getHourOfDay() == null)
            return false;
        if (other.getHourOfDay() != null && other.getHourOfDay().equals(this.getHourOfDay()) == false)
            return false;
        if (other.getMinuteOfHour() == null ^ this.getMinuteOfHour() == null)
            return false;
        if (other.getMinuteOfHour() != null && other.getMinuteOfHour().equals(this.getMinuteOfHour()) == false)
            return false;
        if (other.getDayOfWeek() == null ^ this.getDayOfWeek() == null)
            return false;
        if (other.getDayOfWeek() != null && other.getDayOfWeek().equals(this.getDayOfWeek()) == false)
            return false;
        if (other.getDayOfMonth() == null ^ this.getDayOfMonth() == null)
            return false;
        if (other.getDayOfMonth() != null && other.getDayOfMonth().equals(this.getDayOfMonth()) == false)
            return false;
        if (other.getTimezone() == null ^ this.getTimezone() == null)
            return false;
        if (other.getTimezone() != null && other.getTimezone().equals(this.getTimezone()) == false)
            return false;
        if (other.getSoftwareUpdatePreferences() == null ^ this.getSoftwareUpdatePreferences() == null)
            return false;
        if (other.getSoftwareUpdatePreferences() != null && other.getSoftwareUpdatePreferences().equals(this.getSoftwareUpdatePreferences()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getGatewayARN() == null) ? 0 : getGatewayARN().hashCode());
        hashCode = prime * hashCode + ((getHourOfDay() == null) ? 0 : getHourOfDay().hashCode());
        hashCode = prime * hashCode + ((getMinuteOfHour() == null) ? 0 : getMinuteOfHour().hashCode());
        hashCode = prime * hashCode + ((getDayOfWeek() == null) ? 0 : getDayOfWeek().hashCode());
        hashCode = prime * hashCode + ((getDayOfMonth() == null) ? 0 : getDayOfMonth().hashCode());
        hashCode = prime * hashCode + ((getTimezone() == null) ? 0 : getTimezone().hashCode());
        hashCode = prime * hashCode + ((getSoftwareUpdatePreferences() == null) ? 0 : getSoftwareUpdatePreferences().hashCode());
        return hashCode;
    }

    @Override
    public DescribeMaintenanceStartTimeResult clone() {
        try {
            return (DescribeMaintenanceStartTimeResult) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

}
