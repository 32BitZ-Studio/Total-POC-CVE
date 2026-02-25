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
package com.amazonaws.services.pipes.model;

import java.io.Serializable;
import javax.annotation.Generated;
import com.amazonaws.protocol.StructuredPojo;
import com.amazonaws.protocol.ProtocolMarshaller;

/**
 * <p>
 * The parameters for using a Timestream for LiveAnalytics table as a target.
 * </p>
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/pipes-2015-10-07/PipeTargetTimestreamParameters"
 *      target="_top">AWS API Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class PipeTargetTimestreamParameters implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * Dynamic path to the source data field that represents the time value for your data.
     * </p>
     */
    private String timeValue;
    /**
     * <p>
     * The granularity of the time units used. Default is <code>MILLISECONDS</code>.
     * </p>
     * <p>
     * Required if <code>TimeFieldType</code> is specified as <code>EPOCH</code>.
     * </p>
     */
    private String epochTimeUnit;
    /**
     * <p>
     * The type of time value used.
     * </p>
     * <p>
     * The default is <code>EPOCH</code>.
     * </p>
     */
    private String timeFieldType;
    /**
     * <p>
     * How to format the timestamps. For example, <code>YYYY-MM-DDThh:mm:ss.sssTZD</code>.
     * </p>
     * <p>
     * Required if <code>TimeFieldType</code> is specified as <code>TIMESTAMP_FORMAT</code>.
     * </p>
     */
    private String timestampFormat;
    /**
     * <p>
     * 64 bit version value or source data field that represents the version value for your data.
     * </p>
     * <p>
     * Write requests with a higher version number will update the existing measure values of the record and version. In
     * cases where the measure value is the same, the version will still be updated.
     * </p>
     * <p>
     * Default value is 1.
     * </p>
     * <p>
     * Timestream for LiveAnalytics does not support updating partial measure values in a record.
     * </p>
     * <p>
     * Write requests for duplicate data with a higher version number will update the existing measure value and
     * version. In cases where the measure value is the same, <code>Version</code> will still be updated. Default value
     * is <code>1</code>.
     * </p>
     * <note>
     * <p>
     * <code>Version</code> must be <code>1</code> or greater, or you will receive a <code>ValidationException</code>
     * error.
     * </p>
     * </note>
     */
    private String versionValue;
    /**
     * <p>
     * Map source data to dimensions in the target Timestream for LiveAnalytics table.
     * </p>
     * <p>
     * For more information, see <a
     * href="https://docs.aws.amazon.com/timestream/latest/developerguide/concepts.html">Amazon Timestream for
     * LiveAnalytics concepts</a>
     * </p>
     */
    private java.util.List<DimensionMapping> dimensionMappings;
    /**
     * <p>
     * Mappings of single source data fields to individual records in the specified Timestream for LiveAnalytics table.
     * </p>
     */
    private java.util.List<SingleMeasureMapping> singleMeasureMappings;
    /**
     * <p>
     * Maps multiple measures from the source event to the same record in the specified Timestream for LiveAnalytics
     * table.
     * </p>
     */
    private java.util.List<MultiMeasureMapping> multiMeasureMappings;

    /**
     * <p>
     * Dynamic path to the source data field that represents the time value for your data.
     * </p>
     * 
     * @param timeValue
     *        Dynamic path to the source data field that represents the time value for your data.
     */

    public void setTimeValue(String timeValue) {
        this.timeValue = timeValue;
    }

    /**
     * <p>
     * Dynamic path to the source data field that represents the time value for your data.
     * </p>
     * 
     * @return Dynamic path to the source data field that represents the time value for your data.
     */

    public String getTimeValue() {
        return this.timeValue;
    }

    /**
     * <p>
     * Dynamic path to the source data field that represents the time value for your data.
     * </p>
     * 
     * @param timeValue
     *        Dynamic path to the source data field that represents the time value for your data.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public PipeTargetTimestreamParameters withTimeValue(String timeValue) {
        setTimeValue(timeValue);
        return this;
    }

    /**
     * <p>
     * The granularity of the time units used. Default is <code>MILLISECONDS</code>.
     * </p>
     * <p>
     * Required if <code>TimeFieldType</code> is specified as <code>EPOCH</code>.
     * </p>
     * 
     * @param epochTimeUnit
     *        The granularity of the time units used. Default is <code>MILLISECONDS</code>.</p>
     *        <p>
     *        Required if <code>TimeFieldType</code> is specified as <code>EPOCH</code>.
     * @see EpochTimeUnit
     */

    public void setEpochTimeUnit(String epochTimeUnit) {
        this.epochTimeUnit = epochTimeUnit;
    }

    /**
     * <p>
     * The granularity of the time units used. Default is <code>MILLISECONDS</code>.
     * </p>
     * <p>
     * Required if <code>TimeFieldType</code> is specified as <code>EPOCH</code>.
     * </p>
     * 
     * @return The granularity of the time units used. Default is <code>MILLISECONDS</code>.</p>
     *         <p>
     *         Required if <code>TimeFieldType</code> is specified as <code>EPOCH</code>.
     * @see EpochTimeUnit
     */

    public String getEpochTimeUnit() {
        return this.epochTimeUnit;
    }

    /**
     * <p>
     * The granularity of the time units used. Default is <code>MILLISECONDS</code>.
     * </p>
     * <p>
     * Required if <code>TimeFieldType</code> is specified as <code>EPOCH</code>.
     * </p>
     * 
     * @param epochTimeUnit
     *        The granularity of the time units used. Default is <code>MILLISECONDS</code>.</p>
     *        <p>
     *        Required if <code>TimeFieldType</code> is specified as <code>EPOCH</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see EpochTimeUnit
     */

    public PipeTargetTimestreamParameters withEpochTimeUnit(String epochTimeUnit) {
        setEpochTimeUnit(epochTimeUnit);
        return this;
    }

    /**
     * <p>
     * The granularity of the time units used. Default is <code>MILLISECONDS</code>.
     * </p>
     * <p>
     * Required if <code>TimeFieldType</code> is specified as <code>EPOCH</code>.
     * </p>
     * 
     * @param epochTimeUnit
     *        The granularity of the time units used. Default is <code>MILLISECONDS</code>.</p>
     *        <p>
     *        Required if <code>TimeFieldType</code> is specified as <code>EPOCH</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see EpochTimeUnit
     */

    public PipeTargetTimestreamParameters withEpochTimeUnit(EpochTimeUnit epochTimeUnit) {
        this.epochTimeUnit = epochTimeUnit.toString();
        return this;
    }

    /**
     * <p>
     * The type of time value used.
     * </p>
     * <p>
     * The default is <code>EPOCH</code>.
     * </p>
     * 
     * @param timeFieldType
     *        The type of time value used.</p>
     *        <p>
     *        The default is <code>EPOCH</code>.
     * @see TimeFieldType
     */

    public void setTimeFieldType(String timeFieldType) {
        this.timeFieldType = timeFieldType;
    }

    /**
     * <p>
     * The type of time value used.
     * </p>
     * <p>
     * The default is <code>EPOCH</code>.
     * </p>
     * 
     * @return The type of time value used.</p>
     *         <p>
     *         The default is <code>EPOCH</code>.
     * @see TimeFieldType
     */

    public String getTimeFieldType() {
        return this.timeFieldType;
    }

    /**
     * <p>
     * The type of time value used.
     * </p>
     * <p>
     * The default is <code>EPOCH</code>.
     * </p>
     * 
     * @param timeFieldType
     *        The type of time value used.</p>
     *        <p>
     *        The default is <code>EPOCH</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see TimeFieldType
     */

    public PipeTargetTimestreamParameters withTimeFieldType(String timeFieldType) {
        setTimeFieldType(timeFieldType);
        return this;
    }

    /**
     * <p>
     * The type of time value used.
     * </p>
     * <p>
     * The default is <code>EPOCH</code>.
     * </p>
     * 
     * @param timeFieldType
     *        The type of time value used.</p>
     *        <p>
     *        The default is <code>EPOCH</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see TimeFieldType
     */

    public PipeTargetTimestreamParameters withTimeFieldType(TimeFieldType timeFieldType) {
        this.timeFieldType = timeFieldType.toString();
        return this;
    }

    /**
     * <p>
     * How to format the timestamps. For example, <code>YYYY-MM-DDThh:mm:ss.sssTZD</code>.
     * </p>
     * <p>
     * Required if <code>TimeFieldType</code> is specified as <code>TIMESTAMP_FORMAT</code>.
     * </p>
     * 
     * @param timestampFormat
     *        How to format the timestamps. For example, <code>YYYY-MM-DDThh:mm:ss.sssTZD</code>.</p>
     *        <p>
     *        Required if <code>TimeFieldType</code> is specified as <code>TIMESTAMP_FORMAT</code>.
     */

    public void setTimestampFormat(String timestampFormat) {
        this.timestampFormat = timestampFormat;
    }

    /**
     * <p>
     * How to format the timestamps. For example, <code>YYYY-MM-DDThh:mm:ss.sssTZD</code>.
     * </p>
     * <p>
     * Required if <code>TimeFieldType</code> is specified as <code>TIMESTAMP_FORMAT</code>.
     * </p>
     * 
     * @return How to format the timestamps. For example, <code>YYYY-MM-DDThh:mm:ss.sssTZD</code>.</p>
     *         <p>
     *         Required if <code>TimeFieldType</code> is specified as <code>TIMESTAMP_FORMAT</code>.
     */

    public String getTimestampFormat() {
        return this.timestampFormat;
    }

    /**
     * <p>
     * How to format the timestamps. For example, <code>YYYY-MM-DDThh:mm:ss.sssTZD</code>.
     * </p>
     * <p>
     * Required if <code>TimeFieldType</code> is specified as <code>TIMESTAMP_FORMAT</code>.
     * </p>
     * 
     * @param timestampFormat
     *        How to format the timestamps. For example, <code>YYYY-MM-DDThh:mm:ss.sssTZD</code>.</p>
     *        <p>
     *        Required if <code>TimeFieldType</code> is specified as <code>TIMESTAMP_FORMAT</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public PipeTargetTimestreamParameters withTimestampFormat(String timestampFormat) {
        setTimestampFormat(timestampFormat);
        return this;
    }

    /**
     * <p>
     * 64 bit version value or source data field that represents the version value for your data.
     * </p>
     * <p>
     * Write requests with a higher version number will update the existing measure values of the record and version. In
     * cases where the measure value is the same, the version will still be updated.
     * </p>
     * <p>
     * Default value is 1.
     * </p>
     * <p>
     * Timestream for LiveAnalytics does not support updating partial measure values in a record.
     * </p>
     * <p>
     * Write requests for duplicate data with a higher version number will update the existing measure value and
     * version. In cases where the measure value is the same, <code>Version</code> will still be updated. Default value
     * is <code>1</code>.
     * </p>
     * <note>
     * <p>
     * <code>Version</code> must be <code>1</code> or greater, or you will receive a <code>ValidationException</code>
     * error.
     * </p>
     * </note>
     * 
     * @param versionValue
     *        64 bit version value or source data field that represents the version value for your data.</p>
     *        <p>
     *        Write requests with a higher version number will update the existing measure values of the record and
     *        version. In cases where the measure value is the same, the version will still be updated.
     *        </p>
     *        <p>
     *        Default value is 1.
     *        </p>
     *        <p>
     *        Timestream for LiveAnalytics does not support updating partial measure values in a record.
     *        </p>
     *        <p>
     *        Write requests for duplicate data with a higher version number will update the existing measure value and
     *        version. In cases where the measure value is the same, <code>Version</code> will still be updated. Default
     *        value is <code>1</code>.
     *        </p>
     *        <note>
     *        <p>
     *        <code>Version</code> must be <code>1</code> or greater, or you will receive a
     *        <code>ValidationException</code> error.
     *        </p>
     */

    public void setVersionValue(String versionValue) {
        this.versionValue = versionValue;
    }

    /**
     * <p>
     * 64 bit version value or source data field that represents the version value for your data.
     * </p>
     * <p>
     * Write requests with a higher version number will update the existing measure values of the record and version. In
     * cases where the measure value is the same, the version will still be updated.
     * </p>
     * <p>
     * Default value is 1.
     * </p>
     * <p>
     * Timestream for LiveAnalytics does not support updating partial measure values in a record.
     * </p>
     * <p>
     * Write requests for duplicate data with a higher version number will update the existing measure value and
     * version. In cases where the measure value is the same, <code>Version</code> will still be updated. Default value
     * is <code>1</code>.
     * </p>
     * <note>
     * <p>
     * <code>Version</code> must be <code>1</code> or greater, or you will receive a <code>ValidationException</code>
     * error.
     * </p>
     * </note>
     * 
     * @return 64 bit version value or source data field that represents the version value for your data.</p>
     *         <p>
     *         Write requests with a higher version number will update the existing measure values of the record and
     *         version. In cases where the measure value is the same, the version will still be updated.
     *         </p>
     *         <p>
     *         Default value is 1.
     *         </p>
     *         <p>
     *         Timestream for LiveAnalytics does not support updating partial measure values in a record.
     *         </p>
     *         <p>
     *         Write requests for duplicate data with a higher version number will update the existing measure value and
     *         version. In cases where the measure value is the same, <code>Version</code> will still be updated.
     *         Default value is <code>1</code>.
     *         </p>
     *         <note>
     *         <p>
     *         <code>Version</code> must be <code>1</code> or greater, or you will receive a
     *         <code>ValidationException</code> error.
     *         </p>
     */

    public String getVersionValue() {
        return this.versionValue;
    }

    /**
     * <p>
     * 64 bit version value or source data field that represents the version value for your data.
     * </p>
     * <p>
     * Write requests with a higher version number will update the existing measure values of the record and version. In
     * cases where the measure value is the same, the version will still be updated.
     * </p>
     * <p>
     * Default value is 1.
     * </p>
     * <p>
     * Timestream for LiveAnalytics does not support updating partial measure values in a record.
     * </p>
     * <p>
     * Write requests for duplicate data with a higher version number will update the existing measure value and
     * version. In cases where the measure value is the same, <code>Version</code> will still be updated. Default value
     * is <code>1</code>.
     * </p>
     * <note>
     * <p>
     * <code>Version</code> must be <code>1</code> or greater, or you will receive a <code>ValidationException</code>
     * error.
     * </p>
     * </note>
     * 
     * @param versionValue
     *        64 bit version value or source data field that represents the version value for your data.</p>
     *        <p>
     *        Write requests with a higher version number will update the existing measure values of the record and
     *        version. In cases where the measure value is the same, the version will still be updated.
     *        </p>
     *        <p>
     *        Default value is 1.
     *        </p>
     *        <p>
     *        Timestream for LiveAnalytics does not support updating partial measure values in a record.
     *        </p>
     *        <p>
     *        Write requests for duplicate data with a higher version number will update the existing measure value and
     *        version. In cases where the measure value is the same, <code>Version</code> will still be updated. Default
     *        value is <code>1</code>.
     *        </p>
     *        <note>
     *        <p>
     *        <code>Version</code> must be <code>1</code> or greater, or you will receive a
     *        <code>ValidationException</code> error.
     *        </p>
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public PipeTargetTimestreamParameters withVersionValue(String versionValue) {
        setVersionValue(versionValue);
        return this;
    }

    /**
     * <p>
     * Map source data to dimensions in the target Timestream for LiveAnalytics table.
     * </p>
     * <p>
     * For more information, see <a
     * href="https://docs.aws.amazon.com/timestream/latest/developerguide/concepts.html">Amazon Timestream for
     * LiveAnalytics concepts</a>
     * </p>
     * 
     * @return Map source data to dimensions in the target Timestream for LiveAnalytics table.</p>
     *         <p>
     *         For more information, see <a
     *         href="https://docs.aws.amazon.com/timestream/latest/developerguide/concepts.html">Amazon Timestream for
     *         LiveAnalytics concepts</a>
     */

    public java.util.List<DimensionMapping> getDimensionMappings() {
        return dimensionMappings;
    }

    /**
     * <p>
     * Map source data to dimensions in the target Timestream for LiveAnalytics table.
     * </p>
     * <p>
     * For more information, see <a
     * href="https://docs.aws.amazon.com/timestream/latest/developerguide/concepts.html">Amazon Timestream for
     * LiveAnalytics concepts</a>
     * </p>
     * 
     * @param dimensionMappings
     *        Map source data to dimensions in the target Timestream for LiveAnalytics table.</p>
     *        <p>
     *        For more information, see <a
     *        href="https://docs.aws.amazon.com/timestream/latest/developerguide/concepts.html">Amazon Timestream for
     *        LiveAnalytics concepts</a>
     */

    public void setDimensionMappings(java.util.Collection<DimensionMapping> dimensionMappings) {
        if (dimensionMappings == null) {
            this.dimensionMappings = null;
            return;
        }

        this.dimensionMappings = new java.util.ArrayList<DimensionMapping>(dimensionMappings);
    }

    /**
     * <p>
     * Map source data to dimensions in the target Timestream for LiveAnalytics table.
     * </p>
     * <p>
     * For more information, see <a
     * href="https://docs.aws.amazon.com/timestream/latest/developerguide/concepts.html">Amazon Timestream for
     * LiveAnalytics concepts</a>
     * </p>
     * <p>
     * <b>NOTE:</b> This method appends the values to the existing list (if any). Use
     * {@link #setDimensionMappings(java.util.Collection)} or {@link #withDimensionMappings(java.util.Collection)} if
     * you want to override the existing values.
     * </p>
     * 
     * @param dimensionMappings
     *        Map source data to dimensions in the target Timestream for LiveAnalytics table.</p>
     *        <p>
     *        For more information, see <a
     *        href="https://docs.aws.amazon.com/timestream/latest/developerguide/concepts.html">Amazon Timestream for
     *        LiveAnalytics concepts</a>
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public PipeTargetTimestreamParameters withDimensionMappings(DimensionMapping... dimensionMappings) {
        if (this.dimensionMappings == null) {
            setDimensionMappings(new java.util.ArrayList<DimensionMapping>(dimensionMappings.length));
        }
        for (DimensionMapping ele : dimensionMappings) {
            this.dimensionMappings.add(ele);
        }
        return this;
    }

    /**
     * <p>
     * Map source data to dimensions in the target Timestream for LiveAnalytics table.
     * </p>
     * <p>
     * For more information, see <a
     * href="https://docs.aws.amazon.com/timestream/latest/developerguide/concepts.html">Amazon Timestream for
     * LiveAnalytics concepts</a>
     * </p>
     * 
     * @param dimensionMappings
     *        Map source data to dimensions in the target Timestream for LiveAnalytics table.</p>
     *        <p>
     *        For more information, see <a
     *        href="https://docs.aws.amazon.com/timestream/latest/developerguide/concepts.html">Amazon Timestream for
     *        LiveAnalytics concepts</a>
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public PipeTargetTimestreamParameters withDimensionMappings(java.util.Collection<DimensionMapping> dimensionMappings) {
        setDimensionMappings(dimensionMappings);
        return this;
    }

    /**
     * <p>
     * Mappings of single source data fields to individual records in the specified Timestream for LiveAnalytics table.
     * </p>
     * 
     * @return Mappings of single source data fields to individual records in the specified Timestream for LiveAnalytics
     *         table.
     */

    public java.util.List<SingleMeasureMapping> getSingleMeasureMappings() {
        return singleMeasureMappings;
    }

    /**
     * <p>
     * Mappings of single source data fields to individual records in the specified Timestream for LiveAnalytics table.
     * </p>
     * 
     * @param singleMeasureMappings
     *        Mappings of single source data fields to individual records in the specified Timestream for LiveAnalytics
     *        table.
     */

    public void setSingleMeasureMappings(java.util.Collection<SingleMeasureMapping> singleMeasureMappings) {
        if (singleMeasureMappings == null) {
            this.singleMeasureMappings = null;
            return;
        }

        this.singleMeasureMappings = new java.util.ArrayList<SingleMeasureMapping>(singleMeasureMappings);
    }

    /**
     * <p>
     * Mappings of single source data fields to individual records in the specified Timestream for LiveAnalytics table.
     * </p>
     * <p>
     * <b>NOTE:</b> This method appends the values to the existing list (if any). Use
     * {@link #setSingleMeasureMappings(java.util.Collection)} or
     * {@link #withSingleMeasureMappings(java.util.Collection)} if you want to override the existing values.
     * </p>
     * 
     * @param singleMeasureMappings
     *        Mappings of single source data fields to individual records in the specified Timestream for LiveAnalytics
     *        table.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public PipeTargetTimestreamParameters withSingleMeasureMappings(SingleMeasureMapping... singleMeasureMappings) {
        if (this.singleMeasureMappings == null) {
            setSingleMeasureMappings(new java.util.ArrayList<SingleMeasureMapping>(singleMeasureMappings.length));
        }
        for (SingleMeasureMapping ele : singleMeasureMappings) {
            this.singleMeasureMappings.add(ele);
        }
        return this;
    }

    /**
     * <p>
     * Mappings of single source data fields to individual records in the specified Timestream for LiveAnalytics table.
     * </p>
     * 
     * @param singleMeasureMappings
     *        Mappings of single source data fields to individual records in the specified Timestream for LiveAnalytics
     *        table.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public PipeTargetTimestreamParameters withSingleMeasureMappings(java.util.Collection<SingleMeasureMapping> singleMeasureMappings) {
        setSingleMeasureMappings(singleMeasureMappings);
        return this;
    }

    /**
     * <p>
     * Maps multiple measures from the source event to the same record in the specified Timestream for LiveAnalytics
     * table.
     * </p>
     * 
     * @return Maps multiple measures from the source event to the same record in the specified Timestream for
     *         LiveAnalytics table.
     */

    public java.util.List<MultiMeasureMapping> getMultiMeasureMappings() {
        return multiMeasureMappings;
    }

    /**
     * <p>
     * Maps multiple measures from the source event to the same record in the specified Timestream for LiveAnalytics
     * table.
     * </p>
     * 
     * @param multiMeasureMappings
     *        Maps multiple measures from the source event to the same record in the specified Timestream for
     *        LiveAnalytics table.
     */

    public void setMultiMeasureMappings(java.util.Collection<MultiMeasureMapping> multiMeasureMappings) {
        if (multiMeasureMappings == null) {
            this.multiMeasureMappings = null;
            return;
        }

        this.multiMeasureMappings = new java.util.ArrayList<MultiMeasureMapping>(multiMeasureMappings);
    }

    /**
     * <p>
     * Maps multiple measures from the source event to the same record in the specified Timestream for LiveAnalytics
     * table.
     * </p>
     * <p>
     * <b>NOTE:</b> This method appends the values to the existing list (if any). Use
     * {@link #setMultiMeasureMappings(java.util.Collection)} or {@link #withMultiMeasureMappings(java.util.Collection)}
     * if you want to override the existing values.
     * </p>
     * 
     * @param multiMeasureMappings
     *        Maps multiple measures from the source event to the same record in the specified Timestream for
     *        LiveAnalytics table.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public PipeTargetTimestreamParameters withMultiMeasureMappings(MultiMeasureMapping... multiMeasureMappings) {
        if (this.multiMeasureMappings == null) {
            setMultiMeasureMappings(new java.util.ArrayList<MultiMeasureMapping>(multiMeasureMappings.length));
        }
        for (MultiMeasureMapping ele : multiMeasureMappings) {
            this.multiMeasureMappings.add(ele);
        }
        return this;
    }

    /**
     * <p>
     * Maps multiple measures from the source event to the same record in the specified Timestream for LiveAnalytics
     * table.
     * </p>
     * 
     * @param multiMeasureMappings
     *        Maps multiple measures from the source event to the same record in the specified Timestream for
     *        LiveAnalytics table.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public PipeTargetTimestreamParameters withMultiMeasureMappings(java.util.Collection<MultiMeasureMapping> multiMeasureMappings) {
        setMultiMeasureMappings(multiMeasureMappings);
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
        if (getTimeValue() != null)
            sb.append("TimeValue: ").append(getTimeValue()).append(",");
        if (getEpochTimeUnit() != null)
            sb.append("EpochTimeUnit: ").append(getEpochTimeUnit()).append(",");
        if (getTimeFieldType() != null)
            sb.append("TimeFieldType: ").append(getTimeFieldType()).append(",");
        if (getTimestampFormat() != null)
            sb.append("TimestampFormat: ").append(getTimestampFormat()).append(",");
        if (getVersionValue() != null)
            sb.append("VersionValue: ").append(getVersionValue()).append(",");
        if (getDimensionMappings() != null)
            sb.append("DimensionMappings: ").append(getDimensionMappings()).append(",");
        if (getSingleMeasureMappings() != null)
            sb.append("SingleMeasureMappings: ").append(getSingleMeasureMappings()).append(",");
        if (getMultiMeasureMappings() != null)
            sb.append("MultiMeasureMappings: ").append(getMultiMeasureMappings());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof PipeTargetTimestreamParameters == false)
            return false;
        PipeTargetTimestreamParameters other = (PipeTargetTimestreamParameters) obj;
        if (other.getTimeValue() == null ^ this.getTimeValue() == null)
            return false;
        if (other.getTimeValue() != null && other.getTimeValue().equals(this.getTimeValue()) == false)
            return false;
        if (other.getEpochTimeUnit() == null ^ this.getEpochTimeUnit() == null)
            return false;
        if (other.getEpochTimeUnit() != null && other.getEpochTimeUnit().equals(this.getEpochTimeUnit()) == false)
            return false;
        if (other.getTimeFieldType() == null ^ this.getTimeFieldType() == null)
            return false;
        if (other.getTimeFieldType() != null && other.getTimeFieldType().equals(this.getTimeFieldType()) == false)
            return false;
        if (other.getTimestampFormat() == null ^ this.getTimestampFormat() == null)
            return false;
        if (other.getTimestampFormat() != null && other.getTimestampFormat().equals(this.getTimestampFormat()) == false)
            return false;
        if (other.getVersionValue() == null ^ this.getVersionValue() == null)
            return false;
        if (other.getVersionValue() != null && other.getVersionValue().equals(this.getVersionValue()) == false)
            return false;
        if (other.getDimensionMappings() == null ^ this.getDimensionMappings() == null)
            return false;
        if (other.getDimensionMappings() != null && other.getDimensionMappings().equals(this.getDimensionMappings()) == false)
            return false;
        if (other.getSingleMeasureMappings() == null ^ this.getSingleMeasureMappings() == null)
            return false;
        if (other.getSingleMeasureMappings() != null && other.getSingleMeasureMappings().equals(this.getSingleMeasureMappings()) == false)
            return false;
        if (other.getMultiMeasureMappings() == null ^ this.getMultiMeasureMappings() == null)
            return false;
        if (other.getMultiMeasureMappings() != null && other.getMultiMeasureMappings().equals(this.getMultiMeasureMappings()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getTimeValue() == null) ? 0 : getTimeValue().hashCode());
        hashCode = prime * hashCode + ((getEpochTimeUnit() == null) ? 0 : getEpochTimeUnit().hashCode());
        hashCode = prime * hashCode + ((getTimeFieldType() == null) ? 0 : getTimeFieldType().hashCode());
        hashCode = prime * hashCode + ((getTimestampFormat() == null) ? 0 : getTimestampFormat().hashCode());
        hashCode = prime * hashCode + ((getVersionValue() == null) ? 0 : getVersionValue().hashCode());
        hashCode = prime * hashCode + ((getDimensionMappings() == null) ? 0 : getDimensionMappings().hashCode());
        hashCode = prime * hashCode + ((getSingleMeasureMappings() == null) ? 0 : getSingleMeasureMappings().hashCode());
        hashCode = prime * hashCode + ((getMultiMeasureMappings() == null) ? 0 : getMultiMeasureMappings().hashCode());
        return hashCode;
    }

    @Override
    public PipeTargetTimestreamParameters clone() {
        try {
            return (PipeTargetTimestreamParameters) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.pipes.model.transform.PipeTargetTimestreamParametersMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
