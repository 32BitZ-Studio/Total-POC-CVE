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
 * Details about the Long-Term Evolution (LTE) network.
 * </p>
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/location-2020-11-19/LteCellDetails" target="_top">AWS API
 *      Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class LteCellDetails implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * The E-UTRAN Cell Identifier (ECI).
     * </p>
     */
    private Integer cellId;
    /**
     * <p>
     * The Mobile Country Code (MCC).
     * </p>
     */
    private Integer mcc;
    /**
     * <p>
     * The Mobile Network Code (MNC)
     * </p>
     */
    private Integer mnc;
    /**
     * <p>
     * The LTE local identification information (local ID).
     * </p>
     */
    private LteLocalId localId;
    /**
     * <p>
     * The network measurements.
     * </p>
     */
    private java.util.List<LteNetworkMeasurements> networkMeasurements;
    /**
     * <p>
     * Timing Advance (TA).
     * </p>
     */
    private Integer timingAdvance;
    /**
     * <p>
     * Indicates whether the LTE object is capable of supporting NR (new radio).
     * </p>
     */
    private Boolean nrCapable;
    /**
     * <p>
     * Signal power of the reference signal received, measured in decibel-milliwatts (dBm).
     * </p>
     */
    private Integer rsrp;
    /**
     * <p>
     * Signal quality of the reference Signal received, measured in decibels (dB).
     * </p>
     */
    private Float rsrq;
    /**
     * <p>
     * LTE Tracking Area Code (TAC).
     * </p>
     */
    private Integer tac;

    /**
     * <p>
     * The E-UTRAN Cell Identifier (ECI).
     * </p>
     * 
     * @param cellId
     *        The E-UTRAN Cell Identifier (ECI).
     */

    public void setCellId(Integer cellId) {
        this.cellId = cellId;
    }

    /**
     * <p>
     * The E-UTRAN Cell Identifier (ECI).
     * </p>
     * 
     * @return The E-UTRAN Cell Identifier (ECI).
     */

    public Integer getCellId() {
        return this.cellId;
    }

    /**
     * <p>
     * The E-UTRAN Cell Identifier (ECI).
     * </p>
     * 
     * @param cellId
     *        The E-UTRAN Cell Identifier (ECI).
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public LteCellDetails withCellId(Integer cellId) {
        setCellId(cellId);
        return this;
    }

    /**
     * <p>
     * The Mobile Country Code (MCC).
     * </p>
     * 
     * @param mcc
     *        The Mobile Country Code (MCC).
     */

    public void setMcc(Integer mcc) {
        this.mcc = mcc;
    }

    /**
     * <p>
     * The Mobile Country Code (MCC).
     * </p>
     * 
     * @return The Mobile Country Code (MCC).
     */

    public Integer getMcc() {
        return this.mcc;
    }

    /**
     * <p>
     * The Mobile Country Code (MCC).
     * </p>
     * 
     * @param mcc
     *        The Mobile Country Code (MCC).
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public LteCellDetails withMcc(Integer mcc) {
        setMcc(mcc);
        return this;
    }

    /**
     * <p>
     * The Mobile Network Code (MNC)
     * </p>
     * 
     * @param mnc
     *        The Mobile Network Code (MNC)
     */

    public void setMnc(Integer mnc) {
        this.mnc = mnc;
    }

    /**
     * <p>
     * The Mobile Network Code (MNC)
     * </p>
     * 
     * @return The Mobile Network Code (MNC)
     */

    public Integer getMnc() {
        return this.mnc;
    }

    /**
     * <p>
     * The Mobile Network Code (MNC)
     * </p>
     * 
     * @param mnc
     *        The Mobile Network Code (MNC)
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public LteCellDetails withMnc(Integer mnc) {
        setMnc(mnc);
        return this;
    }

    /**
     * <p>
     * The LTE local identification information (local ID).
     * </p>
     * 
     * @param localId
     *        The LTE local identification information (local ID).
     */

    public void setLocalId(LteLocalId localId) {
        this.localId = localId;
    }

    /**
     * <p>
     * The LTE local identification information (local ID).
     * </p>
     * 
     * @return The LTE local identification information (local ID).
     */

    public LteLocalId getLocalId() {
        return this.localId;
    }

    /**
     * <p>
     * The LTE local identification information (local ID).
     * </p>
     * 
     * @param localId
     *        The LTE local identification information (local ID).
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public LteCellDetails withLocalId(LteLocalId localId) {
        setLocalId(localId);
        return this;
    }

    /**
     * <p>
     * The network measurements.
     * </p>
     * 
     * @return The network measurements.
     */

    public java.util.List<LteNetworkMeasurements> getNetworkMeasurements() {
        return networkMeasurements;
    }

    /**
     * <p>
     * The network measurements.
     * </p>
     * 
     * @param networkMeasurements
     *        The network measurements.
     */

    public void setNetworkMeasurements(java.util.Collection<LteNetworkMeasurements> networkMeasurements) {
        if (networkMeasurements == null) {
            this.networkMeasurements = null;
            return;
        }

        this.networkMeasurements = new java.util.ArrayList<LteNetworkMeasurements>(networkMeasurements);
    }

    /**
     * <p>
     * The network measurements.
     * </p>
     * <p>
     * <b>NOTE:</b> This method appends the values to the existing list (if any). Use
     * {@link #setNetworkMeasurements(java.util.Collection)} or {@link #withNetworkMeasurements(java.util.Collection)}
     * if you want to override the existing values.
     * </p>
     * 
     * @param networkMeasurements
     *        The network measurements.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public LteCellDetails withNetworkMeasurements(LteNetworkMeasurements... networkMeasurements) {
        if (this.networkMeasurements == null) {
            setNetworkMeasurements(new java.util.ArrayList<LteNetworkMeasurements>(networkMeasurements.length));
        }
        for (LteNetworkMeasurements ele : networkMeasurements) {
            this.networkMeasurements.add(ele);
        }
        return this;
    }

    /**
     * <p>
     * The network measurements.
     * </p>
     * 
     * @param networkMeasurements
     *        The network measurements.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public LteCellDetails withNetworkMeasurements(java.util.Collection<LteNetworkMeasurements> networkMeasurements) {
        setNetworkMeasurements(networkMeasurements);
        return this;
    }

    /**
     * <p>
     * Timing Advance (TA).
     * </p>
     * 
     * @param timingAdvance
     *        Timing Advance (TA).
     */

    public void setTimingAdvance(Integer timingAdvance) {
        this.timingAdvance = timingAdvance;
    }

    /**
     * <p>
     * Timing Advance (TA).
     * </p>
     * 
     * @return Timing Advance (TA).
     */

    public Integer getTimingAdvance() {
        return this.timingAdvance;
    }

    /**
     * <p>
     * Timing Advance (TA).
     * </p>
     * 
     * @param timingAdvance
     *        Timing Advance (TA).
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public LteCellDetails withTimingAdvance(Integer timingAdvance) {
        setTimingAdvance(timingAdvance);
        return this;
    }

    /**
     * <p>
     * Indicates whether the LTE object is capable of supporting NR (new radio).
     * </p>
     * 
     * @param nrCapable
     *        Indicates whether the LTE object is capable of supporting NR (new radio).
     */

    public void setNrCapable(Boolean nrCapable) {
        this.nrCapable = nrCapable;
    }

    /**
     * <p>
     * Indicates whether the LTE object is capable of supporting NR (new radio).
     * </p>
     * 
     * @return Indicates whether the LTE object is capable of supporting NR (new radio).
     */

    public Boolean getNrCapable() {
        return this.nrCapable;
    }

    /**
     * <p>
     * Indicates whether the LTE object is capable of supporting NR (new radio).
     * </p>
     * 
     * @param nrCapable
     *        Indicates whether the LTE object is capable of supporting NR (new radio).
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public LteCellDetails withNrCapable(Boolean nrCapable) {
        setNrCapable(nrCapable);
        return this;
    }

    /**
     * <p>
     * Indicates whether the LTE object is capable of supporting NR (new radio).
     * </p>
     * 
     * @return Indicates whether the LTE object is capable of supporting NR (new radio).
     */

    public Boolean isNrCapable() {
        return this.nrCapable;
    }

    /**
     * <p>
     * Signal power of the reference signal received, measured in decibel-milliwatts (dBm).
     * </p>
     * 
     * @param rsrp
     *        Signal power of the reference signal received, measured in decibel-milliwatts (dBm).
     */

    public void setRsrp(Integer rsrp) {
        this.rsrp = rsrp;
    }

    /**
     * <p>
     * Signal power of the reference signal received, measured in decibel-milliwatts (dBm).
     * </p>
     * 
     * @return Signal power of the reference signal received, measured in decibel-milliwatts (dBm).
     */

    public Integer getRsrp() {
        return this.rsrp;
    }

    /**
     * <p>
     * Signal power of the reference signal received, measured in decibel-milliwatts (dBm).
     * </p>
     * 
     * @param rsrp
     *        Signal power of the reference signal received, measured in decibel-milliwatts (dBm).
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public LteCellDetails withRsrp(Integer rsrp) {
        setRsrp(rsrp);
        return this;
    }

    /**
     * <p>
     * Signal quality of the reference Signal received, measured in decibels (dB).
     * </p>
     * 
     * @param rsrq
     *        Signal quality of the reference Signal received, measured in decibels (dB).
     */

    public void setRsrq(Float rsrq) {
        this.rsrq = rsrq;
    }

    /**
     * <p>
     * Signal quality of the reference Signal received, measured in decibels (dB).
     * </p>
     * 
     * @return Signal quality of the reference Signal received, measured in decibels (dB).
     */

    public Float getRsrq() {
        return this.rsrq;
    }

    /**
     * <p>
     * Signal quality of the reference Signal received, measured in decibels (dB).
     * </p>
     * 
     * @param rsrq
     *        Signal quality of the reference Signal received, measured in decibels (dB).
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public LteCellDetails withRsrq(Float rsrq) {
        setRsrq(rsrq);
        return this;
    }

    /**
     * <p>
     * LTE Tracking Area Code (TAC).
     * </p>
     * 
     * @param tac
     *        LTE Tracking Area Code (TAC).
     */

    public void setTac(Integer tac) {
        this.tac = tac;
    }

    /**
     * <p>
     * LTE Tracking Area Code (TAC).
     * </p>
     * 
     * @return LTE Tracking Area Code (TAC).
     */

    public Integer getTac() {
        return this.tac;
    }

    /**
     * <p>
     * LTE Tracking Area Code (TAC).
     * </p>
     * 
     * @param tac
     *        LTE Tracking Area Code (TAC).
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public LteCellDetails withTac(Integer tac) {
        setTac(tac);
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
        if (getCellId() != null)
            sb.append("CellId: ").append(getCellId()).append(",");
        if (getMcc() != null)
            sb.append("Mcc: ").append(getMcc()).append(",");
        if (getMnc() != null)
            sb.append("Mnc: ").append(getMnc()).append(",");
        if (getLocalId() != null)
            sb.append("LocalId: ").append(getLocalId()).append(",");
        if (getNetworkMeasurements() != null)
            sb.append("NetworkMeasurements: ").append(getNetworkMeasurements()).append(",");
        if (getTimingAdvance() != null)
            sb.append("TimingAdvance: ").append(getTimingAdvance()).append(",");
        if (getNrCapable() != null)
            sb.append("NrCapable: ").append(getNrCapable()).append(",");
        if (getRsrp() != null)
            sb.append("Rsrp: ").append(getRsrp()).append(",");
        if (getRsrq() != null)
            sb.append("Rsrq: ").append(getRsrq()).append(",");
        if (getTac() != null)
            sb.append("Tac: ").append(getTac());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof LteCellDetails == false)
            return false;
        LteCellDetails other = (LteCellDetails) obj;
        if (other.getCellId() == null ^ this.getCellId() == null)
            return false;
        if (other.getCellId() != null && other.getCellId().equals(this.getCellId()) == false)
            return false;
        if (other.getMcc() == null ^ this.getMcc() == null)
            return false;
        if (other.getMcc() != null && other.getMcc().equals(this.getMcc()) == false)
            return false;
        if (other.getMnc() == null ^ this.getMnc() == null)
            return false;
        if (other.getMnc() != null && other.getMnc().equals(this.getMnc()) == false)
            return false;
        if (other.getLocalId() == null ^ this.getLocalId() == null)
            return false;
        if (other.getLocalId() != null && other.getLocalId().equals(this.getLocalId()) == false)
            return false;
        if (other.getNetworkMeasurements() == null ^ this.getNetworkMeasurements() == null)
            return false;
        if (other.getNetworkMeasurements() != null && other.getNetworkMeasurements().equals(this.getNetworkMeasurements()) == false)
            return false;
        if (other.getTimingAdvance() == null ^ this.getTimingAdvance() == null)
            return false;
        if (other.getTimingAdvance() != null && other.getTimingAdvance().equals(this.getTimingAdvance()) == false)
            return false;
        if (other.getNrCapable() == null ^ this.getNrCapable() == null)
            return false;
        if (other.getNrCapable() != null && other.getNrCapable().equals(this.getNrCapable()) == false)
            return false;
        if (other.getRsrp() == null ^ this.getRsrp() == null)
            return false;
        if (other.getRsrp() != null && other.getRsrp().equals(this.getRsrp()) == false)
            return false;
        if (other.getRsrq() == null ^ this.getRsrq() == null)
            return false;
        if (other.getRsrq() != null && other.getRsrq().equals(this.getRsrq()) == false)
            return false;
        if (other.getTac() == null ^ this.getTac() == null)
            return false;
        if (other.getTac() != null && other.getTac().equals(this.getTac()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getCellId() == null) ? 0 : getCellId().hashCode());
        hashCode = prime * hashCode + ((getMcc() == null) ? 0 : getMcc().hashCode());
        hashCode = prime * hashCode + ((getMnc() == null) ? 0 : getMnc().hashCode());
        hashCode = prime * hashCode + ((getLocalId() == null) ? 0 : getLocalId().hashCode());
        hashCode = prime * hashCode + ((getNetworkMeasurements() == null) ? 0 : getNetworkMeasurements().hashCode());
        hashCode = prime * hashCode + ((getTimingAdvance() == null) ? 0 : getTimingAdvance().hashCode());
        hashCode = prime * hashCode + ((getNrCapable() == null) ? 0 : getNrCapable().hashCode());
        hashCode = prime * hashCode + ((getRsrp() == null) ? 0 : getRsrp().hashCode());
        hashCode = prime * hashCode + ((getRsrq() == null) ? 0 : getRsrq().hashCode());
        hashCode = prime * hashCode + ((getTac() == null) ? 0 : getTac().hashCode());
        return hashCode;
    }

    @Override
    public LteCellDetails clone() {
        try {
            return (LteCellDetails) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.location.model.transform.LteCellDetailsMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
