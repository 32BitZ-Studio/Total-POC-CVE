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
package com.amazonaws.services.medialive.model;

import java.io.Serializable;
import javax.annotation.Generated;
import com.amazonaws.protocol.StructuredPojo;
import com.amazonaws.protocol.ProtocolMarshaller;

/**
 * The configuration for a source that uses SRT as the connection protocol. In terms of establishing the connection,
 * MediaLive is always caller and the upstream system is always the listener. In terms of transmission of the source
 * content, MediaLive is always the receiver and the upstream system is always the sender.
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/medialive-2017-10-14/SrtCallerSource" target="_top">AWS API
 *      Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class SrtCallerSource implements Serializable, Cloneable, StructuredPojo {

    private SrtCallerDecryption decryption;
    /**
     * The preferred latency (in milliseconds) for implementing packet loss and recovery. Packet recovery is a key
     * feature of SRT.
     */
    private Integer minimumLatency;
    /** The IP address at the upstream system (the listener) that MediaLive (the caller) connects to. */
    private String srtListenerAddress;
    /** The port at the upstream system (the listener) that MediaLive (the caller) connects to. */
    private String srtListenerPort;
    /** The stream ID, if the upstream system uses this identifier. */
    private String streamId;

    /**
     * @param decryption
     */

    public void setDecryption(SrtCallerDecryption decryption) {
        this.decryption = decryption;
    }

    /**
     * @return
     */

    public SrtCallerDecryption getDecryption() {
        return this.decryption;
    }

    /**
     * @param decryption
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public SrtCallerSource withDecryption(SrtCallerDecryption decryption) {
        setDecryption(decryption);
        return this;
    }

    /**
     * The preferred latency (in milliseconds) for implementing packet loss and recovery. Packet recovery is a key
     * feature of SRT.
     * 
     * @param minimumLatency
     *        The preferred latency (in milliseconds) for implementing packet loss and recovery. Packet recovery is a
     *        key feature of SRT.
     */

    public void setMinimumLatency(Integer minimumLatency) {
        this.minimumLatency = minimumLatency;
    }

    /**
     * The preferred latency (in milliseconds) for implementing packet loss and recovery. Packet recovery is a key
     * feature of SRT.
     * 
     * @return The preferred latency (in milliseconds) for implementing packet loss and recovery. Packet recovery is a
     *         key feature of SRT.
     */

    public Integer getMinimumLatency() {
        return this.minimumLatency;
    }

    /**
     * The preferred latency (in milliseconds) for implementing packet loss and recovery. Packet recovery is a key
     * feature of SRT.
     * 
     * @param minimumLatency
     *        The preferred latency (in milliseconds) for implementing packet loss and recovery. Packet recovery is a
     *        key feature of SRT.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public SrtCallerSource withMinimumLatency(Integer minimumLatency) {
        setMinimumLatency(minimumLatency);
        return this;
    }

    /**
     * The IP address at the upstream system (the listener) that MediaLive (the caller) connects to.
     * 
     * @param srtListenerAddress
     *        The IP address at the upstream system (the listener) that MediaLive (the caller) connects to.
     */

    public void setSrtListenerAddress(String srtListenerAddress) {
        this.srtListenerAddress = srtListenerAddress;
    }

    /**
     * The IP address at the upstream system (the listener) that MediaLive (the caller) connects to.
     * 
     * @return The IP address at the upstream system (the listener) that MediaLive (the caller) connects to.
     */

    public String getSrtListenerAddress() {
        return this.srtListenerAddress;
    }

    /**
     * The IP address at the upstream system (the listener) that MediaLive (the caller) connects to.
     * 
     * @param srtListenerAddress
     *        The IP address at the upstream system (the listener) that MediaLive (the caller) connects to.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public SrtCallerSource withSrtListenerAddress(String srtListenerAddress) {
        setSrtListenerAddress(srtListenerAddress);
        return this;
    }

    /**
     * The port at the upstream system (the listener) that MediaLive (the caller) connects to.
     * 
     * @param srtListenerPort
     *        The port at the upstream system (the listener) that MediaLive (the caller) connects to.
     */

    public void setSrtListenerPort(String srtListenerPort) {
        this.srtListenerPort = srtListenerPort;
    }

    /**
     * The port at the upstream system (the listener) that MediaLive (the caller) connects to.
     * 
     * @return The port at the upstream system (the listener) that MediaLive (the caller) connects to.
     */

    public String getSrtListenerPort() {
        return this.srtListenerPort;
    }

    /**
     * The port at the upstream system (the listener) that MediaLive (the caller) connects to.
     * 
     * @param srtListenerPort
     *        The port at the upstream system (the listener) that MediaLive (the caller) connects to.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public SrtCallerSource withSrtListenerPort(String srtListenerPort) {
        setSrtListenerPort(srtListenerPort);
        return this;
    }

    /**
     * The stream ID, if the upstream system uses this identifier.
     * 
     * @param streamId
     *        The stream ID, if the upstream system uses this identifier.
     */

    public void setStreamId(String streamId) {
        this.streamId = streamId;
    }

    /**
     * The stream ID, if the upstream system uses this identifier.
     * 
     * @return The stream ID, if the upstream system uses this identifier.
     */

    public String getStreamId() {
        return this.streamId;
    }

    /**
     * The stream ID, if the upstream system uses this identifier.
     * 
     * @param streamId
     *        The stream ID, if the upstream system uses this identifier.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public SrtCallerSource withStreamId(String streamId) {
        setStreamId(streamId);
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
        if (getDecryption() != null)
            sb.append("Decryption: ").append(getDecryption()).append(",");
        if (getMinimumLatency() != null)
            sb.append("MinimumLatency: ").append(getMinimumLatency()).append(",");
        if (getSrtListenerAddress() != null)
            sb.append("SrtListenerAddress: ").append(getSrtListenerAddress()).append(",");
        if (getSrtListenerPort() != null)
            sb.append("SrtListenerPort: ").append(getSrtListenerPort()).append(",");
        if (getStreamId() != null)
            sb.append("StreamId: ").append(getStreamId());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof SrtCallerSource == false)
            return false;
        SrtCallerSource other = (SrtCallerSource) obj;
        if (other.getDecryption() == null ^ this.getDecryption() == null)
            return false;
        if (other.getDecryption() != null && other.getDecryption().equals(this.getDecryption()) == false)
            return false;
        if (other.getMinimumLatency() == null ^ this.getMinimumLatency() == null)
            return false;
        if (other.getMinimumLatency() != null && other.getMinimumLatency().equals(this.getMinimumLatency()) == false)
            return false;
        if (other.getSrtListenerAddress() == null ^ this.getSrtListenerAddress() == null)
            return false;
        if (other.getSrtListenerAddress() != null && other.getSrtListenerAddress().equals(this.getSrtListenerAddress()) == false)
            return false;
        if (other.getSrtListenerPort() == null ^ this.getSrtListenerPort() == null)
            return false;
        if (other.getSrtListenerPort() != null && other.getSrtListenerPort().equals(this.getSrtListenerPort()) == false)
            return false;
        if (other.getStreamId() == null ^ this.getStreamId() == null)
            return false;
        if (other.getStreamId() != null && other.getStreamId().equals(this.getStreamId()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getDecryption() == null) ? 0 : getDecryption().hashCode());
        hashCode = prime * hashCode + ((getMinimumLatency() == null) ? 0 : getMinimumLatency().hashCode());
        hashCode = prime * hashCode + ((getSrtListenerAddress() == null) ? 0 : getSrtListenerAddress().hashCode());
        hashCode = prime * hashCode + ((getSrtListenerPort() == null) ? 0 : getSrtListenerPort().hashCode());
        hashCode = prime * hashCode + ((getStreamId() == null) ? 0 : getStreamId().hashCode());
        return hashCode;
    }

    @Override
    public SrtCallerSource clone() {
        try {
            return (SrtCallerSource) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.medialive.model.transform.SrtCallerSourceMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
