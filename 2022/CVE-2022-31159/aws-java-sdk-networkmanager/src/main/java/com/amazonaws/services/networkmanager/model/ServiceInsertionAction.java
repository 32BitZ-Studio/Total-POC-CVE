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
package com.amazonaws.services.networkmanager.model;

import java.io.Serializable;
import javax.annotation.Generated;
import com.amazonaws.protocol.StructuredPojo;
import com.amazonaws.protocol.ProtocolMarshaller;

/**
 * <p>
 * Describes the action that the service insertion will take for any segments associated with it.
 * </p>
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/networkmanager-2019-07-05/ServiceInsertionAction"
 *      target="_top">AWS API Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class ServiceInsertionAction implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * The action the service insertion takes for traffic. <code>send-via</code> sends east-west traffic between
     * attachments. <code>send-to</code> sends north-south traffic to the security appliance, and then from that to
     * either the Internet or to an on-premesis location.
     * </p>
     */
    private String action;
    /**
     * <p>
     * Describes the mode packets take for the <code>send-via</code> action. This is not used when the action is
     * <code>send-to</code>. <code>dual-hop</code> packets traverse attachments in both the source to the destination
     * core network edges. This mode requires that an inspection attachment must be present in all Regions of the
     * service insertion-enabled segments. For <code>single-hop</code>, packets traverse a single intermediate inserted
     * attachment. You can use <code>EdgeOverride</code> to specify a specific edge to use.
     * </p>
     */
    private String mode;
    /**
     * <p>
     * The list of destination segments if the service insertion action is <code>send-via</code>.
     * </p>
     */
    private WhenSentTo whenSentTo;
    /**
     * <p>
     * The list of network function groups and any edge overrides for the chosen service insertion action. Used for both
     * <code>send-to</code> or <code>send-via</code>.
     * </p>
     */
    private Via via;

    /**
     * <p>
     * The action the service insertion takes for traffic. <code>send-via</code> sends east-west traffic between
     * attachments. <code>send-to</code> sends north-south traffic to the security appliance, and then from that to
     * either the Internet or to an on-premesis location.
     * </p>
     * 
     * @param action
     *        The action the service insertion takes for traffic. <code>send-via</code> sends east-west traffic between
     *        attachments. <code>send-to</code> sends north-south traffic to the security appliance, and then from that
     *        to either the Internet or to an on-premesis location.
     * @see SegmentActionServiceInsertion
     */

    public void setAction(String action) {
        this.action = action;
    }

    /**
     * <p>
     * The action the service insertion takes for traffic. <code>send-via</code> sends east-west traffic between
     * attachments. <code>send-to</code> sends north-south traffic to the security appliance, and then from that to
     * either the Internet or to an on-premesis location.
     * </p>
     * 
     * @return The action the service insertion takes for traffic. <code>send-via</code> sends east-west traffic between
     *         attachments. <code>send-to</code> sends north-south traffic to the security appliance, and then from that
     *         to either the Internet or to an on-premesis location.
     * @see SegmentActionServiceInsertion
     */

    public String getAction() {
        return this.action;
    }

    /**
     * <p>
     * The action the service insertion takes for traffic. <code>send-via</code> sends east-west traffic between
     * attachments. <code>send-to</code> sends north-south traffic to the security appliance, and then from that to
     * either the Internet or to an on-premesis location.
     * </p>
     * 
     * @param action
     *        The action the service insertion takes for traffic. <code>send-via</code> sends east-west traffic between
     *        attachments. <code>send-to</code> sends north-south traffic to the security appliance, and then from that
     *        to either the Internet or to an on-premesis location.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see SegmentActionServiceInsertion
     */

    public ServiceInsertionAction withAction(String action) {
        setAction(action);
        return this;
    }

    /**
     * <p>
     * The action the service insertion takes for traffic. <code>send-via</code> sends east-west traffic between
     * attachments. <code>send-to</code> sends north-south traffic to the security appliance, and then from that to
     * either the Internet or to an on-premesis location.
     * </p>
     * 
     * @param action
     *        The action the service insertion takes for traffic. <code>send-via</code> sends east-west traffic between
     *        attachments. <code>send-to</code> sends north-south traffic to the security appliance, and then from that
     *        to either the Internet or to an on-premesis location.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see SegmentActionServiceInsertion
     */

    public ServiceInsertionAction withAction(SegmentActionServiceInsertion action) {
        this.action = action.toString();
        return this;
    }

    /**
     * <p>
     * Describes the mode packets take for the <code>send-via</code> action. This is not used when the action is
     * <code>send-to</code>. <code>dual-hop</code> packets traverse attachments in both the source to the destination
     * core network edges. This mode requires that an inspection attachment must be present in all Regions of the
     * service insertion-enabled segments. For <code>single-hop</code>, packets traverse a single intermediate inserted
     * attachment. You can use <code>EdgeOverride</code> to specify a specific edge to use.
     * </p>
     * 
     * @param mode
     *        Describes the mode packets take for the <code>send-via</code> action. This is not used when the action is
     *        <code>send-to</code>. <code>dual-hop</code> packets traverse attachments in both the source to the
     *        destination core network edges. This mode requires that an inspection attachment must be present in all
     *        Regions of the service insertion-enabled segments. For <code>single-hop</code>, packets traverse a single
     *        intermediate inserted attachment. You can use <code>EdgeOverride</code> to specify a specific edge to use.
     * @see SendViaMode
     */

    public void setMode(String mode) {
        this.mode = mode;
    }

    /**
     * <p>
     * Describes the mode packets take for the <code>send-via</code> action. This is not used when the action is
     * <code>send-to</code>. <code>dual-hop</code> packets traverse attachments in both the source to the destination
     * core network edges. This mode requires that an inspection attachment must be present in all Regions of the
     * service insertion-enabled segments. For <code>single-hop</code>, packets traverse a single intermediate inserted
     * attachment. You can use <code>EdgeOverride</code> to specify a specific edge to use.
     * </p>
     * 
     * @return Describes the mode packets take for the <code>send-via</code> action. This is not used when the action is
     *         <code>send-to</code>. <code>dual-hop</code> packets traverse attachments in both the source to the
     *         destination core network edges. This mode requires that an inspection attachment must be present in all
     *         Regions of the service insertion-enabled segments. For <code>single-hop</code>, packets traverse a single
     *         intermediate inserted attachment. You can use <code>EdgeOverride</code> to specify a specific edge to
     *         use.
     * @see SendViaMode
     */

    public String getMode() {
        return this.mode;
    }

    /**
     * <p>
     * Describes the mode packets take for the <code>send-via</code> action. This is not used when the action is
     * <code>send-to</code>. <code>dual-hop</code> packets traverse attachments in both the source to the destination
     * core network edges. This mode requires that an inspection attachment must be present in all Regions of the
     * service insertion-enabled segments. For <code>single-hop</code>, packets traverse a single intermediate inserted
     * attachment. You can use <code>EdgeOverride</code> to specify a specific edge to use.
     * </p>
     * 
     * @param mode
     *        Describes the mode packets take for the <code>send-via</code> action. This is not used when the action is
     *        <code>send-to</code>. <code>dual-hop</code> packets traverse attachments in both the source to the
     *        destination core network edges. This mode requires that an inspection attachment must be present in all
     *        Regions of the service insertion-enabled segments. For <code>single-hop</code>, packets traverse a single
     *        intermediate inserted attachment. You can use <code>EdgeOverride</code> to specify a specific edge to use.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see SendViaMode
     */

    public ServiceInsertionAction withMode(String mode) {
        setMode(mode);
        return this;
    }

    /**
     * <p>
     * Describes the mode packets take for the <code>send-via</code> action. This is not used when the action is
     * <code>send-to</code>. <code>dual-hop</code> packets traverse attachments in both the source to the destination
     * core network edges. This mode requires that an inspection attachment must be present in all Regions of the
     * service insertion-enabled segments. For <code>single-hop</code>, packets traverse a single intermediate inserted
     * attachment. You can use <code>EdgeOverride</code> to specify a specific edge to use.
     * </p>
     * 
     * @param mode
     *        Describes the mode packets take for the <code>send-via</code> action. This is not used when the action is
     *        <code>send-to</code>. <code>dual-hop</code> packets traverse attachments in both the source to the
     *        destination core network edges. This mode requires that an inspection attachment must be present in all
     *        Regions of the service insertion-enabled segments. For <code>single-hop</code>, packets traverse a single
     *        intermediate inserted attachment. You can use <code>EdgeOverride</code> to specify a specific edge to use.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see SendViaMode
     */

    public ServiceInsertionAction withMode(SendViaMode mode) {
        this.mode = mode.toString();
        return this;
    }

    /**
     * <p>
     * The list of destination segments if the service insertion action is <code>send-via</code>.
     * </p>
     * 
     * @param whenSentTo
     *        The list of destination segments if the service insertion action is <code>send-via</code>.
     */

    public void setWhenSentTo(WhenSentTo whenSentTo) {
        this.whenSentTo = whenSentTo;
    }

    /**
     * <p>
     * The list of destination segments if the service insertion action is <code>send-via</code>.
     * </p>
     * 
     * @return The list of destination segments if the service insertion action is <code>send-via</code>.
     */

    public WhenSentTo getWhenSentTo() {
        return this.whenSentTo;
    }

    /**
     * <p>
     * The list of destination segments if the service insertion action is <code>send-via</code>.
     * </p>
     * 
     * @param whenSentTo
     *        The list of destination segments if the service insertion action is <code>send-via</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ServiceInsertionAction withWhenSentTo(WhenSentTo whenSentTo) {
        setWhenSentTo(whenSentTo);
        return this;
    }

    /**
     * <p>
     * The list of network function groups and any edge overrides for the chosen service insertion action. Used for both
     * <code>send-to</code> or <code>send-via</code>.
     * </p>
     * 
     * @param via
     *        The list of network function groups and any edge overrides for the chosen service insertion action. Used
     *        for both <code>send-to</code> or <code>send-via</code>.
     */

    public void setVia(Via via) {
        this.via = via;
    }

    /**
     * <p>
     * The list of network function groups and any edge overrides for the chosen service insertion action. Used for both
     * <code>send-to</code> or <code>send-via</code>.
     * </p>
     * 
     * @return The list of network function groups and any edge overrides for the chosen service insertion action. Used
     *         for both <code>send-to</code> or <code>send-via</code>.
     */

    public Via getVia() {
        return this.via;
    }

    /**
     * <p>
     * The list of network function groups and any edge overrides for the chosen service insertion action. Used for both
     * <code>send-to</code> or <code>send-via</code>.
     * </p>
     * 
     * @param via
     *        The list of network function groups and any edge overrides for the chosen service insertion action. Used
     *        for both <code>send-to</code> or <code>send-via</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ServiceInsertionAction withVia(Via via) {
        setVia(via);
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
        if (getAction() != null)
            sb.append("Action: ").append(getAction()).append(",");
        if (getMode() != null)
            sb.append("Mode: ").append(getMode()).append(",");
        if (getWhenSentTo() != null)
            sb.append("WhenSentTo: ").append(getWhenSentTo()).append(",");
        if (getVia() != null)
            sb.append("Via: ").append(getVia());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof ServiceInsertionAction == false)
            return false;
        ServiceInsertionAction other = (ServiceInsertionAction) obj;
        if (other.getAction() == null ^ this.getAction() == null)
            return false;
        if (other.getAction() != null && other.getAction().equals(this.getAction()) == false)
            return false;
        if (other.getMode() == null ^ this.getMode() == null)
            return false;
        if (other.getMode() != null && other.getMode().equals(this.getMode()) == false)
            return false;
        if (other.getWhenSentTo() == null ^ this.getWhenSentTo() == null)
            return false;
        if (other.getWhenSentTo() != null && other.getWhenSentTo().equals(this.getWhenSentTo()) == false)
            return false;
        if (other.getVia() == null ^ this.getVia() == null)
            return false;
        if (other.getVia() != null && other.getVia().equals(this.getVia()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getAction() == null) ? 0 : getAction().hashCode());
        hashCode = prime * hashCode + ((getMode() == null) ? 0 : getMode().hashCode());
        hashCode = prime * hashCode + ((getWhenSentTo() == null) ? 0 : getWhenSentTo().hashCode());
        hashCode = prime * hashCode + ((getVia() == null) ? 0 : getVia().hashCode());
        return hashCode;
    }

    @Override
    public ServiceInsertionAction clone() {
        try {
            return (ServiceInsertionAction) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.networkmanager.model.transform.ServiceInsertionActionMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
