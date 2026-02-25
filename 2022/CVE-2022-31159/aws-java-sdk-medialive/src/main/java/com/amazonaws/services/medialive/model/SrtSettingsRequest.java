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
 * Configures the sources for this SRT input. For a single-pipeline input, include one srtCallerSource in the array. For
 * a standard-pipeline input, include two srtCallerSource.
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/medialive-2017-10-14/SrtSettingsRequest" target="_top">AWS API
 *      Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class SrtSettingsRequest implements Serializable, Cloneable, StructuredPojo {

    private java.util.List<SrtCallerSourceRequest> srtCallerSources;

    /**
     * @return
     */

    public java.util.List<SrtCallerSourceRequest> getSrtCallerSources() {
        return srtCallerSources;
    }

    /**
     * @param srtCallerSources
     */

    public void setSrtCallerSources(java.util.Collection<SrtCallerSourceRequest> srtCallerSources) {
        if (srtCallerSources == null) {
            this.srtCallerSources = null;
            return;
        }

        this.srtCallerSources = new java.util.ArrayList<SrtCallerSourceRequest>(srtCallerSources);
    }

    /**
     * <p>
     * <b>NOTE:</b> This method appends the values to the existing list (if any). Use
     * {@link #setSrtCallerSources(java.util.Collection)} or {@link #withSrtCallerSources(java.util.Collection)} if you
     * want to override the existing values.
     * </p>
     * 
     * @param srtCallerSources
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public SrtSettingsRequest withSrtCallerSources(SrtCallerSourceRequest... srtCallerSources) {
        if (this.srtCallerSources == null) {
            setSrtCallerSources(new java.util.ArrayList<SrtCallerSourceRequest>(srtCallerSources.length));
        }
        for (SrtCallerSourceRequest ele : srtCallerSources) {
            this.srtCallerSources.add(ele);
        }
        return this;
    }

    /**
     * @param srtCallerSources
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public SrtSettingsRequest withSrtCallerSources(java.util.Collection<SrtCallerSourceRequest> srtCallerSources) {
        setSrtCallerSources(srtCallerSources);
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
        if (getSrtCallerSources() != null)
            sb.append("SrtCallerSources: ").append(getSrtCallerSources());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof SrtSettingsRequest == false)
            return false;
        SrtSettingsRequest other = (SrtSettingsRequest) obj;
        if (other.getSrtCallerSources() == null ^ this.getSrtCallerSources() == null)
            return false;
        if (other.getSrtCallerSources() != null && other.getSrtCallerSources().equals(this.getSrtCallerSources()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getSrtCallerSources() == null) ? 0 : getSrtCallerSources().hashCode());
        return hashCode;
    }

    @Override
    public SrtSettingsRequest clone() {
        try {
            return (SrtSettingsRequest) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.medialive.model.transform.SrtSettingsRequestMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
