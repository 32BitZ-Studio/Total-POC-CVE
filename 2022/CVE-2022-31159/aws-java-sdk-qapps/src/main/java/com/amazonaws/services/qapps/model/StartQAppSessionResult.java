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
package com.amazonaws.services.qapps.model;

import java.io.Serializable;
import javax.annotation.Generated;

/**
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/qapps-2023-11-27/StartQAppSession" target="_top">AWS API
 *      Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class StartQAppSessionResult extends com.amazonaws.AmazonWebServiceResult<com.amazonaws.ResponseMetadata> implements Serializable, Cloneable {

    /**
     * <p>
     * The unique identifier of the new Q App session.
     * </p>
     */
    private String sessionId;
    /**
     * <p>
     * The Amazon Resource Name (ARN) of the new Q App session.
     * </p>
     */
    private String sessionArn;

    /**
     * <p>
     * The unique identifier of the new Q App session.
     * </p>
     * 
     * @param sessionId
     *        The unique identifier of the new Q App session.
     */

    public void setSessionId(String sessionId) {
        this.sessionId = sessionId;
    }

    /**
     * <p>
     * The unique identifier of the new Q App session.
     * </p>
     * 
     * @return The unique identifier of the new Q App session.
     */

    public String getSessionId() {
        return this.sessionId;
    }

    /**
     * <p>
     * The unique identifier of the new Q App session.
     * </p>
     * 
     * @param sessionId
     *        The unique identifier of the new Q App session.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public StartQAppSessionResult withSessionId(String sessionId) {
        setSessionId(sessionId);
        return this;
    }

    /**
     * <p>
     * The Amazon Resource Name (ARN) of the new Q App session.
     * </p>
     * 
     * @param sessionArn
     *        The Amazon Resource Name (ARN) of the new Q App session.
     */

    public void setSessionArn(String sessionArn) {
        this.sessionArn = sessionArn;
    }

    /**
     * <p>
     * The Amazon Resource Name (ARN) of the new Q App session.
     * </p>
     * 
     * @return The Amazon Resource Name (ARN) of the new Q App session.
     */

    public String getSessionArn() {
        return this.sessionArn;
    }

    /**
     * <p>
     * The Amazon Resource Name (ARN) of the new Q App session.
     * </p>
     * 
     * @param sessionArn
     *        The Amazon Resource Name (ARN) of the new Q App session.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public StartQAppSessionResult withSessionArn(String sessionArn) {
        setSessionArn(sessionArn);
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
        if (getSessionId() != null)
            sb.append("SessionId: ").append(getSessionId()).append(",");
        if (getSessionArn() != null)
            sb.append("SessionArn: ").append(getSessionArn());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof StartQAppSessionResult == false)
            return false;
        StartQAppSessionResult other = (StartQAppSessionResult) obj;
        if (other.getSessionId() == null ^ this.getSessionId() == null)
            return false;
        if (other.getSessionId() != null && other.getSessionId().equals(this.getSessionId()) == false)
            return false;
        if (other.getSessionArn() == null ^ this.getSessionArn() == null)
            return false;
        if (other.getSessionArn() != null && other.getSessionArn().equals(this.getSessionArn()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getSessionId() == null) ? 0 : getSessionId().hashCode());
        hashCode = prime * hashCode + ((getSessionArn() == null) ? 0 : getSessionArn().hashCode());
        return hashCode;
    }

    @Override
    public StartQAppSessionResult clone() {
        try {
            return (StartQAppSessionResult) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

}
