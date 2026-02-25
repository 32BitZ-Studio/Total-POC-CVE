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
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/qapps-2023-11-27/PredictQApp" target="_top">AWS API
 *      Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class PredictQAppResult extends com.amazonaws.AmazonWebServiceResult<com.amazonaws.ResponseMetadata> implements Serializable, Cloneable {

    /**
     * <p>
     * The generated Q App definition.
     * </p>
     */
    private PredictAppDefinition app;
    /**
     * <p>
     * The problem statement extracted from the input conversation, if provided.
     * </p>
     */
    private String problemStatement;

    /**
     * <p>
     * The generated Q App definition.
     * </p>
     * 
     * @param app
     *        The generated Q App definition.
     */

    public void setApp(PredictAppDefinition app) {
        this.app = app;
    }

    /**
     * <p>
     * The generated Q App definition.
     * </p>
     * 
     * @return The generated Q App definition.
     */

    public PredictAppDefinition getApp() {
        return this.app;
    }

    /**
     * <p>
     * The generated Q App definition.
     * </p>
     * 
     * @param app
     *        The generated Q App definition.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public PredictQAppResult withApp(PredictAppDefinition app) {
        setApp(app);
        return this;
    }

    /**
     * <p>
     * The problem statement extracted from the input conversation, if provided.
     * </p>
     * 
     * @param problemStatement
     *        The problem statement extracted from the input conversation, if provided.
     */

    public void setProblemStatement(String problemStatement) {
        this.problemStatement = problemStatement;
    }

    /**
     * <p>
     * The problem statement extracted from the input conversation, if provided.
     * </p>
     * 
     * @return The problem statement extracted from the input conversation, if provided.
     */

    public String getProblemStatement() {
        return this.problemStatement;
    }

    /**
     * <p>
     * The problem statement extracted from the input conversation, if provided.
     * </p>
     * 
     * @param problemStatement
     *        The problem statement extracted from the input conversation, if provided.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public PredictQAppResult withProblemStatement(String problemStatement) {
        setProblemStatement(problemStatement);
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
        if (getApp() != null)
            sb.append("App: ").append(getApp()).append(",");
        if (getProblemStatement() != null)
            sb.append("ProblemStatement: ").append(getProblemStatement());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof PredictQAppResult == false)
            return false;
        PredictQAppResult other = (PredictQAppResult) obj;
        if (other.getApp() == null ^ this.getApp() == null)
            return false;
        if (other.getApp() != null && other.getApp().equals(this.getApp()) == false)
            return false;
        if (other.getProblemStatement() == null ^ this.getProblemStatement() == null)
            return false;
        if (other.getProblemStatement() != null && other.getProblemStatement().equals(this.getProblemStatement()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getApp() == null) ? 0 : getApp().hashCode());
        hashCode = prime * hashCode + ((getProblemStatement() == null) ? 0 : getProblemStatement().hashCode());
        return hashCode;
    }

    @Override
    public PredictQAppResult clone() {
        try {
            return (PredictQAppResult) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

}
