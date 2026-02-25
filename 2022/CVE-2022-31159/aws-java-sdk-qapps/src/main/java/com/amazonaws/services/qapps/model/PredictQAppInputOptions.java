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
import com.amazonaws.protocol.StructuredPojo;
import com.amazonaws.protocol.ProtocolMarshaller;

/**
 * <p>
 * The input options for generating an Q App definition.
 * </p>
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/qapps-2023-11-27/PredictQAppInputOptions" target="_top">AWS API
 *      Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class PredictQAppInputOptions implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * A conversation to use as input for generating the Q App definition.
     * </p>
     */
    private java.util.List<ConversationMessage> conversation;
    /**
     * <p>
     * A problem statement to use as input for generating the Q App definition.
     * </p>
     */
    private String problemStatement;

    /**
     * <p>
     * A conversation to use as input for generating the Q App definition.
     * </p>
     * 
     * @return A conversation to use as input for generating the Q App definition.
     */

    public java.util.List<ConversationMessage> getConversation() {
        return conversation;
    }

    /**
     * <p>
     * A conversation to use as input for generating the Q App definition.
     * </p>
     * 
     * @param conversation
     *        A conversation to use as input for generating the Q App definition.
     */

    public void setConversation(java.util.Collection<ConversationMessage> conversation) {
        if (conversation == null) {
            this.conversation = null;
            return;
        }

        this.conversation = new java.util.ArrayList<ConversationMessage>(conversation);
    }

    /**
     * <p>
     * A conversation to use as input for generating the Q App definition.
     * </p>
     * <p>
     * <b>NOTE:</b> This method appends the values to the existing list (if any). Use
     * {@link #setConversation(java.util.Collection)} or {@link #withConversation(java.util.Collection)} if you want to
     * override the existing values.
     * </p>
     * 
     * @param conversation
     *        A conversation to use as input for generating the Q App definition.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public PredictQAppInputOptions withConversation(ConversationMessage... conversation) {
        if (this.conversation == null) {
            setConversation(new java.util.ArrayList<ConversationMessage>(conversation.length));
        }
        for (ConversationMessage ele : conversation) {
            this.conversation.add(ele);
        }
        return this;
    }

    /**
     * <p>
     * A conversation to use as input for generating the Q App definition.
     * </p>
     * 
     * @param conversation
     *        A conversation to use as input for generating the Q App definition.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public PredictQAppInputOptions withConversation(java.util.Collection<ConversationMessage> conversation) {
        setConversation(conversation);
        return this;
    }

    /**
     * <p>
     * A problem statement to use as input for generating the Q App definition.
     * </p>
     * 
     * @param problemStatement
     *        A problem statement to use as input for generating the Q App definition.
     */

    public void setProblemStatement(String problemStatement) {
        this.problemStatement = problemStatement;
    }

    /**
     * <p>
     * A problem statement to use as input for generating the Q App definition.
     * </p>
     * 
     * @return A problem statement to use as input for generating the Q App definition.
     */

    public String getProblemStatement() {
        return this.problemStatement;
    }

    /**
     * <p>
     * A problem statement to use as input for generating the Q App definition.
     * </p>
     * 
     * @param problemStatement
     *        A problem statement to use as input for generating the Q App definition.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public PredictQAppInputOptions withProblemStatement(String problemStatement) {
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
        if (getConversation() != null)
            sb.append("Conversation: ").append(getConversation()).append(",");
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

        if (obj instanceof PredictQAppInputOptions == false)
            return false;
        PredictQAppInputOptions other = (PredictQAppInputOptions) obj;
        if (other.getConversation() == null ^ this.getConversation() == null)
            return false;
        if (other.getConversation() != null && other.getConversation().equals(this.getConversation()) == false)
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

        hashCode = prime * hashCode + ((getConversation() == null) ? 0 : getConversation().hashCode());
        hashCode = prime * hashCode + ((getProblemStatement() == null) ? 0 : getProblemStatement().hashCode());
        return hashCode;
    }

    @Override
    public PredictQAppInputOptions clone() {
        try {
            return (PredictQAppInputOptions) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.qapps.model.transform.PredictQAppInputOptionsMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
