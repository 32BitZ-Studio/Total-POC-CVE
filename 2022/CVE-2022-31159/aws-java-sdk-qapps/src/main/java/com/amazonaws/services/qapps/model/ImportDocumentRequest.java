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

import com.amazonaws.AmazonWebServiceRequest;

/**
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/qapps-2023-11-27/ImportDocument" target="_top">AWS API
 *      Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class ImportDocumentRequest extends com.amazonaws.AmazonWebServiceRequest implements Serializable, Cloneable {

    /**
     * <p>
     * The unique identifier of the Amazon Q Business application environment instance.
     * </p>
     */
    private String instanceId;
    /**
     * <p>
     * The unique identifier of the card the file is associated with, if applicable.
     * </p>
     */
    private String cardId;
    /**
     * <p>
     * The unique identifier of the Q App the file is associated with.
     * </p>
     */
    private String appId;
    /**
     * <p>
     * The base64-encoded contents of the file to upload.
     * </p>
     */
    private String fileContentsBase64;
    /**
     * <p>
     * The name of the file being uploaded.
     * </p>
     */
    private String fileName;
    /**
     * <p>
     * Whether the file is associated with an Q App definition or a specific Q App session.
     * </p>
     */
    private String scope;
    /**
     * <p>
     * The unique identifier of the Q App session the file is associated with, if applicable.
     * </p>
     */
    private String sessionId;

    /**
     * <p>
     * The unique identifier of the Amazon Q Business application environment instance.
     * </p>
     * 
     * @param instanceId
     *        The unique identifier of the Amazon Q Business application environment instance.
     */

    public void setInstanceId(String instanceId) {
        this.instanceId = instanceId;
    }

    /**
     * <p>
     * The unique identifier of the Amazon Q Business application environment instance.
     * </p>
     * 
     * @return The unique identifier of the Amazon Q Business application environment instance.
     */

    public String getInstanceId() {
        return this.instanceId;
    }

    /**
     * <p>
     * The unique identifier of the Amazon Q Business application environment instance.
     * </p>
     * 
     * @param instanceId
     *        The unique identifier of the Amazon Q Business application environment instance.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ImportDocumentRequest withInstanceId(String instanceId) {
        setInstanceId(instanceId);
        return this;
    }

    /**
     * <p>
     * The unique identifier of the card the file is associated with, if applicable.
     * </p>
     * 
     * @param cardId
     *        The unique identifier of the card the file is associated with, if applicable.
     */

    public void setCardId(String cardId) {
        this.cardId = cardId;
    }

    /**
     * <p>
     * The unique identifier of the card the file is associated with, if applicable.
     * </p>
     * 
     * @return The unique identifier of the card the file is associated with, if applicable.
     */

    public String getCardId() {
        return this.cardId;
    }

    /**
     * <p>
     * The unique identifier of the card the file is associated with, if applicable.
     * </p>
     * 
     * @param cardId
     *        The unique identifier of the card the file is associated with, if applicable.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ImportDocumentRequest withCardId(String cardId) {
        setCardId(cardId);
        return this;
    }

    /**
     * <p>
     * The unique identifier of the Q App the file is associated with.
     * </p>
     * 
     * @param appId
     *        The unique identifier of the Q App the file is associated with.
     */

    public void setAppId(String appId) {
        this.appId = appId;
    }

    /**
     * <p>
     * The unique identifier of the Q App the file is associated with.
     * </p>
     * 
     * @return The unique identifier of the Q App the file is associated with.
     */

    public String getAppId() {
        return this.appId;
    }

    /**
     * <p>
     * The unique identifier of the Q App the file is associated with.
     * </p>
     * 
     * @param appId
     *        The unique identifier of the Q App the file is associated with.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ImportDocumentRequest withAppId(String appId) {
        setAppId(appId);
        return this;
    }

    /**
     * <p>
     * The base64-encoded contents of the file to upload.
     * </p>
     * 
     * @param fileContentsBase64
     *        The base64-encoded contents of the file to upload.
     */

    public void setFileContentsBase64(String fileContentsBase64) {
        this.fileContentsBase64 = fileContentsBase64;
    }

    /**
     * <p>
     * The base64-encoded contents of the file to upload.
     * </p>
     * 
     * @return The base64-encoded contents of the file to upload.
     */

    public String getFileContentsBase64() {
        return this.fileContentsBase64;
    }

    /**
     * <p>
     * The base64-encoded contents of the file to upload.
     * </p>
     * 
     * @param fileContentsBase64
     *        The base64-encoded contents of the file to upload.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ImportDocumentRequest withFileContentsBase64(String fileContentsBase64) {
        setFileContentsBase64(fileContentsBase64);
        return this;
    }

    /**
     * <p>
     * The name of the file being uploaded.
     * </p>
     * 
     * @param fileName
     *        The name of the file being uploaded.
     */

    public void setFileName(String fileName) {
        this.fileName = fileName;
    }

    /**
     * <p>
     * The name of the file being uploaded.
     * </p>
     * 
     * @return The name of the file being uploaded.
     */

    public String getFileName() {
        return this.fileName;
    }

    /**
     * <p>
     * The name of the file being uploaded.
     * </p>
     * 
     * @param fileName
     *        The name of the file being uploaded.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ImportDocumentRequest withFileName(String fileName) {
        setFileName(fileName);
        return this;
    }

    /**
     * <p>
     * Whether the file is associated with an Q App definition or a specific Q App session.
     * </p>
     * 
     * @param scope
     *        Whether the file is associated with an Q App definition or a specific Q App session.
     * @see DocumentScope
     */

    public void setScope(String scope) {
        this.scope = scope;
    }

    /**
     * <p>
     * Whether the file is associated with an Q App definition or a specific Q App session.
     * </p>
     * 
     * @return Whether the file is associated with an Q App definition or a specific Q App session.
     * @see DocumentScope
     */

    public String getScope() {
        return this.scope;
    }

    /**
     * <p>
     * Whether the file is associated with an Q App definition or a specific Q App session.
     * </p>
     * 
     * @param scope
     *        Whether the file is associated with an Q App definition or a specific Q App session.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see DocumentScope
     */

    public ImportDocumentRequest withScope(String scope) {
        setScope(scope);
        return this;
    }

    /**
     * <p>
     * Whether the file is associated with an Q App definition or a specific Q App session.
     * </p>
     * 
     * @param scope
     *        Whether the file is associated with an Q App definition or a specific Q App session.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see DocumentScope
     */

    public ImportDocumentRequest withScope(DocumentScope scope) {
        this.scope = scope.toString();
        return this;
    }

    /**
     * <p>
     * The unique identifier of the Q App session the file is associated with, if applicable.
     * </p>
     * 
     * @param sessionId
     *        The unique identifier of the Q App session the file is associated with, if applicable.
     */

    public void setSessionId(String sessionId) {
        this.sessionId = sessionId;
    }

    /**
     * <p>
     * The unique identifier of the Q App session the file is associated with, if applicable.
     * </p>
     * 
     * @return The unique identifier of the Q App session the file is associated with, if applicable.
     */

    public String getSessionId() {
        return this.sessionId;
    }

    /**
     * <p>
     * The unique identifier of the Q App session the file is associated with, if applicable.
     * </p>
     * 
     * @param sessionId
     *        The unique identifier of the Q App session the file is associated with, if applicable.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ImportDocumentRequest withSessionId(String sessionId) {
        setSessionId(sessionId);
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
        if (getInstanceId() != null)
            sb.append("InstanceId: ").append(getInstanceId()).append(",");
        if (getCardId() != null)
            sb.append("CardId: ").append(getCardId()).append(",");
        if (getAppId() != null)
            sb.append("AppId: ").append(getAppId()).append(",");
        if (getFileContentsBase64() != null)
            sb.append("FileContentsBase64: ").append(getFileContentsBase64()).append(",");
        if (getFileName() != null)
            sb.append("FileName: ").append(getFileName()).append(",");
        if (getScope() != null)
            sb.append("Scope: ").append(getScope()).append(",");
        if (getSessionId() != null)
            sb.append("SessionId: ").append(getSessionId());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof ImportDocumentRequest == false)
            return false;
        ImportDocumentRequest other = (ImportDocumentRequest) obj;
        if (other.getInstanceId() == null ^ this.getInstanceId() == null)
            return false;
        if (other.getInstanceId() != null && other.getInstanceId().equals(this.getInstanceId()) == false)
            return false;
        if (other.getCardId() == null ^ this.getCardId() == null)
            return false;
        if (other.getCardId() != null && other.getCardId().equals(this.getCardId()) == false)
            return false;
        if (other.getAppId() == null ^ this.getAppId() == null)
            return false;
        if (other.getAppId() != null && other.getAppId().equals(this.getAppId()) == false)
            return false;
        if (other.getFileContentsBase64() == null ^ this.getFileContentsBase64() == null)
            return false;
        if (other.getFileContentsBase64() != null && other.getFileContentsBase64().equals(this.getFileContentsBase64()) == false)
            return false;
        if (other.getFileName() == null ^ this.getFileName() == null)
            return false;
        if (other.getFileName() != null && other.getFileName().equals(this.getFileName()) == false)
            return false;
        if (other.getScope() == null ^ this.getScope() == null)
            return false;
        if (other.getScope() != null && other.getScope().equals(this.getScope()) == false)
            return false;
        if (other.getSessionId() == null ^ this.getSessionId() == null)
            return false;
        if (other.getSessionId() != null && other.getSessionId().equals(this.getSessionId()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getInstanceId() == null) ? 0 : getInstanceId().hashCode());
        hashCode = prime * hashCode + ((getCardId() == null) ? 0 : getCardId().hashCode());
        hashCode = prime * hashCode + ((getAppId() == null) ? 0 : getAppId().hashCode());
        hashCode = prime * hashCode + ((getFileContentsBase64() == null) ? 0 : getFileContentsBase64().hashCode());
        hashCode = prime * hashCode + ((getFileName() == null) ? 0 : getFileName().hashCode());
        hashCode = prime * hashCode + ((getScope() == null) ? 0 : getScope().hashCode());
        hashCode = prime * hashCode + ((getSessionId() == null) ? 0 : getSessionId().hashCode());
        return hashCode;
    }

    @Override
    public ImportDocumentRequest clone() {
        return (ImportDocumentRequest) super.clone();
    }

}
