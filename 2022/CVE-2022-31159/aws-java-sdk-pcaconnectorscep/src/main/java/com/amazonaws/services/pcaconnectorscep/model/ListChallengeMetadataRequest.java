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
package com.amazonaws.services.pcaconnectorscep.model;

import java.io.Serializable;
import javax.annotation.Generated;

import com.amazonaws.AmazonWebServiceRequest;

/**
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/pca-connector-scep-2018-05-10/ListChallengeMetadata"
 *      target="_top">AWS API Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class ListChallengeMetadataRequest extends com.amazonaws.AmazonWebServiceRequest implements Serializable, Cloneable {

    /**
     * <p>
     * The maximum number of objects that you want Connector for SCEP to return for this request. If more objects are
     * available, in the response, Connector for SCEP provides a <code>NextToken</code> value that you can use in a
     * subsequent call to get the next batch of objects.
     * </p>
     */
    private Integer maxResults;
    /**
     * <p>
     * When you request a list of objects with a <code>MaxResults</code> setting, if the number of objects that are
     * still available for retrieval exceeds the maximum you requested, Connector for SCEP returns a
     * <code>NextToken</code> value in the response. To retrieve the next batch of objects, use the token returned from
     * the prior request in your next request.
     * </p>
     */
    private String nextToken;
    /**
     * <p>
     * The Amazon Resource Name (ARN) of the connector.
     * </p>
     */
    private String connectorArn;

    /**
     * <p>
     * The maximum number of objects that you want Connector for SCEP to return for this request. If more objects are
     * available, in the response, Connector for SCEP provides a <code>NextToken</code> value that you can use in a
     * subsequent call to get the next batch of objects.
     * </p>
     * 
     * @param maxResults
     *        The maximum number of objects that you want Connector for SCEP to return for this request. If more objects
     *        are available, in the response, Connector for SCEP provides a <code>NextToken</code> value that you can
     *        use in a subsequent call to get the next batch of objects.
     */

    public void setMaxResults(Integer maxResults) {
        this.maxResults = maxResults;
    }

    /**
     * <p>
     * The maximum number of objects that you want Connector for SCEP to return for this request. If more objects are
     * available, in the response, Connector for SCEP provides a <code>NextToken</code> value that you can use in a
     * subsequent call to get the next batch of objects.
     * </p>
     * 
     * @return The maximum number of objects that you want Connector for SCEP to return for this request. If more
     *         objects are available, in the response, Connector for SCEP provides a <code>NextToken</code> value that
     *         you can use in a subsequent call to get the next batch of objects.
     */

    public Integer getMaxResults() {
        return this.maxResults;
    }

    /**
     * <p>
     * The maximum number of objects that you want Connector for SCEP to return for this request. If more objects are
     * available, in the response, Connector for SCEP provides a <code>NextToken</code> value that you can use in a
     * subsequent call to get the next batch of objects.
     * </p>
     * 
     * @param maxResults
     *        The maximum number of objects that you want Connector for SCEP to return for this request. If more objects
     *        are available, in the response, Connector for SCEP provides a <code>NextToken</code> value that you can
     *        use in a subsequent call to get the next batch of objects.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ListChallengeMetadataRequest withMaxResults(Integer maxResults) {
        setMaxResults(maxResults);
        return this;
    }

    /**
     * <p>
     * When you request a list of objects with a <code>MaxResults</code> setting, if the number of objects that are
     * still available for retrieval exceeds the maximum you requested, Connector for SCEP returns a
     * <code>NextToken</code> value in the response. To retrieve the next batch of objects, use the token returned from
     * the prior request in your next request.
     * </p>
     * 
     * @param nextToken
     *        When you request a list of objects with a <code>MaxResults</code> setting, if the number of objects that
     *        are still available for retrieval exceeds the maximum you requested, Connector for SCEP returns a
     *        <code>NextToken</code> value in the response. To retrieve the next batch of objects, use the token
     *        returned from the prior request in your next request.
     */

    public void setNextToken(String nextToken) {
        this.nextToken = nextToken;
    }

    /**
     * <p>
     * When you request a list of objects with a <code>MaxResults</code> setting, if the number of objects that are
     * still available for retrieval exceeds the maximum you requested, Connector for SCEP returns a
     * <code>NextToken</code> value in the response. To retrieve the next batch of objects, use the token returned from
     * the prior request in your next request.
     * </p>
     * 
     * @return When you request a list of objects with a <code>MaxResults</code> setting, if the number of objects that
     *         are still available for retrieval exceeds the maximum you requested, Connector for SCEP returns a
     *         <code>NextToken</code> value in the response. To retrieve the next batch of objects, use the token
     *         returned from the prior request in your next request.
     */

    public String getNextToken() {
        return this.nextToken;
    }

    /**
     * <p>
     * When you request a list of objects with a <code>MaxResults</code> setting, if the number of objects that are
     * still available for retrieval exceeds the maximum you requested, Connector for SCEP returns a
     * <code>NextToken</code> value in the response. To retrieve the next batch of objects, use the token returned from
     * the prior request in your next request.
     * </p>
     * 
     * @param nextToken
     *        When you request a list of objects with a <code>MaxResults</code> setting, if the number of objects that
     *        are still available for retrieval exceeds the maximum you requested, Connector for SCEP returns a
     *        <code>NextToken</code> value in the response. To retrieve the next batch of objects, use the token
     *        returned from the prior request in your next request.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ListChallengeMetadataRequest withNextToken(String nextToken) {
        setNextToken(nextToken);
        return this;
    }

    /**
     * <p>
     * The Amazon Resource Name (ARN) of the connector.
     * </p>
     * 
     * @param connectorArn
     *        The Amazon Resource Name (ARN) of the connector.
     */

    public void setConnectorArn(String connectorArn) {
        this.connectorArn = connectorArn;
    }

    /**
     * <p>
     * The Amazon Resource Name (ARN) of the connector.
     * </p>
     * 
     * @return The Amazon Resource Name (ARN) of the connector.
     */

    public String getConnectorArn() {
        return this.connectorArn;
    }

    /**
     * <p>
     * The Amazon Resource Name (ARN) of the connector.
     * </p>
     * 
     * @param connectorArn
     *        The Amazon Resource Name (ARN) of the connector.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ListChallengeMetadataRequest withConnectorArn(String connectorArn) {
        setConnectorArn(connectorArn);
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
        if (getMaxResults() != null)
            sb.append("MaxResults: ").append(getMaxResults()).append(",");
        if (getNextToken() != null)
            sb.append("NextToken: ").append(getNextToken()).append(",");
        if (getConnectorArn() != null)
            sb.append("ConnectorArn: ").append(getConnectorArn());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof ListChallengeMetadataRequest == false)
            return false;
        ListChallengeMetadataRequest other = (ListChallengeMetadataRequest) obj;
        if (other.getMaxResults() == null ^ this.getMaxResults() == null)
            return false;
        if (other.getMaxResults() != null && other.getMaxResults().equals(this.getMaxResults()) == false)
            return false;
        if (other.getNextToken() == null ^ this.getNextToken() == null)
            return false;
        if (other.getNextToken() != null && other.getNextToken().equals(this.getNextToken()) == false)
            return false;
        if (other.getConnectorArn() == null ^ this.getConnectorArn() == null)
            return false;
        if (other.getConnectorArn() != null && other.getConnectorArn().equals(this.getConnectorArn()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getMaxResults() == null) ? 0 : getMaxResults().hashCode());
        hashCode = prime * hashCode + ((getNextToken() == null) ? 0 : getNextToken().hashCode());
        hashCode = prime * hashCode + ((getConnectorArn() == null) ? 0 : getConnectorArn().hashCode());
        return hashCode;
    }

    @Override
    public ListChallengeMetadataRequest clone() {
        return (ListChallengeMetadataRequest) super.clone();
    }

}
