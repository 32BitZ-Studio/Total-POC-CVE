/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */
package com.amazonaws.services.s3.model;

import java.util.List;

/**
 * Response object for listing Amazon S3 buckets owned by a user.
 */
public class ListBucketsPaginatedResult {
    private Owner owner;
    private List<Bucket> buckets;
    private String continuationToken;
    private String prefix;

    /**
     * Returns the list of buckets owned by the requester.
     */
    public List<Bucket> getBuckets() {
        return buckets;
    }

    /**
     * Sets the buckets
     *
     * @param buckets The new buckets value.
     * @return This object for method chaining.
     */
    public void setBuckets(List<Bucket> buckets) {
        this.buckets = buckets;
    }

    /**
     * Sets the buckets
     *
     * @param buckets The new buckets value.
     * @return This object for method chaining.
     */
    public ListBucketsPaginatedResult withBuckets(List<Bucket> buckets) {
        setBuckets(buckets);
        return this;
    }

    /**
     * Returns the owner of the buckets listed.
     */
    public Owner getOwner() {
        return owner;
    }

    /**
     * Sets the owner of the buckets listed.
     */
    public void setOwner(Owner bucketsOwner) {
        this.owner = bucketsOwner;
    }

    /**
     * Sets the owner
     *
     * @param owner The new owner value.
     * @return This object for method chaining.
     */
    public ListBucketsPaginatedResult withOwner(Owner owner) {
        setOwner(owner);
        return this;
    }

    /**
     * Returns the continuationToken. ContinuationToken is included in the response when there are more buckets that can be
     * listed. The next list bucket request to Amazon S3 can be continued with this ContinuationToken. ContinuationToken is
     * obfuscated and is not a real bucket.
     */
    public String getContinuationToken() {
        return continuationToken;
    }

    /**
     * Sets the continuationToken. ContinuationToken is included in the response when there are more buckets that can be listed.
     * The next list bucket request to Amazon S3 can be continued with this ContinuationToken. ContinuationToken is
     * obfuscated and is not a real bucket.
     */
    public void setContinuationToken(String continuationToken) {
        this.continuationToken = continuationToken;
    }

    /**
     * Sets the continuationToken. ContinuationToken is included in the response when there are more buckets that can be listed.
     * The next list bucket request to Amazon S3 can be continued with this ContinuationToken. ContinuationToken is
     * obfuscated and is not a real bucket.
     *
     * @param continuationToken The new continuationToken value.
     * @return This object for method chaining.
     */
    public ListBucketsPaginatedResult withContinuationToken(String continuationToken) {
        setContinuationToken(continuationToken);
        return this;
    }

    /**
     * Returns the prefix used to filter bucket names in the response.
     */
    public String getPrefix() {
        return prefix;
    }

    /**
     * Sets the prefix used to filter bucket names in the response.
     *
     * @param prefix The new prefix value.
     */
    public void setPrefix(String prefix) {
        this.prefix = prefix;
    }

    /**
     * Sets the prefix used to filter bucket names in the response.
     *
     * @param prefix The new prefix value.
     * @return This object for method chaining.
     */
    public ListBucketsPaginatedResult withPrefix(String prefix) {
        setPrefix(prefix);
        return this;
    }
}
