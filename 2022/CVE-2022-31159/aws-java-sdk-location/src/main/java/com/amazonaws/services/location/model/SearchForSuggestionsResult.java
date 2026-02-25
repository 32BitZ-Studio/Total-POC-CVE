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
 * Contains a place suggestion resulting from a place suggestion query that is run on a place index resource.
 * </p>
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/location-2020-11-19/SearchForSuggestionsResult"
 *      target="_top">AWS API Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class SearchForSuggestionsResult implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * The text of the place suggestion, typically formatted as an address string.
     * </p>
     */
    private String text;
    /**
     * <p>
     * The unique identifier of the Place. You can use this with the <code>GetPlace</code> operation to find the place
     * again later, or to get full information for the Place.
     * </p>
     * <p>
     * The <code>GetPlace</code> request must use the same <code>PlaceIndex</code> resource as the
     * <code>SearchPlaceIndexForSuggestions</code> that generated the Place ID.
     * </p>
     * <note>
     * <p>
     * For <code>SearchPlaceIndexForSuggestions</code> operations, the <code>PlaceId</code> is returned by place indexes
     * that use Esri, Grab, or HERE as data providers.
     * </p>
     * </note>
     */
    private String placeId;
    /**
     * <p>
     * The Amazon Location categories that describe the Place.
     * </p>
     * <p>
     * For more information about using categories, including a list of Amazon Location categories, see <a
     * href="https://docs.aws.amazon.com/location/latest/developerguide/category-filtering.html">Categories and
     * filtering</a>, in the <i>Amazon Location Service Developer Guide</i>.
     * </p>
     */
    private java.util.List<String> categories;
    /**
     * <p>
     * Categories from the data provider that describe the Place that are not mapped to any Amazon Location categories.
     * </p>
     */
    private java.util.List<String> supplementalCategories;

    /**
     * <p>
     * The text of the place suggestion, typically formatted as an address string.
     * </p>
     * 
     * @param text
     *        The text of the place suggestion, typically formatted as an address string.
     */

    public void setText(String text) {
        this.text = text;
    }

    /**
     * <p>
     * The text of the place suggestion, typically formatted as an address string.
     * </p>
     * 
     * @return The text of the place suggestion, typically formatted as an address string.
     */

    public String getText() {
        return this.text;
    }

    /**
     * <p>
     * The text of the place suggestion, typically formatted as an address string.
     * </p>
     * 
     * @param text
     *        The text of the place suggestion, typically formatted as an address string.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public SearchForSuggestionsResult withText(String text) {
        setText(text);
        return this;
    }

    /**
     * <p>
     * The unique identifier of the Place. You can use this with the <code>GetPlace</code> operation to find the place
     * again later, or to get full information for the Place.
     * </p>
     * <p>
     * The <code>GetPlace</code> request must use the same <code>PlaceIndex</code> resource as the
     * <code>SearchPlaceIndexForSuggestions</code> that generated the Place ID.
     * </p>
     * <note>
     * <p>
     * For <code>SearchPlaceIndexForSuggestions</code> operations, the <code>PlaceId</code> is returned by place indexes
     * that use Esri, Grab, or HERE as data providers.
     * </p>
     * </note>
     * 
     * @param placeId
     *        The unique identifier of the Place. You can use this with the <code>GetPlace</code> operation to find the
     *        place again later, or to get full information for the Place.</p>
     *        <p>
     *        The <code>GetPlace</code> request must use the same <code>PlaceIndex</code> resource as the
     *        <code>SearchPlaceIndexForSuggestions</code> that generated the Place ID.
     *        </p>
     *        <note>
     *        <p>
     *        For <code>SearchPlaceIndexForSuggestions</code> operations, the <code>PlaceId</code> is returned by place
     *        indexes that use Esri, Grab, or HERE as data providers.
     *        </p>
     */

    public void setPlaceId(String placeId) {
        this.placeId = placeId;
    }

    /**
     * <p>
     * The unique identifier of the Place. You can use this with the <code>GetPlace</code> operation to find the place
     * again later, or to get full information for the Place.
     * </p>
     * <p>
     * The <code>GetPlace</code> request must use the same <code>PlaceIndex</code> resource as the
     * <code>SearchPlaceIndexForSuggestions</code> that generated the Place ID.
     * </p>
     * <note>
     * <p>
     * For <code>SearchPlaceIndexForSuggestions</code> operations, the <code>PlaceId</code> is returned by place indexes
     * that use Esri, Grab, or HERE as data providers.
     * </p>
     * </note>
     * 
     * @return The unique identifier of the Place. You can use this with the <code>GetPlace</code> operation to find the
     *         place again later, or to get full information for the Place.</p>
     *         <p>
     *         The <code>GetPlace</code> request must use the same <code>PlaceIndex</code> resource as the
     *         <code>SearchPlaceIndexForSuggestions</code> that generated the Place ID.
     *         </p>
     *         <note>
     *         <p>
     *         For <code>SearchPlaceIndexForSuggestions</code> operations, the <code>PlaceId</code> is returned by place
     *         indexes that use Esri, Grab, or HERE as data providers.
     *         </p>
     */

    public String getPlaceId() {
        return this.placeId;
    }

    /**
     * <p>
     * The unique identifier of the Place. You can use this with the <code>GetPlace</code> operation to find the place
     * again later, or to get full information for the Place.
     * </p>
     * <p>
     * The <code>GetPlace</code> request must use the same <code>PlaceIndex</code> resource as the
     * <code>SearchPlaceIndexForSuggestions</code> that generated the Place ID.
     * </p>
     * <note>
     * <p>
     * For <code>SearchPlaceIndexForSuggestions</code> operations, the <code>PlaceId</code> is returned by place indexes
     * that use Esri, Grab, or HERE as data providers.
     * </p>
     * </note>
     * 
     * @param placeId
     *        The unique identifier of the Place. You can use this with the <code>GetPlace</code> operation to find the
     *        place again later, or to get full information for the Place.</p>
     *        <p>
     *        The <code>GetPlace</code> request must use the same <code>PlaceIndex</code> resource as the
     *        <code>SearchPlaceIndexForSuggestions</code> that generated the Place ID.
     *        </p>
     *        <note>
     *        <p>
     *        For <code>SearchPlaceIndexForSuggestions</code> operations, the <code>PlaceId</code> is returned by place
     *        indexes that use Esri, Grab, or HERE as data providers.
     *        </p>
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public SearchForSuggestionsResult withPlaceId(String placeId) {
        setPlaceId(placeId);
        return this;
    }

    /**
     * <p>
     * The Amazon Location categories that describe the Place.
     * </p>
     * <p>
     * For more information about using categories, including a list of Amazon Location categories, see <a
     * href="https://docs.aws.amazon.com/location/latest/developerguide/category-filtering.html">Categories and
     * filtering</a>, in the <i>Amazon Location Service Developer Guide</i>.
     * </p>
     * 
     * @return The Amazon Location categories that describe the Place.</p>
     *         <p>
     *         For more information about using categories, including a list of Amazon Location categories, see <a
     *         href="https://docs.aws.amazon.com/location/latest/developerguide/category-filtering.html">Categories and
     *         filtering</a>, in the <i>Amazon Location Service Developer Guide</i>.
     */

    public java.util.List<String> getCategories() {
        return categories;
    }

    /**
     * <p>
     * The Amazon Location categories that describe the Place.
     * </p>
     * <p>
     * For more information about using categories, including a list of Amazon Location categories, see <a
     * href="https://docs.aws.amazon.com/location/latest/developerguide/category-filtering.html">Categories and
     * filtering</a>, in the <i>Amazon Location Service Developer Guide</i>.
     * </p>
     * 
     * @param categories
     *        The Amazon Location categories that describe the Place.</p>
     *        <p>
     *        For more information about using categories, including a list of Amazon Location categories, see <a
     *        href="https://docs.aws.amazon.com/location/latest/developerguide/category-filtering.html">Categories and
     *        filtering</a>, in the <i>Amazon Location Service Developer Guide</i>.
     */

    public void setCategories(java.util.Collection<String> categories) {
        if (categories == null) {
            this.categories = null;
            return;
        }

        this.categories = new java.util.ArrayList<String>(categories);
    }

    /**
     * <p>
     * The Amazon Location categories that describe the Place.
     * </p>
     * <p>
     * For more information about using categories, including a list of Amazon Location categories, see <a
     * href="https://docs.aws.amazon.com/location/latest/developerguide/category-filtering.html">Categories and
     * filtering</a>, in the <i>Amazon Location Service Developer Guide</i>.
     * </p>
     * <p>
     * <b>NOTE:</b> This method appends the values to the existing list (if any). Use
     * {@link #setCategories(java.util.Collection)} or {@link #withCategories(java.util.Collection)} if you want to
     * override the existing values.
     * </p>
     * 
     * @param categories
     *        The Amazon Location categories that describe the Place.</p>
     *        <p>
     *        For more information about using categories, including a list of Amazon Location categories, see <a
     *        href="https://docs.aws.amazon.com/location/latest/developerguide/category-filtering.html">Categories and
     *        filtering</a>, in the <i>Amazon Location Service Developer Guide</i>.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public SearchForSuggestionsResult withCategories(String... categories) {
        if (this.categories == null) {
            setCategories(new java.util.ArrayList<String>(categories.length));
        }
        for (String ele : categories) {
            this.categories.add(ele);
        }
        return this;
    }

    /**
     * <p>
     * The Amazon Location categories that describe the Place.
     * </p>
     * <p>
     * For more information about using categories, including a list of Amazon Location categories, see <a
     * href="https://docs.aws.amazon.com/location/latest/developerguide/category-filtering.html">Categories and
     * filtering</a>, in the <i>Amazon Location Service Developer Guide</i>.
     * </p>
     * 
     * @param categories
     *        The Amazon Location categories that describe the Place.</p>
     *        <p>
     *        For more information about using categories, including a list of Amazon Location categories, see <a
     *        href="https://docs.aws.amazon.com/location/latest/developerguide/category-filtering.html">Categories and
     *        filtering</a>, in the <i>Amazon Location Service Developer Guide</i>.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public SearchForSuggestionsResult withCategories(java.util.Collection<String> categories) {
        setCategories(categories);
        return this;
    }

    /**
     * <p>
     * Categories from the data provider that describe the Place that are not mapped to any Amazon Location categories.
     * </p>
     * 
     * @return Categories from the data provider that describe the Place that are not mapped to any Amazon Location
     *         categories.
     */

    public java.util.List<String> getSupplementalCategories() {
        return supplementalCategories;
    }

    /**
     * <p>
     * Categories from the data provider that describe the Place that are not mapped to any Amazon Location categories.
     * </p>
     * 
     * @param supplementalCategories
     *        Categories from the data provider that describe the Place that are not mapped to any Amazon Location
     *        categories.
     */

    public void setSupplementalCategories(java.util.Collection<String> supplementalCategories) {
        if (supplementalCategories == null) {
            this.supplementalCategories = null;
            return;
        }

        this.supplementalCategories = new java.util.ArrayList<String>(supplementalCategories);
    }

    /**
     * <p>
     * Categories from the data provider that describe the Place that are not mapped to any Amazon Location categories.
     * </p>
     * <p>
     * <b>NOTE:</b> This method appends the values to the existing list (if any). Use
     * {@link #setSupplementalCategories(java.util.Collection)} or
     * {@link #withSupplementalCategories(java.util.Collection)} if you want to override the existing values.
     * </p>
     * 
     * @param supplementalCategories
     *        Categories from the data provider that describe the Place that are not mapped to any Amazon Location
     *        categories.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public SearchForSuggestionsResult withSupplementalCategories(String... supplementalCategories) {
        if (this.supplementalCategories == null) {
            setSupplementalCategories(new java.util.ArrayList<String>(supplementalCategories.length));
        }
        for (String ele : supplementalCategories) {
            this.supplementalCategories.add(ele);
        }
        return this;
    }

    /**
     * <p>
     * Categories from the data provider that describe the Place that are not mapped to any Amazon Location categories.
     * </p>
     * 
     * @param supplementalCategories
     *        Categories from the data provider that describe the Place that are not mapped to any Amazon Location
     *        categories.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public SearchForSuggestionsResult withSupplementalCategories(java.util.Collection<String> supplementalCategories) {
        setSupplementalCategories(supplementalCategories);
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
        if (getText() != null)
            sb.append("Text: ").append(getText()).append(",");
        if (getPlaceId() != null)
            sb.append("PlaceId: ").append(getPlaceId()).append(",");
        if (getCategories() != null)
            sb.append("Categories: ").append(getCategories()).append(",");
        if (getSupplementalCategories() != null)
            sb.append("SupplementalCategories: ").append(getSupplementalCategories());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof SearchForSuggestionsResult == false)
            return false;
        SearchForSuggestionsResult other = (SearchForSuggestionsResult) obj;
        if (other.getText() == null ^ this.getText() == null)
            return false;
        if (other.getText() != null && other.getText().equals(this.getText()) == false)
            return false;
        if (other.getPlaceId() == null ^ this.getPlaceId() == null)
            return false;
        if (other.getPlaceId() != null && other.getPlaceId().equals(this.getPlaceId()) == false)
            return false;
        if (other.getCategories() == null ^ this.getCategories() == null)
            return false;
        if (other.getCategories() != null && other.getCategories().equals(this.getCategories()) == false)
            return false;
        if (other.getSupplementalCategories() == null ^ this.getSupplementalCategories() == null)
            return false;
        if (other.getSupplementalCategories() != null && other.getSupplementalCategories().equals(this.getSupplementalCategories()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getText() == null) ? 0 : getText().hashCode());
        hashCode = prime * hashCode + ((getPlaceId() == null) ? 0 : getPlaceId().hashCode());
        hashCode = prime * hashCode + ((getCategories() == null) ? 0 : getCategories().hashCode());
        hashCode = prime * hashCode + ((getSupplementalCategories() == null) ? 0 : getSupplementalCategories().hashCode());
        return hashCode;
    }

    @Override
    public SearchForSuggestionsResult clone() {
        try {
            return (SearchForSuggestionsResult) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.location.model.transform.SearchForSuggestionsResultMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
