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
package com.amazonaws.services.taxsettings.model;

import java.io.Serializable;
import javax.annotation.Generated;
import com.amazonaws.protocol.StructuredPojo;
import com.amazonaws.protocol.ProtocolMarshaller;

/**
 * <p>
 * Additional tax information associated with your TRN. The Tax Settings API returns country-specific information in the
 * response when any additional information is present with your TRN for the following countries.
 * </p>
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/taxsettings-2018-05-10/AdditionalInfoResponse" target="_top">AWS
 *      API Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class AdditionalInfoResponse implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * Additional tax information associated with your TRN in Brazil. The Tax Settings API returns this information in
     * your response when any additional information is present with your TRN in Brazil.
     * </p>
     */
    private BrazilAdditionalInfo brazilAdditionalInfo;
    /**
     * <p>
     * Additional tax information associated with your TRN in Canada.
     * </p>
     */
    private CanadaAdditionalInfo canadaAdditionalInfo;
    /**
     * <p>
     * Additional tax information associated with your TRN in Estonia.
     * </p>
     */
    private EstoniaAdditionalInfo estoniaAdditionalInfo;
    /**
     * <p>
     * Additional tax information associated with your TRN in Georgia.
     * </p>
     */
    private GeorgiaAdditionalInfo georgiaAdditionalInfo;
    /**
     * <p>
     * Additional tax information in India.
     * </p>
     */
    private IndiaAdditionalInfo indiaAdditionalInfo;
    /**
     * <p>
     * Additional tax information associated with your TRN in Israel.
     * </p>
     */
    private IsraelAdditionalInfo israelAdditionalInfo;
    /**
     * <p>
     * Additional tax information associated with your TRN in Italy.
     * </p>
     */
    private ItalyAdditionalInfo italyAdditionalInfo;
    /**
     * <p>
     * Additional tax information associated with your TRN in Kenya.
     * </p>
     */
    private KenyaAdditionalInfo kenyaAdditionalInfo;
    /**
     * <p>
     * Additional tax information associated with your TRN in Malaysia.
     * </p>
     */
    private MalaysiaAdditionalInfo malaysiaAdditionalInfo;
    /**
     * <p>
     * Additional tax information associated with your TRN in Poland.
     * </p>
     */
    private PolandAdditionalInfo polandAdditionalInfo;
    /**
     * <p>
     * Additional tax information to specify for a TRN in Romania.
     * </p>
     */
    private RomaniaAdditionalInfo romaniaAdditionalInfo;
    /**
     * <p>
     * Additional tax information associated with your TRN in Saudi Arabia.
     * </p>
     */
    private SaudiArabiaAdditionalInfo saudiArabiaAdditionalInfo;
    /**
     * <p>
     * Additional tax information associated with your TRN in South Korea.
     * </p>
     */
    private SouthKoreaAdditionalInfo southKoreaAdditionalInfo;
    /**
     * <p>
     * Additional tax information associated with your TRN in Spain.
     * </p>
     */
    private SpainAdditionalInfo spainAdditionalInfo;
    /**
     * <p>
     * Additional tax information associated with your TRN in Turkey.
     * </p>
     */
    private TurkeyAdditionalInfo turkeyAdditionalInfo;
    /**
     * <p>
     * Additional tax information associated with your TRN in Ukraine.
     * </p>
     */
    private UkraineAdditionalInfo ukraineAdditionalInfo;

    /**
     * <p>
     * Additional tax information associated with your TRN in Brazil. The Tax Settings API returns this information in
     * your response when any additional information is present with your TRN in Brazil.
     * </p>
     * 
     * @param brazilAdditionalInfo
     *        Additional tax information associated with your TRN in Brazil. The Tax Settings API returns this
     *        information in your response when any additional information is present with your TRN in Brazil.
     */

    public void setBrazilAdditionalInfo(BrazilAdditionalInfo brazilAdditionalInfo) {
        this.brazilAdditionalInfo = brazilAdditionalInfo;
    }

    /**
     * <p>
     * Additional tax information associated with your TRN in Brazil. The Tax Settings API returns this information in
     * your response when any additional information is present with your TRN in Brazil.
     * </p>
     * 
     * @return Additional tax information associated with your TRN in Brazil. The Tax Settings API returns this
     *         information in your response when any additional information is present with your TRN in Brazil.
     */

    public BrazilAdditionalInfo getBrazilAdditionalInfo() {
        return this.brazilAdditionalInfo;
    }

    /**
     * <p>
     * Additional tax information associated with your TRN in Brazil. The Tax Settings API returns this information in
     * your response when any additional information is present with your TRN in Brazil.
     * </p>
     * 
     * @param brazilAdditionalInfo
     *        Additional tax information associated with your TRN in Brazil. The Tax Settings API returns this
     *        information in your response when any additional information is present with your TRN in Brazil.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public AdditionalInfoResponse withBrazilAdditionalInfo(BrazilAdditionalInfo brazilAdditionalInfo) {
        setBrazilAdditionalInfo(brazilAdditionalInfo);
        return this;
    }

    /**
     * <p>
     * Additional tax information associated with your TRN in Canada.
     * </p>
     * 
     * @param canadaAdditionalInfo
     *        Additional tax information associated with your TRN in Canada.
     */

    public void setCanadaAdditionalInfo(CanadaAdditionalInfo canadaAdditionalInfo) {
        this.canadaAdditionalInfo = canadaAdditionalInfo;
    }

    /**
     * <p>
     * Additional tax information associated with your TRN in Canada.
     * </p>
     * 
     * @return Additional tax information associated with your TRN in Canada.
     */

    public CanadaAdditionalInfo getCanadaAdditionalInfo() {
        return this.canadaAdditionalInfo;
    }

    /**
     * <p>
     * Additional tax information associated with your TRN in Canada.
     * </p>
     * 
     * @param canadaAdditionalInfo
     *        Additional tax information associated with your TRN in Canada.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public AdditionalInfoResponse withCanadaAdditionalInfo(CanadaAdditionalInfo canadaAdditionalInfo) {
        setCanadaAdditionalInfo(canadaAdditionalInfo);
        return this;
    }

    /**
     * <p>
     * Additional tax information associated with your TRN in Estonia.
     * </p>
     * 
     * @param estoniaAdditionalInfo
     *        Additional tax information associated with your TRN in Estonia.
     */

    public void setEstoniaAdditionalInfo(EstoniaAdditionalInfo estoniaAdditionalInfo) {
        this.estoniaAdditionalInfo = estoniaAdditionalInfo;
    }

    /**
     * <p>
     * Additional tax information associated with your TRN in Estonia.
     * </p>
     * 
     * @return Additional tax information associated with your TRN in Estonia.
     */

    public EstoniaAdditionalInfo getEstoniaAdditionalInfo() {
        return this.estoniaAdditionalInfo;
    }

    /**
     * <p>
     * Additional tax information associated with your TRN in Estonia.
     * </p>
     * 
     * @param estoniaAdditionalInfo
     *        Additional tax information associated with your TRN in Estonia.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public AdditionalInfoResponse withEstoniaAdditionalInfo(EstoniaAdditionalInfo estoniaAdditionalInfo) {
        setEstoniaAdditionalInfo(estoniaAdditionalInfo);
        return this;
    }

    /**
     * <p>
     * Additional tax information associated with your TRN in Georgia.
     * </p>
     * 
     * @param georgiaAdditionalInfo
     *        Additional tax information associated with your TRN in Georgia.
     */

    public void setGeorgiaAdditionalInfo(GeorgiaAdditionalInfo georgiaAdditionalInfo) {
        this.georgiaAdditionalInfo = georgiaAdditionalInfo;
    }

    /**
     * <p>
     * Additional tax information associated with your TRN in Georgia.
     * </p>
     * 
     * @return Additional tax information associated with your TRN in Georgia.
     */

    public GeorgiaAdditionalInfo getGeorgiaAdditionalInfo() {
        return this.georgiaAdditionalInfo;
    }

    /**
     * <p>
     * Additional tax information associated with your TRN in Georgia.
     * </p>
     * 
     * @param georgiaAdditionalInfo
     *        Additional tax information associated with your TRN in Georgia.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public AdditionalInfoResponse withGeorgiaAdditionalInfo(GeorgiaAdditionalInfo georgiaAdditionalInfo) {
        setGeorgiaAdditionalInfo(georgiaAdditionalInfo);
        return this;
    }

    /**
     * <p>
     * Additional tax information in India.
     * </p>
     * 
     * @param indiaAdditionalInfo
     *        Additional tax information in India.
     */

    public void setIndiaAdditionalInfo(IndiaAdditionalInfo indiaAdditionalInfo) {
        this.indiaAdditionalInfo = indiaAdditionalInfo;
    }

    /**
     * <p>
     * Additional tax information in India.
     * </p>
     * 
     * @return Additional tax information in India.
     */

    public IndiaAdditionalInfo getIndiaAdditionalInfo() {
        return this.indiaAdditionalInfo;
    }

    /**
     * <p>
     * Additional tax information in India.
     * </p>
     * 
     * @param indiaAdditionalInfo
     *        Additional tax information in India.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public AdditionalInfoResponse withIndiaAdditionalInfo(IndiaAdditionalInfo indiaAdditionalInfo) {
        setIndiaAdditionalInfo(indiaAdditionalInfo);
        return this;
    }

    /**
     * <p>
     * Additional tax information associated with your TRN in Israel.
     * </p>
     * 
     * @param israelAdditionalInfo
     *        Additional tax information associated with your TRN in Israel.
     */

    public void setIsraelAdditionalInfo(IsraelAdditionalInfo israelAdditionalInfo) {
        this.israelAdditionalInfo = israelAdditionalInfo;
    }

    /**
     * <p>
     * Additional tax information associated with your TRN in Israel.
     * </p>
     * 
     * @return Additional tax information associated with your TRN in Israel.
     */

    public IsraelAdditionalInfo getIsraelAdditionalInfo() {
        return this.israelAdditionalInfo;
    }

    /**
     * <p>
     * Additional tax information associated with your TRN in Israel.
     * </p>
     * 
     * @param israelAdditionalInfo
     *        Additional tax information associated with your TRN in Israel.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public AdditionalInfoResponse withIsraelAdditionalInfo(IsraelAdditionalInfo israelAdditionalInfo) {
        setIsraelAdditionalInfo(israelAdditionalInfo);
        return this;
    }

    /**
     * <p>
     * Additional tax information associated with your TRN in Italy.
     * </p>
     * 
     * @param italyAdditionalInfo
     *        Additional tax information associated with your TRN in Italy.
     */

    public void setItalyAdditionalInfo(ItalyAdditionalInfo italyAdditionalInfo) {
        this.italyAdditionalInfo = italyAdditionalInfo;
    }

    /**
     * <p>
     * Additional tax information associated with your TRN in Italy.
     * </p>
     * 
     * @return Additional tax information associated with your TRN in Italy.
     */

    public ItalyAdditionalInfo getItalyAdditionalInfo() {
        return this.italyAdditionalInfo;
    }

    /**
     * <p>
     * Additional tax information associated with your TRN in Italy.
     * </p>
     * 
     * @param italyAdditionalInfo
     *        Additional tax information associated with your TRN in Italy.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public AdditionalInfoResponse withItalyAdditionalInfo(ItalyAdditionalInfo italyAdditionalInfo) {
        setItalyAdditionalInfo(italyAdditionalInfo);
        return this;
    }

    /**
     * <p>
     * Additional tax information associated with your TRN in Kenya.
     * </p>
     * 
     * @param kenyaAdditionalInfo
     *        Additional tax information associated with your TRN in Kenya.
     */

    public void setKenyaAdditionalInfo(KenyaAdditionalInfo kenyaAdditionalInfo) {
        this.kenyaAdditionalInfo = kenyaAdditionalInfo;
    }

    /**
     * <p>
     * Additional tax information associated with your TRN in Kenya.
     * </p>
     * 
     * @return Additional tax information associated with your TRN in Kenya.
     */

    public KenyaAdditionalInfo getKenyaAdditionalInfo() {
        return this.kenyaAdditionalInfo;
    }

    /**
     * <p>
     * Additional tax information associated with your TRN in Kenya.
     * </p>
     * 
     * @param kenyaAdditionalInfo
     *        Additional tax information associated with your TRN in Kenya.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public AdditionalInfoResponse withKenyaAdditionalInfo(KenyaAdditionalInfo kenyaAdditionalInfo) {
        setKenyaAdditionalInfo(kenyaAdditionalInfo);
        return this;
    }

    /**
     * <p>
     * Additional tax information associated with your TRN in Malaysia.
     * </p>
     * 
     * @param malaysiaAdditionalInfo
     *        Additional tax information associated with your TRN in Malaysia.
     */

    public void setMalaysiaAdditionalInfo(MalaysiaAdditionalInfo malaysiaAdditionalInfo) {
        this.malaysiaAdditionalInfo = malaysiaAdditionalInfo;
    }

    /**
     * <p>
     * Additional tax information associated with your TRN in Malaysia.
     * </p>
     * 
     * @return Additional tax information associated with your TRN in Malaysia.
     */

    public MalaysiaAdditionalInfo getMalaysiaAdditionalInfo() {
        return this.malaysiaAdditionalInfo;
    }

    /**
     * <p>
     * Additional tax information associated with your TRN in Malaysia.
     * </p>
     * 
     * @param malaysiaAdditionalInfo
     *        Additional tax information associated with your TRN in Malaysia.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public AdditionalInfoResponse withMalaysiaAdditionalInfo(MalaysiaAdditionalInfo malaysiaAdditionalInfo) {
        setMalaysiaAdditionalInfo(malaysiaAdditionalInfo);
        return this;
    }

    /**
     * <p>
     * Additional tax information associated with your TRN in Poland.
     * </p>
     * 
     * @param polandAdditionalInfo
     *        Additional tax information associated with your TRN in Poland.
     */

    public void setPolandAdditionalInfo(PolandAdditionalInfo polandAdditionalInfo) {
        this.polandAdditionalInfo = polandAdditionalInfo;
    }

    /**
     * <p>
     * Additional tax information associated with your TRN in Poland.
     * </p>
     * 
     * @return Additional tax information associated with your TRN in Poland.
     */

    public PolandAdditionalInfo getPolandAdditionalInfo() {
        return this.polandAdditionalInfo;
    }

    /**
     * <p>
     * Additional tax information associated with your TRN in Poland.
     * </p>
     * 
     * @param polandAdditionalInfo
     *        Additional tax information associated with your TRN in Poland.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public AdditionalInfoResponse withPolandAdditionalInfo(PolandAdditionalInfo polandAdditionalInfo) {
        setPolandAdditionalInfo(polandAdditionalInfo);
        return this;
    }

    /**
     * <p>
     * Additional tax information to specify for a TRN in Romania.
     * </p>
     * 
     * @param romaniaAdditionalInfo
     *        Additional tax information to specify for a TRN in Romania.
     */

    public void setRomaniaAdditionalInfo(RomaniaAdditionalInfo romaniaAdditionalInfo) {
        this.romaniaAdditionalInfo = romaniaAdditionalInfo;
    }

    /**
     * <p>
     * Additional tax information to specify for a TRN in Romania.
     * </p>
     * 
     * @return Additional tax information to specify for a TRN in Romania.
     */

    public RomaniaAdditionalInfo getRomaniaAdditionalInfo() {
        return this.romaniaAdditionalInfo;
    }

    /**
     * <p>
     * Additional tax information to specify for a TRN in Romania.
     * </p>
     * 
     * @param romaniaAdditionalInfo
     *        Additional tax information to specify for a TRN in Romania.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public AdditionalInfoResponse withRomaniaAdditionalInfo(RomaniaAdditionalInfo romaniaAdditionalInfo) {
        setRomaniaAdditionalInfo(romaniaAdditionalInfo);
        return this;
    }

    /**
     * <p>
     * Additional tax information associated with your TRN in Saudi Arabia.
     * </p>
     * 
     * @param saudiArabiaAdditionalInfo
     *        Additional tax information associated with your TRN in Saudi Arabia.
     */

    public void setSaudiArabiaAdditionalInfo(SaudiArabiaAdditionalInfo saudiArabiaAdditionalInfo) {
        this.saudiArabiaAdditionalInfo = saudiArabiaAdditionalInfo;
    }

    /**
     * <p>
     * Additional tax information associated with your TRN in Saudi Arabia.
     * </p>
     * 
     * @return Additional tax information associated with your TRN in Saudi Arabia.
     */

    public SaudiArabiaAdditionalInfo getSaudiArabiaAdditionalInfo() {
        return this.saudiArabiaAdditionalInfo;
    }

    /**
     * <p>
     * Additional tax information associated with your TRN in Saudi Arabia.
     * </p>
     * 
     * @param saudiArabiaAdditionalInfo
     *        Additional tax information associated with your TRN in Saudi Arabia.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public AdditionalInfoResponse withSaudiArabiaAdditionalInfo(SaudiArabiaAdditionalInfo saudiArabiaAdditionalInfo) {
        setSaudiArabiaAdditionalInfo(saudiArabiaAdditionalInfo);
        return this;
    }

    /**
     * <p>
     * Additional tax information associated with your TRN in South Korea.
     * </p>
     * 
     * @param southKoreaAdditionalInfo
     *        Additional tax information associated with your TRN in South Korea.
     */

    public void setSouthKoreaAdditionalInfo(SouthKoreaAdditionalInfo southKoreaAdditionalInfo) {
        this.southKoreaAdditionalInfo = southKoreaAdditionalInfo;
    }

    /**
     * <p>
     * Additional tax information associated with your TRN in South Korea.
     * </p>
     * 
     * @return Additional tax information associated with your TRN in South Korea.
     */

    public SouthKoreaAdditionalInfo getSouthKoreaAdditionalInfo() {
        return this.southKoreaAdditionalInfo;
    }

    /**
     * <p>
     * Additional tax information associated with your TRN in South Korea.
     * </p>
     * 
     * @param southKoreaAdditionalInfo
     *        Additional tax information associated with your TRN in South Korea.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public AdditionalInfoResponse withSouthKoreaAdditionalInfo(SouthKoreaAdditionalInfo southKoreaAdditionalInfo) {
        setSouthKoreaAdditionalInfo(southKoreaAdditionalInfo);
        return this;
    }

    /**
     * <p>
     * Additional tax information associated with your TRN in Spain.
     * </p>
     * 
     * @param spainAdditionalInfo
     *        Additional tax information associated with your TRN in Spain.
     */

    public void setSpainAdditionalInfo(SpainAdditionalInfo spainAdditionalInfo) {
        this.spainAdditionalInfo = spainAdditionalInfo;
    }

    /**
     * <p>
     * Additional tax information associated with your TRN in Spain.
     * </p>
     * 
     * @return Additional tax information associated with your TRN in Spain.
     */

    public SpainAdditionalInfo getSpainAdditionalInfo() {
        return this.spainAdditionalInfo;
    }

    /**
     * <p>
     * Additional tax information associated with your TRN in Spain.
     * </p>
     * 
     * @param spainAdditionalInfo
     *        Additional tax information associated with your TRN in Spain.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public AdditionalInfoResponse withSpainAdditionalInfo(SpainAdditionalInfo spainAdditionalInfo) {
        setSpainAdditionalInfo(spainAdditionalInfo);
        return this;
    }

    /**
     * <p>
     * Additional tax information associated with your TRN in Turkey.
     * </p>
     * 
     * @param turkeyAdditionalInfo
     *        Additional tax information associated with your TRN in Turkey.
     */

    public void setTurkeyAdditionalInfo(TurkeyAdditionalInfo turkeyAdditionalInfo) {
        this.turkeyAdditionalInfo = turkeyAdditionalInfo;
    }

    /**
     * <p>
     * Additional tax information associated with your TRN in Turkey.
     * </p>
     * 
     * @return Additional tax information associated with your TRN in Turkey.
     */

    public TurkeyAdditionalInfo getTurkeyAdditionalInfo() {
        return this.turkeyAdditionalInfo;
    }

    /**
     * <p>
     * Additional tax information associated with your TRN in Turkey.
     * </p>
     * 
     * @param turkeyAdditionalInfo
     *        Additional tax information associated with your TRN in Turkey.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public AdditionalInfoResponse withTurkeyAdditionalInfo(TurkeyAdditionalInfo turkeyAdditionalInfo) {
        setTurkeyAdditionalInfo(turkeyAdditionalInfo);
        return this;
    }

    /**
     * <p>
     * Additional tax information associated with your TRN in Ukraine.
     * </p>
     * 
     * @param ukraineAdditionalInfo
     *        Additional tax information associated with your TRN in Ukraine.
     */

    public void setUkraineAdditionalInfo(UkraineAdditionalInfo ukraineAdditionalInfo) {
        this.ukraineAdditionalInfo = ukraineAdditionalInfo;
    }

    /**
     * <p>
     * Additional tax information associated with your TRN in Ukraine.
     * </p>
     * 
     * @return Additional tax information associated with your TRN in Ukraine.
     */

    public UkraineAdditionalInfo getUkraineAdditionalInfo() {
        return this.ukraineAdditionalInfo;
    }

    /**
     * <p>
     * Additional tax information associated with your TRN in Ukraine.
     * </p>
     * 
     * @param ukraineAdditionalInfo
     *        Additional tax information associated with your TRN in Ukraine.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public AdditionalInfoResponse withUkraineAdditionalInfo(UkraineAdditionalInfo ukraineAdditionalInfo) {
        setUkraineAdditionalInfo(ukraineAdditionalInfo);
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
        if (getBrazilAdditionalInfo() != null)
            sb.append("BrazilAdditionalInfo: ").append(getBrazilAdditionalInfo()).append(",");
        if (getCanadaAdditionalInfo() != null)
            sb.append("CanadaAdditionalInfo: ").append(getCanadaAdditionalInfo()).append(",");
        if (getEstoniaAdditionalInfo() != null)
            sb.append("EstoniaAdditionalInfo: ").append(getEstoniaAdditionalInfo()).append(",");
        if (getGeorgiaAdditionalInfo() != null)
            sb.append("GeorgiaAdditionalInfo: ").append(getGeorgiaAdditionalInfo()).append(",");
        if (getIndiaAdditionalInfo() != null)
            sb.append("IndiaAdditionalInfo: ").append(getIndiaAdditionalInfo()).append(",");
        if (getIsraelAdditionalInfo() != null)
            sb.append("IsraelAdditionalInfo: ").append(getIsraelAdditionalInfo()).append(",");
        if (getItalyAdditionalInfo() != null)
            sb.append("ItalyAdditionalInfo: ").append(getItalyAdditionalInfo()).append(",");
        if (getKenyaAdditionalInfo() != null)
            sb.append("KenyaAdditionalInfo: ").append(getKenyaAdditionalInfo()).append(",");
        if (getMalaysiaAdditionalInfo() != null)
            sb.append("MalaysiaAdditionalInfo: ").append(getMalaysiaAdditionalInfo()).append(",");
        if (getPolandAdditionalInfo() != null)
            sb.append("PolandAdditionalInfo: ").append(getPolandAdditionalInfo()).append(",");
        if (getRomaniaAdditionalInfo() != null)
            sb.append("RomaniaAdditionalInfo: ").append(getRomaniaAdditionalInfo()).append(",");
        if (getSaudiArabiaAdditionalInfo() != null)
            sb.append("SaudiArabiaAdditionalInfo: ").append(getSaudiArabiaAdditionalInfo()).append(",");
        if (getSouthKoreaAdditionalInfo() != null)
            sb.append("SouthKoreaAdditionalInfo: ").append(getSouthKoreaAdditionalInfo()).append(",");
        if (getSpainAdditionalInfo() != null)
            sb.append("SpainAdditionalInfo: ").append(getSpainAdditionalInfo()).append(",");
        if (getTurkeyAdditionalInfo() != null)
            sb.append("TurkeyAdditionalInfo: ").append(getTurkeyAdditionalInfo()).append(",");
        if (getUkraineAdditionalInfo() != null)
            sb.append("UkraineAdditionalInfo: ").append(getUkraineAdditionalInfo());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof AdditionalInfoResponse == false)
            return false;
        AdditionalInfoResponse other = (AdditionalInfoResponse) obj;
        if (other.getBrazilAdditionalInfo() == null ^ this.getBrazilAdditionalInfo() == null)
            return false;
        if (other.getBrazilAdditionalInfo() != null && other.getBrazilAdditionalInfo().equals(this.getBrazilAdditionalInfo()) == false)
            return false;
        if (other.getCanadaAdditionalInfo() == null ^ this.getCanadaAdditionalInfo() == null)
            return false;
        if (other.getCanadaAdditionalInfo() != null && other.getCanadaAdditionalInfo().equals(this.getCanadaAdditionalInfo()) == false)
            return false;
        if (other.getEstoniaAdditionalInfo() == null ^ this.getEstoniaAdditionalInfo() == null)
            return false;
        if (other.getEstoniaAdditionalInfo() != null && other.getEstoniaAdditionalInfo().equals(this.getEstoniaAdditionalInfo()) == false)
            return false;
        if (other.getGeorgiaAdditionalInfo() == null ^ this.getGeorgiaAdditionalInfo() == null)
            return false;
        if (other.getGeorgiaAdditionalInfo() != null && other.getGeorgiaAdditionalInfo().equals(this.getGeorgiaAdditionalInfo()) == false)
            return false;
        if (other.getIndiaAdditionalInfo() == null ^ this.getIndiaAdditionalInfo() == null)
            return false;
        if (other.getIndiaAdditionalInfo() != null && other.getIndiaAdditionalInfo().equals(this.getIndiaAdditionalInfo()) == false)
            return false;
        if (other.getIsraelAdditionalInfo() == null ^ this.getIsraelAdditionalInfo() == null)
            return false;
        if (other.getIsraelAdditionalInfo() != null && other.getIsraelAdditionalInfo().equals(this.getIsraelAdditionalInfo()) == false)
            return false;
        if (other.getItalyAdditionalInfo() == null ^ this.getItalyAdditionalInfo() == null)
            return false;
        if (other.getItalyAdditionalInfo() != null && other.getItalyAdditionalInfo().equals(this.getItalyAdditionalInfo()) == false)
            return false;
        if (other.getKenyaAdditionalInfo() == null ^ this.getKenyaAdditionalInfo() == null)
            return false;
        if (other.getKenyaAdditionalInfo() != null && other.getKenyaAdditionalInfo().equals(this.getKenyaAdditionalInfo()) == false)
            return false;
        if (other.getMalaysiaAdditionalInfo() == null ^ this.getMalaysiaAdditionalInfo() == null)
            return false;
        if (other.getMalaysiaAdditionalInfo() != null && other.getMalaysiaAdditionalInfo().equals(this.getMalaysiaAdditionalInfo()) == false)
            return false;
        if (other.getPolandAdditionalInfo() == null ^ this.getPolandAdditionalInfo() == null)
            return false;
        if (other.getPolandAdditionalInfo() != null && other.getPolandAdditionalInfo().equals(this.getPolandAdditionalInfo()) == false)
            return false;
        if (other.getRomaniaAdditionalInfo() == null ^ this.getRomaniaAdditionalInfo() == null)
            return false;
        if (other.getRomaniaAdditionalInfo() != null && other.getRomaniaAdditionalInfo().equals(this.getRomaniaAdditionalInfo()) == false)
            return false;
        if (other.getSaudiArabiaAdditionalInfo() == null ^ this.getSaudiArabiaAdditionalInfo() == null)
            return false;
        if (other.getSaudiArabiaAdditionalInfo() != null && other.getSaudiArabiaAdditionalInfo().equals(this.getSaudiArabiaAdditionalInfo()) == false)
            return false;
        if (other.getSouthKoreaAdditionalInfo() == null ^ this.getSouthKoreaAdditionalInfo() == null)
            return false;
        if (other.getSouthKoreaAdditionalInfo() != null && other.getSouthKoreaAdditionalInfo().equals(this.getSouthKoreaAdditionalInfo()) == false)
            return false;
        if (other.getSpainAdditionalInfo() == null ^ this.getSpainAdditionalInfo() == null)
            return false;
        if (other.getSpainAdditionalInfo() != null && other.getSpainAdditionalInfo().equals(this.getSpainAdditionalInfo()) == false)
            return false;
        if (other.getTurkeyAdditionalInfo() == null ^ this.getTurkeyAdditionalInfo() == null)
            return false;
        if (other.getTurkeyAdditionalInfo() != null && other.getTurkeyAdditionalInfo().equals(this.getTurkeyAdditionalInfo()) == false)
            return false;
        if (other.getUkraineAdditionalInfo() == null ^ this.getUkraineAdditionalInfo() == null)
            return false;
        if (other.getUkraineAdditionalInfo() != null && other.getUkraineAdditionalInfo().equals(this.getUkraineAdditionalInfo()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getBrazilAdditionalInfo() == null) ? 0 : getBrazilAdditionalInfo().hashCode());
        hashCode = prime * hashCode + ((getCanadaAdditionalInfo() == null) ? 0 : getCanadaAdditionalInfo().hashCode());
        hashCode = prime * hashCode + ((getEstoniaAdditionalInfo() == null) ? 0 : getEstoniaAdditionalInfo().hashCode());
        hashCode = prime * hashCode + ((getGeorgiaAdditionalInfo() == null) ? 0 : getGeorgiaAdditionalInfo().hashCode());
        hashCode = prime * hashCode + ((getIndiaAdditionalInfo() == null) ? 0 : getIndiaAdditionalInfo().hashCode());
        hashCode = prime * hashCode + ((getIsraelAdditionalInfo() == null) ? 0 : getIsraelAdditionalInfo().hashCode());
        hashCode = prime * hashCode + ((getItalyAdditionalInfo() == null) ? 0 : getItalyAdditionalInfo().hashCode());
        hashCode = prime * hashCode + ((getKenyaAdditionalInfo() == null) ? 0 : getKenyaAdditionalInfo().hashCode());
        hashCode = prime * hashCode + ((getMalaysiaAdditionalInfo() == null) ? 0 : getMalaysiaAdditionalInfo().hashCode());
        hashCode = prime * hashCode + ((getPolandAdditionalInfo() == null) ? 0 : getPolandAdditionalInfo().hashCode());
        hashCode = prime * hashCode + ((getRomaniaAdditionalInfo() == null) ? 0 : getRomaniaAdditionalInfo().hashCode());
        hashCode = prime * hashCode + ((getSaudiArabiaAdditionalInfo() == null) ? 0 : getSaudiArabiaAdditionalInfo().hashCode());
        hashCode = prime * hashCode + ((getSouthKoreaAdditionalInfo() == null) ? 0 : getSouthKoreaAdditionalInfo().hashCode());
        hashCode = prime * hashCode + ((getSpainAdditionalInfo() == null) ? 0 : getSpainAdditionalInfo().hashCode());
        hashCode = prime * hashCode + ((getTurkeyAdditionalInfo() == null) ? 0 : getTurkeyAdditionalInfo().hashCode());
        hashCode = prime * hashCode + ((getUkraineAdditionalInfo() == null) ? 0 : getUkraineAdditionalInfo().hashCode());
        return hashCode;
    }

    @Override
    public AdditionalInfoResponse clone() {
        try {
            return (AdditionalInfoResponse) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.taxsettings.model.transform.AdditionalInfoResponseMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
