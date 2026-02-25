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
package com.amazonaws.services.mediaconvert.model;

import java.io.Serializable;
import javax.annotation.Generated;
import com.amazonaws.protocol.StructuredPojo;
import com.amazonaws.protocol.ProtocolMarshaller;

/**
 * When you include Video generator, MediaConvert creates a video input with black frames. Use this setting if you do
 * not have a video input or if you want to add black video frames before, or after, other inputs. You can specify Video
 * generator, or you can specify an Input file, but you cannot specify both. For more information, see
 * https://docs.aws.amazon.com/mediaconvert/latest/ug/video-generator.html
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/mediaconvert-2017-08-29/InputVideoGenerator" target="_top">AWS
 *      API Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class InputVideoGenerator implements Serializable, Cloneable, StructuredPojo {

    /**
     * Specify the number of audio channels to include in your video generator input. MediaConvert creates these audio
     * channels as silent audio within a single audio track. Enter an integer from 1 to 32.
     */
    private Integer channels;
    /**
     * Specify the duration, in milliseconds, for your video generator input. Enter an integer from 50 to 86400000.
     */
    private Integer duration;
    /**
     * Specify the denominator of the fraction that represents the frame rate for your video generator input. When you
     * do, you must also specify a value for Frame rate numerator. MediaConvert uses a default frame rate of 29.97 when
     * you leave Frame rate numerator and Frame rate denominator blank.
     */
    private Integer framerateDenominator;
    /**
     * Specify the numerator of the fraction that represents the frame rate for your video generator input. When you do,
     * you must also specify a value for Frame rate denominator. MediaConvert uses a default frame rate of 29.97 when
     * you leave Frame rate numerator and Frame rate denominator blank.
     */
    private Integer framerateNumerator;
    /**
     * Specify the audio sample rate, in Hz, for the silent audio in your video generator input. Enter an integer from
     * 32000 to 48000.
     */
    private Integer sampleRate;

    /**
     * Specify the number of audio channels to include in your video generator input. MediaConvert creates these audio
     * channels as silent audio within a single audio track. Enter an integer from 1 to 32.
     * 
     * @param channels
     *        Specify the number of audio channels to include in your video generator input. MediaConvert creates these
     *        audio channels as silent audio within a single audio track. Enter an integer from 1 to 32.
     */

    public void setChannels(Integer channels) {
        this.channels = channels;
    }

    /**
     * Specify the number of audio channels to include in your video generator input. MediaConvert creates these audio
     * channels as silent audio within a single audio track. Enter an integer from 1 to 32.
     * 
     * @return Specify the number of audio channels to include in your video generator input. MediaConvert creates these
     *         audio channels as silent audio within a single audio track. Enter an integer from 1 to 32.
     */

    public Integer getChannels() {
        return this.channels;
    }

    /**
     * Specify the number of audio channels to include in your video generator input. MediaConvert creates these audio
     * channels as silent audio within a single audio track. Enter an integer from 1 to 32.
     * 
     * @param channels
     *        Specify the number of audio channels to include in your video generator input. MediaConvert creates these
     *        audio channels as silent audio within a single audio track. Enter an integer from 1 to 32.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public InputVideoGenerator withChannels(Integer channels) {
        setChannels(channels);
        return this;
    }

    /**
     * Specify the duration, in milliseconds, for your video generator input. Enter an integer from 50 to 86400000.
     * 
     * @param duration
     *        Specify the duration, in milliseconds, for your video generator input. Enter an integer from 50 to
     *        86400000.
     */

    public void setDuration(Integer duration) {
        this.duration = duration;
    }

    /**
     * Specify the duration, in milliseconds, for your video generator input. Enter an integer from 50 to 86400000.
     * 
     * @return Specify the duration, in milliseconds, for your video generator input. Enter an integer from 50 to
     *         86400000.
     */

    public Integer getDuration() {
        return this.duration;
    }

    /**
     * Specify the duration, in milliseconds, for your video generator input. Enter an integer from 50 to 86400000.
     * 
     * @param duration
     *        Specify the duration, in milliseconds, for your video generator input. Enter an integer from 50 to
     *        86400000.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public InputVideoGenerator withDuration(Integer duration) {
        setDuration(duration);
        return this;
    }

    /**
     * Specify the denominator of the fraction that represents the frame rate for your video generator input. When you
     * do, you must also specify a value for Frame rate numerator. MediaConvert uses a default frame rate of 29.97 when
     * you leave Frame rate numerator and Frame rate denominator blank.
     * 
     * @param framerateDenominator
     *        Specify the denominator of the fraction that represents the frame rate for your video generator input.
     *        When you do, you must also specify a value for Frame rate numerator. MediaConvert uses a default frame
     *        rate of 29.97 when you leave Frame rate numerator and Frame rate denominator blank.
     */

    public void setFramerateDenominator(Integer framerateDenominator) {
        this.framerateDenominator = framerateDenominator;
    }

    /**
     * Specify the denominator of the fraction that represents the frame rate for your video generator input. When you
     * do, you must also specify a value for Frame rate numerator. MediaConvert uses a default frame rate of 29.97 when
     * you leave Frame rate numerator and Frame rate denominator blank.
     * 
     * @return Specify the denominator of the fraction that represents the frame rate for your video generator input.
     *         When you do, you must also specify a value for Frame rate numerator. MediaConvert uses a default frame
     *         rate of 29.97 when you leave Frame rate numerator and Frame rate denominator blank.
     */

    public Integer getFramerateDenominator() {
        return this.framerateDenominator;
    }

    /**
     * Specify the denominator of the fraction that represents the frame rate for your video generator input. When you
     * do, you must also specify a value for Frame rate numerator. MediaConvert uses a default frame rate of 29.97 when
     * you leave Frame rate numerator and Frame rate denominator blank.
     * 
     * @param framerateDenominator
     *        Specify the denominator of the fraction that represents the frame rate for your video generator input.
     *        When you do, you must also specify a value for Frame rate numerator. MediaConvert uses a default frame
     *        rate of 29.97 when you leave Frame rate numerator and Frame rate denominator blank.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public InputVideoGenerator withFramerateDenominator(Integer framerateDenominator) {
        setFramerateDenominator(framerateDenominator);
        return this;
    }

    /**
     * Specify the numerator of the fraction that represents the frame rate for your video generator input. When you do,
     * you must also specify a value for Frame rate denominator. MediaConvert uses a default frame rate of 29.97 when
     * you leave Frame rate numerator and Frame rate denominator blank.
     * 
     * @param framerateNumerator
     *        Specify the numerator of the fraction that represents the frame rate for your video generator input. When
     *        you do, you must also specify a value for Frame rate denominator. MediaConvert uses a default frame rate
     *        of 29.97 when you leave Frame rate numerator and Frame rate denominator blank.
     */

    public void setFramerateNumerator(Integer framerateNumerator) {
        this.framerateNumerator = framerateNumerator;
    }

    /**
     * Specify the numerator of the fraction that represents the frame rate for your video generator input. When you do,
     * you must also specify a value for Frame rate denominator. MediaConvert uses a default frame rate of 29.97 when
     * you leave Frame rate numerator and Frame rate denominator blank.
     * 
     * @return Specify the numerator of the fraction that represents the frame rate for your video generator input. When
     *         you do, you must also specify a value for Frame rate denominator. MediaConvert uses a default frame rate
     *         of 29.97 when you leave Frame rate numerator and Frame rate denominator blank.
     */

    public Integer getFramerateNumerator() {
        return this.framerateNumerator;
    }

    /**
     * Specify the numerator of the fraction that represents the frame rate for your video generator input. When you do,
     * you must also specify a value for Frame rate denominator. MediaConvert uses a default frame rate of 29.97 when
     * you leave Frame rate numerator and Frame rate denominator blank.
     * 
     * @param framerateNumerator
     *        Specify the numerator of the fraction that represents the frame rate for your video generator input. When
     *        you do, you must also specify a value for Frame rate denominator. MediaConvert uses a default frame rate
     *        of 29.97 when you leave Frame rate numerator and Frame rate denominator blank.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public InputVideoGenerator withFramerateNumerator(Integer framerateNumerator) {
        setFramerateNumerator(framerateNumerator);
        return this;
    }

    /**
     * Specify the audio sample rate, in Hz, for the silent audio in your video generator input. Enter an integer from
     * 32000 to 48000.
     * 
     * @param sampleRate
     *        Specify the audio sample rate, in Hz, for the silent audio in your video generator input. Enter an integer
     *        from 32000 to 48000.
     */

    public void setSampleRate(Integer sampleRate) {
        this.sampleRate = sampleRate;
    }

    /**
     * Specify the audio sample rate, in Hz, for the silent audio in your video generator input. Enter an integer from
     * 32000 to 48000.
     * 
     * @return Specify the audio sample rate, in Hz, for the silent audio in your video generator input. Enter an
     *         integer from 32000 to 48000.
     */

    public Integer getSampleRate() {
        return this.sampleRate;
    }

    /**
     * Specify the audio sample rate, in Hz, for the silent audio in your video generator input. Enter an integer from
     * 32000 to 48000.
     * 
     * @param sampleRate
     *        Specify the audio sample rate, in Hz, for the silent audio in your video generator input. Enter an integer
     *        from 32000 to 48000.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public InputVideoGenerator withSampleRate(Integer sampleRate) {
        setSampleRate(sampleRate);
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
        if (getChannels() != null)
            sb.append("Channels: ").append(getChannels()).append(",");
        if (getDuration() != null)
            sb.append("Duration: ").append(getDuration()).append(",");
        if (getFramerateDenominator() != null)
            sb.append("FramerateDenominator: ").append(getFramerateDenominator()).append(",");
        if (getFramerateNumerator() != null)
            sb.append("FramerateNumerator: ").append(getFramerateNumerator()).append(",");
        if (getSampleRate() != null)
            sb.append("SampleRate: ").append(getSampleRate());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof InputVideoGenerator == false)
            return false;
        InputVideoGenerator other = (InputVideoGenerator) obj;
        if (other.getChannels() == null ^ this.getChannels() == null)
            return false;
        if (other.getChannels() != null && other.getChannels().equals(this.getChannels()) == false)
            return false;
        if (other.getDuration() == null ^ this.getDuration() == null)
            return false;
        if (other.getDuration() != null && other.getDuration().equals(this.getDuration()) == false)
            return false;
        if (other.getFramerateDenominator() == null ^ this.getFramerateDenominator() == null)
            return false;
        if (other.getFramerateDenominator() != null && other.getFramerateDenominator().equals(this.getFramerateDenominator()) == false)
            return false;
        if (other.getFramerateNumerator() == null ^ this.getFramerateNumerator() == null)
            return false;
        if (other.getFramerateNumerator() != null && other.getFramerateNumerator().equals(this.getFramerateNumerator()) == false)
            return false;
        if (other.getSampleRate() == null ^ this.getSampleRate() == null)
            return false;
        if (other.getSampleRate() != null && other.getSampleRate().equals(this.getSampleRate()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getChannels() == null) ? 0 : getChannels().hashCode());
        hashCode = prime * hashCode + ((getDuration() == null) ? 0 : getDuration().hashCode());
        hashCode = prime * hashCode + ((getFramerateDenominator() == null) ? 0 : getFramerateDenominator().hashCode());
        hashCode = prime * hashCode + ((getFramerateNumerator() == null) ? 0 : getFramerateNumerator().hashCode());
        hashCode = prime * hashCode + ((getSampleRate() == null) ? 0 : getSampleRate().hashCode());
        return hashCode;
    }

    @Override
    public InputVideoGenerator clone() {
        try {
            return (InputVideoGenerator) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.mediaconvert.model.transform.InputVideoGeneratorMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
