/*
 * Copyright 2013-2017 Guardtime, Inc.
 *
 * This file is part of the Guardtime client SDK.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES, CONDITIONS, OR OTHER LICENSES OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 * "Guardtime" and "KSI" are trademarks or registered trademarks of
 * Guardtime, Inc., and no license to trademarks is granted; Guardtime
 * reserves and retains all trademark rights.
 */
package com.guardtime.signatureconverter.asn1;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;

import java.io.IOException;
import java.io.InputStream;


/**
 * <a target="_blank" href="http://www.ietf.org/rfc/rfc3161.txt">RFC 3161</a>
 * structure {@code Accuracy} ({@code contentInfo.content.encapContentInfo.eContent.accuracy}).
 *
 * <pre>
 * Accuracy ::= SEQUENCE {
 *    seconds INTEGER OPTIONAL,
 *    millis  [0] INTEGER (1..999) OPTIONAL,
 *    micros  [1] INTEGER (1..999) OPTIONAL
 * }
 * </pre>
 *
 * @since 0.4
 */
public final class Accuracy
        extends Asn1Wrapper {
    private org.bouncycastle.asn1.tsp.Accuracy accuracy;
    private Integer seconds;
    private Integer millis;
    private Integer micros;


    /**
     * Parses a DER-encoded {@code Accuracy} out from the given input stream.
     *
     * @param in the input stream to read data from.
     * @return the {@code Accuracy} object.
     * @throws com.guardtime.signatureconverter.asn1.Asn1FormatException if the data read from
     *                                                                   {@code in} does not
     *                                                                   represent a valid {@code
     *                                                                   Accuracy} object.
     * @throws java.io.IOException                                       if {@code in} throws one.
     */
    public static Accuracy getInstance(InputStream in)
            throws Asn1FormatException, IOException {
        if (in == null) {
            throw new IllegalArgumentException("invalid input stream: null");
        }

        try {
            ASN1Object obj = Asn1Util.readASN1Object(in);
            return new Accuracy(obj);
        } catch (IOException e) {
            if (isAsnParserException(e)) {
                throw new Asn1FormatException("accuracy has invalid format", e);
            } else {
                throw e;
            }
        } catch (IllegalArgumentException e) {
            if (isAsnParserException(e)) {
                throw new Asn1FormatException("accuracy has invalid format", e);
            } else {
                throw e;
            }
        }
    }


    /**
     * Returns the DER representation of the {@code Accuracy}.
     *
     * @return a DER byte array, or {@code null} on error.
     */
    public byte[] getDerEncoded() {
        try {
            return accuracy.getEncoded(ASN1Encoding.DER);
        } catch (IOException e) {
            return null;
        }
    }


    /**
     * Returns the full seconds value of the accuracy. Note that this can be
     * {@code null} which should be treated as zero.
     * <p>
     * The total tolerance represented by this structure is
     * {@code (seconds + 0.001 * millis + 0.000001 * micros)} seconds.
     *
     * @return the full seconds part of accuracy.
     */
    public Integer getSeconds() {
        return seconds;
    }

    /**
     * Returns the milliseconds value of the accuracy. Note that this can be
     * {@code null} which should be treated as zero.
     * <p>
     * The total tolerance represented by this structure is
     * {@code (seconds + 0.001 * millis + 0.000001 * micros)} seconds.
     *
     * @return the milliseconds part of accuracy.
     */
    public Integer getMillis() {
        return millis;
    }

    /**
     * Returns the microseconds value of the accuracy. Note that this can be
     * {@code null} which should be treated as zero.
     * <p>
     * The total tolerance represented by this structure is
     * {@code (seconds + 0.001 * millis + 0.000001 * micros)} seconds.
     *
     * @return the microseconds part of accuracy.
     */
    public Integer getMicros() {
        return micros;
    }


    /**
     * Class constructor.
     *
     * @param obj ASN.1 representation of the timestamp accuracy.
     * @throws com.guardtime.signatureconverter.asn1.Asn1FormatException if provided ASN.1 object
     *                                                                   has invalid format.
     */
    Accuracy(ASN1Encodable obj)
            throws Asn1FormatException {
        try {
            accuracy = org.bouncycastle.asn1.tsp.Accuracy.getInstance(obj);

            ASN1Integer sec = accuracy.getSeconds();
            if (sec == null) {
                seconds = null;
            } else {
                int n = sec.getValue().intValue();
                if (n < 0) {
                    throw new Asn1FormatException("invalid seconds value: " + n);
                }
                seconds = new Integer(n);
            }

            ASN1Integer mls = accuracy.getMillis();
            if (mls == null) {
                millis = null;
            } else {
                int n = mls.getValue().intValue();
                if (n < 1 || n > 999) {
                    throw new Asn1FormatException("invalid millis value: " + n);
                }
                millis = new Integer(n);
            }

            ASN1Integer mcs = accuracy.getMicros();
            if (mcs == null) {
                micros = null;
            } else {
                int n = mcs.getValue().intValue();
                if (n < 1 || n > 999) {
                    throw new Asn1FormatException("invalid micros value: " + n);
                }
                micros = new Integer(n);
            }
        } catch (Asn1FormatException e) {
            throw e;
        } catch (Exception e) {
            throw new Asn1FormatException("accuracy has invalid format", e);
        }
    }
}
