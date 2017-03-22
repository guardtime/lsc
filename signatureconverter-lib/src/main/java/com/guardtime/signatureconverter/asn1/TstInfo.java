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

import com.guardtime.ksi.util.Util;

import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.tsp.TSTInfo;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.util.Date;


/**
 * <a target="_blank" href="http://www.ietf.org/rfc/rfc3161.txt">RFC 3161</a>
 * structure {@code TSTInfo} ({@code contentInfo.content.encapContentInfo.eContent}).
 *
 * <pre>
 * TSTInfo ::= SEQUENCE {
 *    version        INTEGER  { v1(1) },
 *    policy         TSAPolicyId,
 *    messageImprint MessageImprint,
 *    -- MUST have the same value as the similar field in TimeStampReq
 *    serialNumber   INTEGER,
 *    -- Users MUST be ready to accommodate integers up to 160 bits
 *    genTime        GeneralizedTime,
 *    accuracy       Accuracy OPTIONAL,
 *    ordering       BOOLEAN DEFAULT FALSE,
 *    nonce          INTEGER OPTIONAL,
 *    -- MUST be present if the similar field was present in TimeStampReq.
 *    -- In that case it MUST have the same value.
 *    tsa            [0] GeneralName OPTIONAL,
 *    extensions     [1] IMPLICIT Extensions OPTIONAL
 * }
 * </pre>
 *
 * @see com.guardtime.signatureconverter.asn1.MessageImprint
 * @see com.guardtime.signatureconverter.asn1.Accuracy
 * @since 0.4
 */
public final class TstInfo
        extends Asn1Wrapper {
    public static final int VERSION = 1;

    private TSTInfo tstInfo;
    private int version;
    private String policy;
    private MessageImprint messageImprint;
    private BigInteger serialNumber;
    private Date genTime;
    private Accuracy accuracy;
    private boolean ordering;
    private BigInteger nonce;
    private String tsa;
    private byte[] extensions;

    private byte[] bytesBeforeHashedMessage;
    private byte[] bytesAfterHashedMessage;


    /**
     * Parses a DER-encoded {@code TSTInfo} out from the given input stream.
     *
     * @param in the input stream to read data from.
     * @return the {@code TSTInfo} object.
     * @throws com.guardtime.signatureconverter.asn1.Asn1FormatException if the data read from
     *                                                                   {@code in} does not
     *                                                                   represent a valid {@code
     *                                                                   TSTInfo} object.
     * @throws java.io.IOException                                       if {@code in} throws one.
     */
    public static TstInfo getInstance(InputStream in)
            throws Asn1FormatException, IOException {
        if (in == null) {
            throw new IllegalArgumentException("invalid input stream: null");
        }

        try {
            ASN1Object obj = Asn1Util.readASN1Object(in);
            return new TstInfo(obj);
        } catch (IOException e) {
            if (isAsnParserException(e)) {
                throw new Asn1FormatException("TST info has invalid format", e);
            } else {
                throw e;
            }
        } catch (IllegalArgumentException e) {
            if (isAsnParserException(e)) {
                throw new Asn1FormatException("TST info has invalid format", e);
            } else {
                throw e;
            }
        }
    }


    /**
     * Returns the DER representation of the {@code ContentInfo}.
     *
     * @return a DER byte array, or {@code null} on error.
     */
    public byte[] getDerEncoded() {
        try {
            return tstInfo.getEncoded(ASN1Encoding.DER);
        } catch (IOException e) {
            return null;
        }
    }


    /**
     * Returns the version number of the syntax of the {@code TSTInfo} object.
     * GuardTime timestamps always use {@link #VERSION}.
     *
     * @return the value of the {@code version} field of this {@code TSTInfo} object.
     */
    public int getVersion() {
        return version;
    }

    /**
     * Returns the identifier of the policy under which the timestamp was
     * issued.
     *
     * @return the OID of the timestamping policy.
     */
    public String getPolicy() {
        return policy;
    }

    /**
     * Returns the imprint of the timestamped datum.
     *
     * @return the message imprint.
     */
    public MessageImprint getMessageImprint() {
        return messageImprint;
    }

    /**
     * Returns the serial number of the timestamp.
     *
     * @return the serial number.
     */
    public BigInteger getSerialNumber() {
        return serialNumber;
    }

    /**
     * Returns the time when the timestamping request was received by the
     * GuardTime gateway that issued the timestamp, according to the gateway's
     * local clock.
     * <p>
     * Note that this is not the same as the time value extracted from the
     * history hash chain of the {@link com.guardtime.signatureconverter.asn1.TimeSignature}.
     *
     * @return the request time.
     */
    public Date getGenTime() {
        return (Date) genTime.clone();
    }

    /**
     * Returns the claimed accuracy of the issuing gateway's local clock.
     *
     * @return the accuracy of the request time.
     */
    public Accuracy getAccuracy() {
        return accuracy;
    }

    /**
     * Returns {@code true} if any two timestamps can be ordered in time by
     * comparing the values returned by {@link #getGenTime()}.
     * <p>
     * This is not the case for GuardTime timestamps, so this method always
     * returns {@code false}
     *
     * @return {@code false}.
     */
    public boolean getOrdering() {
        return ordering;
    }

    /**
     * Returns the nonce from the timestamp, if there is one.
     *
     * @return the nonce, or {@code null}.
     */
    public BigInteger getNonce() {
        return nonce;
    }

    /**
     * Returns the name of the gateway that issued the timestamp.
     *
     * @return the hostname of the gateway.
     */
    public String getTsa() {
        return tsa;
    }

    /**
     * Returns the DER representation of {@code TSTInfo} extensions.
     * <p>
     * No extensions are used by the current version of the GuardTime service.
     *
     * @return DER-encoded extensions.
     */
    public byte[] getEncodedExtensions() {
        return Util.copyOf(extensions);
    }

    /**
     * Get all encoded bytes before hashed message
     *
     * @return encoded bytes before hashed message
     */
    public byte[] getBytesBeforeHashedMessage() {
        return bytesBeforeHashedMessage;
    }

    /**
     * Get all encoded bytes after hashed message
     *
     * @return encoded bytes after hashed message
     */
    public byte[] getBytesAfterHashedMessage() {
        return bytesAfterHashedMessage;
    }


    /**
     * Returns the same value as {@link #getAccuracy()}, but formatted for
     * human reading.
     *
     * @return the accuracy of the request time.
     */
    public String getFormattedAccuracy() {
        if (accuracy == null) {
            return null;
        }

        // RFC 3161: if either seconds, millis or micros is missing, then
        // a value of zero MUST be taken for the missing field.
        long value = 0;

        Integer seconds = accuracy.getSeconds();
        if (seconds != null) {
            value += seconds.intValue();
        }
        value *= 1000;

        Integer millis = accuracy.getMillis();
        if (millis != null) {
            value += millis.intValue();
        }
        value *= 1000;

        Integer micros = accuracy.getMicros();
        if (micros != null) {
            value += micros.intValue();
        }

        if (value % 1000000 == 0) {
            return (value / 1000000) + "s";
        } else if (value % 1000 == 0) {
            return (value / 1000) + "ms";
        } else {
            return value + "us";
        }
    }

    /**
     * Returns the same value as {@link #getTsa()}, but formatted for human
     * reading.
     *
     * @return the hostname of the gateway.
     */
    public String getFormattedTsa() {
        if (tsa == null) {
            return null;
        } else if (tsa.startsWith("0: ")) {
            return tsa.replaceFirst("0: ", "Other:");
        } else if (tsa.startsWith("1: ")) {
            return tsa.replaceFirst("1: ", "RFC822:");
        } else if (tsa.startsWith("2: ")) {
            return tsa.replaceFirst("2: ", "DNS:");
        } else if (tsa.startsWith("3: ")) {
            return tsa.replaceFirst("3: ", "X400:");
        } else if (tsa.startsWith("4: ")) {
            return tsa.replaceFirst("4: ", "DN:");
        } else if (tsa.startsWith("5:")) {
            return tsa.replaceFirst("5: ", "EDIParty:");
        } else if (tsa.startsWith("6: ")) {
            return tsa.replaceFirst("6: ", "URI:");
        } else if (tsa.startsWith("7: ")) {
            return tsa.replaceFirst("7: ", "IP:");
        } else if (tsa.startsWith("8:")) {
            return tsa.replaceFirst("8: ", "OID:");
        }

        return tsa;
    }

    /**
     * Class constructor.
     *
     * @param obj ASN.1 representation of TST info.
     * @throws com.guardtime.signatureconverter.asn1.Asn1FormatException if provided ASN.1 object
     *                                                                   has invalid format.
     */
    TstInfo(ASN1Encodable obj)
            throws Asn1FormatException {
        try {
            tstInfo = TSTInfo.getInstance(obj);

            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

            ASN1Sequence tstInfoSequence = ASN1Sequence.getInstance(obj);

            outputStream.write(Asn1Util.getASN1ObjectHeader(tstInfoSequence));
            outputStream.write(tstInfoSequence.getObjectAt(0).toASN1Primitive().getEncoded(ASN1Encoding.DER));
            outputStream.write(tstInfoSequence.getObjectAt(1).toASN1Primitive().getEncoded(ASN1Encoding.DER));

            ASN1Sequence messageImprintSequence = ASN1Sequence.getInstance(tstInfoSequence.getObjectAt(2));
            outputStream.write(Asn1Util.getASN1ObjectHeader(messageImprintSequence));
            outputStream.write(messageImprintSequence.getObjectAt(0).toASN1Primitive().getEncoded(ASN1Encoding.DER));
            outputStream.write(Asn1Util.getASN1ObjectHeader(messageImprintSequence.getObjectAt(1).toASN1Primitive()));
            bytesBeforeHashedMessage = outputStream.toByteArray();

            outputStream = new ByteArrayOutputStream();
            for (int i = 3; i < tstInfoSequence.size(); i++) {
                outputStream.write(tstInfoSequence.getObjectAt(i).toASN1Primitive().getEncoded(ASN1Encoding.DER));
            }
            bytesAfterHashedMessage = outputStream.toByteArray();

            // Extract and check version
            BigInteger ver = tstInfo.getVersion().getValue();
            if (!ver.equals(BigInteger.valueOf(VERSION))) {
                throw new Asn1FormatException("invalid TST info version: " + ver);
            }
            version = ver.intValue();

            // Extract policy
            policy = tstInfo.getPolicy().getId();

            // Extract message imprint
            messageImprint = new MessageImprint(tstInfo.getMessageImprint().toASN1Primitive());

            // Extract serial number
            //
            // As `DERInteger` can be constructed out of `ASN1OctetString`
            // without any error, here we have no option to determine
            // if the serial number is actually an INTEGER or OCTET STRING.
            //
            // Possible solutions is to rewrite BouncyCastle `TSTInfo` class
            // adding more strict checks.
            serialNumber = tstInfo.getSerialNumber().getValue();

            // Extract request time
            //
            // Current BouncyCastle implementation can parse the time string
            // that does not omit trailing zeros in second fraction part.
            // RFC 3161 requires that such time string is labeled invalid.
            genTime = tstInfo.getGenTime().getDate();

            // Extract optional fields

            ASN1Encodable acc = tstInfo.getAccuracy();
            accuracy = ((acc == null) ? null : new Accuracy(acc.toASN1Primitive()));

            ASN1Boolean ord = tstInfo.getOrdering();
            ordering = (ord != null && ord.isTrue());

            ASN1Integer nnc = tstInfo.getNonce();
            nonce = ((nnc == null) ? null : nnc.getValue());

            GeneralName tsaName = tstInfo.getTsa();
            tsa = ((tsaName == null) ? null : tsaName.toString());

            Extensions exts = tstInfo.getExtensions();
            if (exts != null) {
                // check for critical extensions
                Asn1Util.checkExtensions(exts);
                extensions = exts.getEncoded(ASN1Encoding.DER);
            }
        } catch (Asn1FormatException e) {
            throw e;
        } catch (Exception e) {
            throw new Asn1FormatException("TST info has invalid format", e);
        }
    }


}
