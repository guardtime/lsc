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

import com.guardtime.ksi.util.Base32;
import com.guardtime.ksi.util.Util;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.util.Enumeration;

/**
 * GuardTime structure {@code PublishedData}
 * ({@code contentInfo.content.signerInfo.signature.publishedData}).
 *
 * <pre>
 * PublishedData ::= SEQUENCE {
 *    publicationIdentifier   INTEGER,
 *    publicationImprint      DataImprint
 * }
 * DataImprint ::= OCTET STRING
 * </pre>
 */
public final class PublishedData
        extends Asn1Wrapper {
    private Asn1PublishedData publishedData;
    private BigInteger publicationId;
    private byte[] publicationImprint;

    /**
     * Parses a DER-encoded {@code PublishedData} out from the given input
     * stream.
     *
     * @param in the input stream to read data from.
     * @return the {@code PublishedData} object.
     * @throws com.guardtime.signatureconverter.asn1.Asn1FormatException if the data read from
     *                                                                   {@code in} does not
     *                                                                   represent a valid {@code
     *                                                                   PublishedData} object.
     * @throws java.io.IOException                                       if {@code in} throws one.
     */
    public static PublishedData getInstance(InputStream in)
            throws Asn1FormatException, IOException {
        if (in == null) {
            throw new IllegalArgumentException("invalid input stream: null");
        }

        try {
            ASN1Object obj = Asn1Util.readASN1Object(in);
            return new PublishedData(obj);
        } catch (IOException e) {
            if (isAsnParserException(e)) {
                throw new Asn1FormatException("published data has invalid format", e);
            } else {
                throw e;
            }
        } catch (IllegalArgumentException e) {
            if (isAsnParserException(e)) {
                throw new Asn1FormatException("published data has invalid format", e);
            } else {
                throw e;
            }
        }
    }

    /**
     * Returns the DER representation of the {@code PublishedData}.
     *
     * @return a DER byte array, or {@code null} on error.
     */
    public byte[] getDerEncoded() {
        try {
            return publishedData.getEncoded(ASN1Encoding.DER);
        } catch (IOException e) {
            return null;
        }
    }

    /**
     * Returns the data formatted for publishing in a printed newspaper.
     * <p>
     * The formatting is as follows:
     * <ul>
     * <li>the publication ID (a 64-bit Unix <code>time_t</code> value) is
     * listed from most to least significant byte;
     * <li>and the publication imprint (the hash value from the root of the
     * GuardTime calendar tree for the moment corresponding to the publication
     * ID) is appended;
     * <li>the CCITT CRC32 checksum over the preceding data is appended;
     * <li>the result is encoded in base-32;
     * <li>the result is grouped by inserting dashes after every 6 characters.
     * </ul>
     *
     * @return the formatted control publication.
     */
    public String getEncodedPublication() {
        byte[] idBytes = Util.toByteArray(getPublicationId().longValue());
        byte[] imprintBytes = getPublicationImprint();
        byte[] result = new byte[idBytes.length + imprintBytes.length];
        System.arraycopy(idBytes, 0, result, 0, idBytes.length);
        System.arraycopy(imprintBytes, 0, result, idBytes.length, imprintBytes.length);
        return Base32.encodeWithDashes(Util.addCrc32(result));
    }

    /**
     * Returns the publication ID, which is essentially a Unix
     * <code>time_t</code> value for the second when the publication imprint
     * was extracted from the GuardTime calendar tree.
     *
     * @return the publication ID.
     */
    public BigInteger getPublicationId() {
        return publicationId;
    }

    /**
     * Returns the publication imprint, which is a 1-byte hash algorithm ID
     * followed by the root hash value from the GuardTime calendar tree.
     *
     * @return the publication imprint.
     */
    public byte[] getPublicationImprint() {
        return Util.copyOf(publicationImprint);
    }

    /**
     * Class constructor.
     *
     * @param obj ASN.1 representation of time signature.
     * @throws com.guardtime.signatureconverter.asn1.Asn1FormatException if provided ASN.1 object
     *                                                                   has invalid format.
     */
    PublishedData(ASN1Encodable obj)
            throws Asn1FormatException {
        try {
            publishedData = Asn1PublishedData.getInstance(obj);

            // Check that publication ID and imprint are present
            // (NullPointerException will be thrown otherwise)
            publicationId = publishedData.getPublicationIdentifier().getValue();
            publicationImprint = publishedData.getPublicationImprint().getOctets();
        } catch (Exception e) {
            throw new Asn1FormatException("published data has invalid format", e);
        }
    }
}

/**
 * Internal implementation class for the ASN.1 representation of
 * {@code PublishedData}.
 */
class Asn1PublishedData
        extends ASN1Object {
    private ASN1Integer publicationIdentifier;
    private ASN1OctetString publicationImprint;

    public static Asn1PublishedData getInstance(Object obj) {
        if (obj == null || obj instanceof Asn1PublishedData) {
            return (Asn1PublishedData) obj;
        } else if (obj instanceof ASN1Sequence) {
            return new Asn1PublishedData((ASN1Sequence) obj);
        }

        throw new IllegalArgumentException("unknown object in factory: " + obj.getClass().getName());
    }

    public Asn1PublishedData(ASN1Sequence seq) {
        Enumeration en = seq.getObjects();

        // Required elements
        publicationIdentifier = ASN1Integer.getInstance(en.nextElement());
        publicationImprint = ASN1OctetString.getInstance(en.nextElement());

        // Extra elements (not allowed)
        if (en.hasMoreElements()) {
            throw new IllegalArgumentException("invalid object in factory: " + en.nextElement());
        }
    }

    public ASN1Integer getPublicationIdentifier() {
        return publicationIdentifier;
    }

    public ASN1OctetString getPublicationImprint() {
        return publicationImprint;
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(publicationIdentifier);
        v.add(publicationImprint);
        return new DERSequence(v);
    }
}
