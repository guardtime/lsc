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

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;

import java.io.IOException;
import java.io.InputStream;
import java.util.Enumeration;


/**
 * GuardTime structure {@code TimeSignature}
 * ({@code contentInfo.content.signerInfo.signature}).
 *
 * <pre>
 * TimeSignature ::= SEQUENCE {
 *    location        OCTET STRING,
 *    history         OCTET STRING,
 *    publishedData   PublishedData,
 *    pkSignature     [0] IMPLICIT SignatureInfo OPTIONAL,
 *    pubReferences   [1] IMPLICIT SET OF OCTET STRING OPTIONAL
 * }
 * </pre>
 *
 * @see com.guardtime.signatureconverter.asn1.PublishedData
 * @see com.guardtime.signatureconverter.asn1.SignatureInfo
 * @since 0.4
 */
public final class TimeSignature
        extends Asn1Wrapper {
    private Asn1TimeSignature timeSignature;
    private byte[] location;
    private byte[] history;
    private PublishedData publishedData;
    private SignatureInfo pkSignature;
    private References pubReferences;


    /**
     * Parses a DER-encoded {@code TimeSignature} out from the given input stream.
     *
     * @param in the input stream to read data from.
     * @return the {@code TimeSignature} object.
     * @throws com.guardtime.signatureconverter.asn1.Asn1FormatException if the data read from
     *                                                                   {@code in} does not
     *                                                                   represent a valid {@code
     *                                                                   TimeSignature} object.
     * @throws java.io.IOException                                       if {@code in} throws one.
     */
    public static TimeSignature getInstance(InputStream in)
            throws Asn1FormatException, IOException {
        if (in == null) {
            throw new IllegalArgumentException("invalid input stream: null");
        }

        try {
            ASN1Object obj = Asn1Util.readASN1Object(in);
            return new TimeSignature(obj);
        } catch (IOException e) {
            if (isAsnParserException(e)) {
                throw new Asn1FormatException("time signature has invalid format", e);
            } else {
                throw e;
            }
        } catch (IllegalArgumentException e) {
            if (isAsnParserException(e)) {
                throw new Asn1FormatException("time signature has invalid format", e);
            } else {
                throw e;
            }
        }
    }


    /**
     * Returns the DER representation of the {@code TimeSignature}.
     *
     * @return a DER byte array, or {@code null} on error.
     */
    public byte[] getDerEncoded() {
        try {
            return timeSignature.getEncoded(ASN1Encoding.DER);
        } catch (IOException e) {
            return null;
        }
    }


    /**
     * Returns the location hash chain from the {@code TimeSignature} object.
     * <p>
     * This is the hash chain that connects the leaf corresponding to this
     * signature to the root of the global aggregation tree for the second when
     * the signature was registered in the GuardTime calendar by inserting the
     * root hash value of the aggregation tree as a leaf in the calendar tree.
     *
     * @return the contents of the {@code location} field of this {@code TimeSignature} object.
     */
    public byte[] getLocation() {
        return Util.copyOf(location);
    }

    /**
     * Returns the history hash chain from the {@code TimeSignature} object. <p> This is the hash
     * chain that connects the leaf corresponding to the second when the signature was registered in
     * the GuardTime calendar to the root of the calendar tree in the state the tree was at the
     * moment corresponding to the {@code publicationID} in the {@link
     * com.guardtime.signatureconverter.asn1.PublishedData}.
     *
     * @return the contents of the {@code history} field of this {@code TimeSIgnature} object.
     */
    public byte[] getHistory() {
        return Util.copyOf(history);
    }

    /**
     * Returns the control publication data from the {@code TimeSignature} object. <p> For an
     * unextended signature, this data is not actually published. Such a signature may be verified
     * by either extending it (see {@link com.guardtime.signatureconverter.asn1.CertToken}) or by
     * verifying the PKI signature temporarily protecting the {@code PublishedData}. <p> For an
     * extended signature, this represents the contents of the control publication that can be used
     * to provide tangible proof of integrity of the timestamp.
     *
     * @return the contents of the {@code publishedData} field of this {@code TimeSignature} object.
     */
    public PublishedData getPublishedData() {
        return publishedData;
    }

    /**
     * Returns the temporary PKI signature protecting the {@code PublishedData}
     * until a control publication is available.
     * <p>
     * This is {@code null} for an extended signature.
     *
     * @return the PKI signature value, or {@code null}.
     */
    public SignatureInfo getPkSignature() {
        return pkSignature;
    }

    /**
     * Returns the publication references list from the {@code TimeSignature}
     * object.
     * <p>
     * This list contains bibliographic references to the print media where the
     * control publication represented by {@code PublishedData} was printed.
     * <p>
     * This is {@code null} for an unextended signature.
     *
     * @return the contents of the {@code pubReferences} field of this {@code TimeSignature} object.
     * @since 0.4.7 (had a different return type in prior versions)
     */
    public References getPubReferences() {
        return pubReferences;
    }


    /**
     * Checks whether the signature is extended.
     * <p>
     * An extended signature is traceable to a control publication without any
     * extra information. An unextended signature needs additional information
     * from the online verification service.
     *
     * @return {@code true} if the timestamp is extended, {@code false} otherwise.
     * @see com.guardtime.signatureconverter.asn1.CertToken
     */
    public boolean isExtended() {
        return (pkSignature == null);
    }


    /**
     * Class constructor.
     *
     * @param obj ASN.1 representation of time signature.
     * @throws com.guardtime.signatureconverter.asn1.Asn1FormatException if provided ASN.1 object
     *                                                                   has invalid format.
     */
    TimeSignature(ASN1Encodable obj)
            throws Asn1FormatException {
        try {
            timeSignature = Asn1TimeSignature.getInstance(obj);

            // Check that location and history chains are present
            // (NullPointerException will be thrown otherwise)
            location = timeSignature.getLocation().getOctets();
            history = timeSignature.getHistory().getOctets();

            publishedData = new PublishedData(timeSignature.getPublishedData());

            Asn1SignatureInfo pkSig = timeSignature.getPkSignature();
            if (pkSig != null) {
                pkSignature = new SignatureInfo(pkSig);
            }

            ASN1Set pubRefs = timeSignature.getPubReferences();
            if (pubRefs != null) {
                pubReferences = new References(pubRefs);
            }
        } catch (Asn1FormatException e) {
            throw e;
        } catch (Exception e) {
            throw new Asn1FormatException("time signature has invalid format", e);
        }
    }
}


/**
 * Internal implementation class for the ASN.1 representation of
 * {@code TimeSignature}.
 */
class Asn1TimeSignature
        extends ASN1Object {
    private ASN1OctetString location;
    private ASN1OctetString history;
    private Asn1PublishedData publishedData;
    private Asn1SignatureInfo pkSignature = null;
    private ASN1Set pubReferences = null;


    public static Asn1TimeSignature getInstance(Object obj) {
        if (obj == null || obj instanceof Asn1TimeSignature) {
            return (Asn1TimeSignature) obj;
        } else if (obj instanceof ASN1Sequence) {
            return new Asn1TimeSignature((ASN1Sequence) obj);
        }

        throw new IllegalArgumentException("unknown object in factory: " + obj.getClass().getName());
    }


    public Asn1TimeSignature(ASN1Sequence seq) {
        Enumeration en = seq.getObjects();

        // Required elements
        location = ASN1OctetString.getInstance(en.nextElement());
        history = ASN1OctetString.getInstance(en.nextElement());
        publishedData = Asn1PublishedData.getInstance(en.nextElement());

        // Optional elements
        while (en.hasMoreElements()) {
            ASN1TaggedObject obj = ASN1TaggedObject.getInstance(en.nextElement());
            int tag = obj.getTagNo();
            if (tag == 0 && pkSignature == null) {
                pkSignature = Asn1SignatureInfo.getInstance(obj, false);
            } else if (tag == 1 && pubReferences == null) {
                pubReferences = ASN1Set.getInstance(obj, false);
            } else {
                throw new IllegalArgumentException("invalid object in factory: " + obj);
            }
        }
    }

    public ASN1OctetString getHistory() {
        return history;
    }

    public ASN1OctetString getLocation() {
        return location;
    }

    public Asn1SignatureInfo getPkSignature() {
        return pkSignature;
    }

    public ASN1Set getPubReferences() {
        return pubReferences;
    }

    public Asn1PublishedData getPublishedData() {
        return publishedData;
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(location);
        v.add(history);
        v.add(publishedData);
        if (pkSignature != null) {
            v.add(new DERTaggedObject(false, 0, pkSignature));
        }
        if (pubReferences != null) {
            v.add(new DERTaggedObject(false, 1, pubReferences));
        }
        return new DERSequence(v);
    }
}
