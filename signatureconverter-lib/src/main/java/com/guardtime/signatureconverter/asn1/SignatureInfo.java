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

import com.guardtime.ksi.util.Base16;
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
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

import java.io.IOException;
import java.io.InputStream;
import java.util.Enumeration;


/**
 * GuardTime structure {@code SignatureInfo}
 * ({@code contentInfo.content.signerInfo.signature.pkSignature}).
 *
 * <pre>
 * SignatureInfo ::= SEQUENCE {
 *   signatureAlgorithm   AlgorithmIdentifier,
 *   signatureValue       OCTET STRING
 *   pkiReferences        [0] IMPLICIT SET OF OCTET STRING OPTIONAL
 * }
 * </pre>
 *
 * @since 0.4
 */
public final class SignatureInfo
        extends Asn1Wrapper {
    private Asn1SignatureInfo signatureInfo;
    private String signatureAlgorithm;
    private byte[] signatureValue;
    private References pkiReferences;


    /**
     * Parses a DER-encoded {@code SignatureInfo} out from the given input stream.
     *
     * @param in the input stream to read data from.
     * @return the {@code SignatureInfo} object.
     * @throws com.guardtime.signatureconverter.asn1.Asn1FormatException if the data read from
     *                                                                   {@code in} does not
     *                                                                   represent a valid {@code
     *                                                                   SignatureInfo} object.
     * @throws java.io.IOException                                       if {@code in} throws one.
     */
    public static SignatureInfo getInstance(InputStream in)
            throws Asn1FormatException, IOException {
        if (in == null) {
            throw new IllegalArgumentException("invalid input stream: null");
        }

        try {
            ASN1Object obj = Asn1Util.readASN1Object(in);
            return new SignatureInfo(obj);
        } catch (IOException e) {
            if (isAsnParserException(e)) {
                throw new Asn1FormatException("signature info has invalid format", e);
            } else {
                throw e;
            }
        } catch (IllegalArgumentException e) {
            if (isAsnParserException(e)) {
                throw new Asn1FormatException("signature info has invalid format", e);
            } else {
                throw e;
            }
        }
    }


    /**
     * Returns the DER representation of the {@code SignatureInfo}.
     *
     * @return a DER byte array, or {@code null} on error.
     */
    public byte[] getDerEncoded() {
        try {
            return signatureInfo.getEncoded(ASN1Encoding.DER);
        } catch (IOException e) {
            return null;
        }
    }


    /**
     * Returns the identifier of the signing algorithm used to produce the
     * signature value.
     *
     * @return the algorithm ID.
     */
    public String getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    /**
     * Returns the signature value.
     *
     * @return the signature value.
     */
    public byte[] getSignatureValue() {
        return Util.copyOf(signatureValue);
    }

    /**
     * Returns the key commitment reference list.
     * <p>
     * This list contains bibliographic references to the print media where the
     * fingerprints of the GuardTime timestamp signing keys were printed.
     *
     * @return the key commitment references.
     * @since 0.4.7 (had a different return type in prior versions)
     */
    public References getPkiReferences() {
        return pkiReferences;
    }


    /**
     * Returns formatted PK signature.
     * <p>
     * The formatting is done as follows:
     * <ul>
     * <li>signature algorithm is listed by OID, followed by dash;
     * <li>signature value is encoded in Base16 (hex), inserting dots after
     * every byte value.
     * </ul>
     * <p>
     * Example: {@code 0.1.2.3-45:67:89:AB:CD:EF}, where {@code 0.1.2.3} is
     * algorithm OID, and {@code 45:67:89:AB:CD:EF} is hex-encoded signature
     * value.
     *
     * @return formatted PK signature.
     */
    public String getEncodedSignature() {
        StringBuffer sb = new StringBuffer();
        sb.append(signatureAlgorithm);
        sb.append("-");
        sb.append(Base16.encodeWithColons(signatureValue));
        return sb.toString();
    }


    /**
     * Class constructor.
     *
     * @param obj ASN.1 representation of time signature.
     * @throws com.guardtime.signatureconverter.asn1.Asn1FormatException if provided ASN.1 object
     *                                                                   has invalid format.
     */
    SignatureInfo(ASN1Encodable obj)
            throws Asn1FormatException {
        try {
            signatureInfo = Asn1SignatureInfo.getInstance(obj);

            // Check that signature algorithm and value are present
            // (NullPointerException will be thrown otherwise)
            signatureAlgorithm = signatureInfo.getSignatureAlgorithm().getAlgorithm().getId();
            signatureValue = signatureInfo.getSignatureValue().getOctets();

            ASN1Set pkiRefs = signatureInfo.getPkiReferences();
            if (pkiRefs != null) {
                pkiReferences = new References(pkiRefs);
            }
        } catch (Exception e) {
            throw new Asn1FormatException("signature info has invalid format", e);
        }
    }
}


/**
 * Internal implementation class for the ASN.1 representation of
 * {@code SignatureInfo}.
 */
class Asn1SignatureInfo
        extends ASN1Object {
    private AlgorithmIdentifier signatureAlgorithm;
    private ASN1OctetString signatureValue;
    private ASN1Set pkiReferences = null;


    public static Asn1SignatureInfo getInstance(ASN1TaggedObject obj, boolean explicit) {
        return new Asn1SignatureInfo(ASN1Sequence.getInstance(obj, explicit));
    }

    public static Asn1SignatureInfo getInstance(Object obj) {
        if (obj == null || obj instanceof Asn1SignatureInfo) {
            return (Asn1SignatureInfo) obj;
        } else if (obj instanceof ASN1Sequence) {
            return new Asn1SignatureInfo((ASN1Sequence) obj);
        }

        throw new IllegalArgumentException("unknown object in factory: " + obj.getClass().getName());
    }


    public Asn1SignatureInfo(ASN1Sequence seq) {
        Enumeration en = seq.getObjects();

        // Required elements
        signatureAlgorithm = AlgorithmIdentifier.getInstance(en.nextElement());
        signatureValue = ASN1OctetString.getInstance(en.nextElement());

        // Optional elements
        while (en.hasMoreElements()) {
            ASN1TaggedObject obj = ASN1TaggedObject.getInstance(en.nextElement());
            if (obj.getTagNo() == 0 && pkiReferences == null) {
                pkiReferences = ASN1Set.getInstance(obj, false);
            } else {
                throw new IllegalArgumentException("invalid object in factory: " + obj);
            }
        }
    }

    public AlgorithmIdentifier getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    public ASN1OctetString getSignatureValue() {
        return signatureValue;
    }

    public ASN1Set getPkiReferences() {
        return pkiReferences;
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(signatureAlgorithm);
        v.add(signatureValue);
        if (pkiReferences != null) {
            v.add(new DERTaggedObject(false, 0, pkiReferences));
        }
        return new DERSequence(v);
    }
}
