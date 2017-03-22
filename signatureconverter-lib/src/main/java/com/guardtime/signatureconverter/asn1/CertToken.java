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
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.Extensions;

import java.io.IOException;
import java.io.InputStream;
import java.util.Enumeration;


/**
 * GuardTime structure {@code CertToken}.
 * <p>
 * Certification token contains data needed to extend a timestamp, that is, to
 * link it to a control publication.
 * <p>
 * Certification token is created by online verification service in response to
 * a certification token request.
 *
 * <pre>
 * CertToken ::= SEQUENCE {
 *    version         INTEGER { v1(1) },
 *    history         OCTET STRING,
 *    publishedData   PublishedData,
 *    pubReferences   SET OF OCTET STRING OPTIONAL
 *    extensions      [0] IMPLICIT Extensions OPTIONAL
 * }
 * </pre>
 *
 * @see com.guardtime.signatureconverter.asn1.PublishedData
 * @since 0.4
 */
public final class CertToken
        extends com.guardtime.signatureconverter.asn1.Asn1Wrapper {
    public static final int VERSION = 1;

    private Asn1CertToken certToken;
    private int version;
    private byte[] history;
    private PublishedData publishedData;
    private References pubReferences;
    private byte[] extensions;


    /**
     * Parses a DER-encoded {@code CertToken} out from the given input stream.
     *
     * @param in the input stream to read data from.
     * @return the {@code CertToken} object.
     * @throws com.guardtime.signatureconverter.asn1.Asn1FormatException if the data read from
     *                                                                   {@code in} does not
     *                                                                   represent a valid {@code
     *                                                                   CertToken} object.
     * @throws java.io.IOException                                       if {@code in} throws one.
     */
    public static CertToken getInstance(InputStream in)
            throws Asn1FormatException, IOException {
        if (in == null) {
            throw new IllegalArgumentException("invalid input stream: null");
        }

        try {
            ASN1Object obj = Asn1Util.readASN1Object(in);
            return new CertToken(obj);
        } catch (IOException e) {
            if (isAsnParserException(e)) {
                throw new Asn1FormatException("cert token has invalid format", e);
            } else {
                throw e;
            }
        } catch (IllegalArgumentException e) {
            if (isAsnParserException(e)) {
                throw new Asn1FormatException("cert token has invalid format", e);
            } else {
                throw e;
            }
        }
    }


    /**
     * Returns the DER representation of the {@code CertToken}.
     *
     * @return a DER byte array, or {@code null} on error.
     */
    public byte[] getDerEncoded() {
        try {
            return certToken.getEncoded(ASN1Encoding.DER);
        } catch (IOException e) {
            return null;
        }
    }


    /**
     * Returns the version number of the syntax of the {@code CertToken} object.
     * <p>
     * The current version is {@link #VERSION}.
     *
     * @return the value of the {@code version} field of this {@code CertToken} object.
     */
    public int getVersion() {
        return version;
    }

    /**
     * Returns the history hash chain from the {@code CertToken} object.
     *
     * @return the contents of the {@code history} field of this {@code CertToken} object.
     */
    public byte[] getHistory() {
        return Util.copyOf(history);
    }

    /**
     * Returns the control publication data from the {@code CertToken} object.
     * <p>
     * This represents the contents of the control publication that can be
     * used to provide tangible proof of integrity of the timestamp.
     *
     * @return the contents of the {@code publishedData} field of this {@code CertToken} object.
     */
    public PublishedData getPublishedData() {
        return publishedData;
    }

    /**
     * Returns the publication references list from the {@code CertToken} object.
     * <p>
     * This list contains bibliographic references to the print media where the
     * control publication represented by {@code PublishedData} was printed.
     *
     * @return the contents of the {@code pubReferences} field of this {@code CertToken} object.
     * @since 0.4.7 (had a different return type in prior versions)
     */
    public References getPubReferences() {
        return pubReferences;
    }

    /**
     * Returns the DER representation of {@code CertToken} extensions.
     * <p>
     * No extensions are used by the current version of the GuardTime service.
     *
     * @return DER-encoded extensions.
     */
    public byte[] getEncodedExtensions() {
        return Util.copyOf(extensions);
    }


    /**
     * Class constructor.
     *
     * @param obj ASN.1 representation of certification token.
     */
    CertToken(ASN1Encodable obj)
            throws Asn1FormatException {
        try {
            certToken = Asn1CertToken.getInstance(obj);

            version = certToken.getVersion().getValue().intValue();
            if (version != VERSION) {
                throw new Asn1FormatException("invalid cert token version: " + version);
            }

            history = certToken.getHistory().getOctets();

            publishedData = new PublishedData(certToken.getPublishedData());

            ASN1Set refs = certToken.getPubReferences();
            if (refs != null) {
                pubReferences = new References(refs);
            }

            Extensions exts = certToken.getExtensions();
            if (exts != null) {
                // check for critical extensions
                Asn1Util.checkExtensions(exts);
                extensions = exts.getEncoded(ASN1Encoding.DER);
            }
        } catch (Asn1FormatException e) {
            throw e;
        } catch (Exception e) {
            throw new Asn1FormatException("cert token has invalid format", e);
        }
    }

    Asn1CertToken getAsn1Token() {
        return certToken;
    }
}


/**
 * Internal implementation class for the ASN.1 representation of
 * {@code CertToken}.
 */
class Asn1CertToken
        extends ASN1Object {
    private ASN1Integer version;
    private ASN1OctetString history;
    private Asn1PublishedData publishedData;
    private ASN1Set pubReferences;
    private Extensions extensions;


    public static Asn1CertToken getInstance(ASN1TaggedObject obj, boolean explicit) {
        return new Asn1CertToken(ASN1Sequence.getInstance(obj, explicit));
    }

    public static Asn1CertToken getInstance(Object obj) {
        if (obj == null || obj instanceof Asn1CertToken) {
            return (Asn1CertToken) obj;
        } else if (obj instanceof ASN1Sequence) {
            return new Asn1CertToken((ASN1Sequence) obj);
        }

        throw new IllegalArgumentException("unknown object in factory: " + obj.getClass().getName());
    }


    public Asn1CertToken(ASN1Sequence seq) {
        Enumeration en = seq.getObjects();

        // Required elements
        version = ASN1Integer.getInstance(en.nextElement());
        history = ASN1OctetString.getInstance(en.nextElement());
        publishedData = Asn1PublishedData.getInstance(en.nextElement());

        // Optional elements
        while (en.hasMoreElements()) {
            Object elem = en.nextElement();
            if (elem instanceof ASN1Set && pubReferences == null) {
                pubReferences = ASN1Set.getInstance(elem);
            } else if (elem instanceof ASN1TaggedObject) {
                ASN1TaggedObject obj = ASN1TaggedObject.getInstance(elem);
                if (obj.getTagNo() == 0 && extensions == null) {
                    extensions = Extensions.getInstance(obj, false);
                } else {
                    throw new IllegalArgumentException("invalid object in factory: " + obj);
                }
            } else {
                throw new IllegalArgumentException("invalid object in factory: " + elem);
            }
        }
    }

    public Extensions getExtensions() {
        return extensions;
    }

    public ASN1OctetString getHistory() {
        return history;
    }

    public ASN1Set getPubReferences() {
        return pubReferences;
    }

    public Asn1PublishedData getPublishedData() {
        return publishedData;
    }

    public ASN1Integer getVersion() {
        return version;
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(version);
        v.add(history);
        v.add(publishedData);
        v.add(pubReferences);
        if (extensions != null) {
            v.add(new DERTaggedObject(false, 0, extensions));
        }
        return new DERSequence(v);
    }

}
