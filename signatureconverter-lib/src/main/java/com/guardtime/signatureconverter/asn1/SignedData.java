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
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;


/**
 * <a target="_blank" href="http://www.ietf.org/rfc/rfc2630.txt">RFC 2630</a>
 * structure {@code SignedData} ({@code contentInfo.content}).
 *
 * <pre>
 * SignedData ::= SEQUENCE {
 *    version          INTEGER  { v0(0), v1(1), v2(2), v3(3), v4(4) },
 *    digestAlgorithms SET OF DigestAlgorithmIdentifier,
 *    encapContentInfo EncapsulatedContentInfo,
 *    certificates     [0] IMPLICIT SET OF CertificateChoices OPTIONAL,
 *    crls             [1] IMPLICIT SET OF CertificateList OPTIONAL,
 *    signerInfos      SET OF SignerInfo
 * }
 * </pre>
 *
 * @see com.guardtime.signatureconverter.asn1.SignerInfo
 * @since 0.4
 */
public final class SignedData
        extends Asn1Wrapper {
    public static final int VERSION = 3;
    public static final String E_CONTENT_TYPE = "1.2.840.113549.1.9.16.1.4";

    private org.bouncycastle.asn1.cms.SignedData signedData;
    private int version;
    private List digestAlgorithms;
    private String eContentType;
    private TstInfo eContent;
    private X509Certificate certificate;
    private byte[] crls;
    private SignerInfo signerInfo;


    /**
     * Parses a DER-encoded {@code SignedData} out from the given input stream.
     *
     * @param in the input stream to read data from.
     * @return the {@code SignedData} object.
     * @throws com.guardtime.signatureconverter.asn1.Asn1FormatException if the data read from
     *                                                                   {@code in} does not
     *                                                                   represent a valid {@code
     *                                                                   SignedData} object.
     * @throws java.io.IOException                                       if {@code in} throws one.
     */
    public static SignedData getInstance(InputStream in)
            throws Asn1FormatException, IOException {
        if (in == null) {
            throw new IllegalArgumentException("invalid input stream: null");
        }

        try {
            ASN1Object obj = Asn1Util.readASN1Object(in);
            return new SignedData(obj);
        } catch (IOException e) {
            if (isAsnParserException(e)) {
                throw new Asn1FormatException("signed data has invalid format", e);
            } else {
                throw e;
            }
        } catch (IllegalArgumentException e) {
            if (isAsnParserException(e)) {
                throw new Asn1FormatException("signed data has invalid format", e);
            } else {
                throw e;
            }
        }
    }


    /**
     * Returns the DER representation of the {@code SignedData}.
     *
     * @return a DER byte array, or {@code null} on error.
     */
    public byte[] getDerEncoded() {
        try {
            return signedData.getEncoded(ASN1Encoding.DER);
        } catch (IOException e) {
            return null;
        }
    }


    /**
     * Returns the version number of the syntax of the {@code SignedData} object.
     * GuardTime timestamps always use {@link #VERSION}.
     *
     * @return the value of the {@code version} field of this {@code SignedData} object.
     */
    public int getVersion() {
        return version;
    }

    /**
     * Returns the identifiers of digest algorithms used to hash the timestamped
     * data.
     * <p>
     * In general, there may be several signatures in a {@code SignedData}
     * structure, but RFC 3161 requires that timestamps only contain one.
     * Therefore it is to be expected that this list also contains only one
     * element, but this is not an actual requirement.
     * <p>
     * This list is read-only. Any attempts to modify it will result in an
     * {@code UnsupportedOperationException}.
     *
     * @return the list of algorithm identifiers.
     */
    public List getDigestAlgorithms() {
        return ((digestAlgorithms == null) ? null : Collections.unmodifiableList(digestAlgorithms));
    }

    /**
     * Returns the identifier of the type of the embedded content.
     * <p>
     * It must be equal to {@link #E_CONTENT_TYPE} for timestamps.
     *
     * @return the content type OID.
     */
    public String getEContentType() {
        return eContentType;
    }

    /**
     * Returns the actual content embedded in this object.
     * <p>
     * This must be a {@code TSTInfo} object for timestamps.
     *
     * @return the content.
     */
    public TstInfo getEContent() {
        return eContent;
    }

    /**
     * Returns the certificate needed to verify the PKI signature embedded in
     * the TimeSignature of an unextended timestamp.
     * <p>
     * In general, there may be several certificates in a {@code SignedData}
     * structure, but RFC 3161 requires that timestamps only contain one. The
     * whole list is still optional, though, and always absent in extended
     * GuardTime timestamps.
     * <p>
     * If several certificates are found in this signed data, all except the
     * first one (#0) are ignored.
     *
     * @return a certificate containing the public key needed to verify the {@link
     * com.guardtime.signatureconverter.asn1.TimeSignature}, or {@code null}.
     */
    public X509Certificate getCertificate() {
        return certificate;
    }

    /**
     * Returns DER representation of CRLs contained in this timestamp.
     * <p>
     * GuardTime is not using CRLs field of the timestamp, so this method
     * should return {@code null} if invoked on a valid GuardTime timestamp.
     *
     * @return DER-encoded CRLs.
     */
    public byte[] getEncodedCrls() {
        return Util.copyOf(crls);
    }

    /**
     * Returns the signer info structure signing the timestamp.
     * <p>
     * In general, there may be several signatures in a {@code SignedData}
     * structure, but RFC 3161 requires that timestamps only contain one.
     *
     * @return a {@code SignerInfo} structure signing the timestamp.
     */
    public SignerInfo getSignerInfo() {
        return signerInfo;
    }


    /**
     * Checks whether the timestamp is extended.
     * <p>
     * An extended timestamp is traceable to a control publication without any
     * extra information. An unextended timestamp needs additional information
     * from the online verification service.
     *
     * @return {@code true} if the timestamp is extended, {@code false} otherwise.
     * @see com.guardtime.signatureconverter.asn1.CertToken
     */
    public boolean isExtended() {
        return signerInfo.isExtended();
    }


    /**
     * Class constructor.
     *
     * @param obj ASN.1 representation of signed data.
     * @throws com.guardtime.signatureconverter.asn1.Asn1FormatException if provided ASN.1 object
     *                                                                   has invalid format.
     */
    SignedData(ASN1Encodable obj)
            throws Asn1FormatException {
        try {
            signedData = org.bouncycastle.asn1.cms.SignedData.getInstance(obj);

            // Extract and check version
            //
            // RFC 2630/3161 require version to be 0..4
            // GuardTime requires version to be exactly 3
            BigInteger ver = signedData.getVersion().getValue();
            if (!ver.equals(BigInteger.valueOf(VERSION))) {
                throw new Asn1FormatException("invalid signed data version: " + ver);
            }
            version = ver.intValue();

            // Extract and check digest algorithm list
            //
            // Digest algorithm list can contain duplicate entries as
            // RFC 2630 does not directly deny that
            //
            // RFC 2630 allows digest algorithm list to be empty
            digestAlgorithms = new ArrayList();
            Enumeration e = signedData.getDigestAlgorithms().getObjects();
            while (e.hasMoreElements()) {
                Object o = e.nextElement();
                String algOid = AlgorithmIdentifier.getInstance(o).getAlgorithm().getId();
                Asn1Util.checkDigestAlgorithm(algOid);
                digestAlgorithms.add(algOid);
            }

            // Extract and check encapsulated content info
            ContentInfo eContentInfo = signedData.getEncapContentInfo();
            eContentType = eContentInfo.getContentType().toString();
            // RFC3161 requires type to be id-ct-TSTInfo
            if (!eContentType.equals(E_CONTENT_TYPE)) {
                throw new Asn1FormatException("invalid encapsulated content type: " + eContentType);
            }
            DEROctetString eContentData = (DEROctetString) eContentInfo.getContent();
            eContent = TstInfo.getInstance(eContentData.getOctetStream());

            // Extract certificates (optional field)
            ASN1Set certificates = signedData.getCertificates();
            if (certificates != null && certificates.size() > 0) {
                byte[] certBytes = certificates.getObjectAt(0).toASN1Primitive().getEncoded(ASN1Encoding.DER);
                InputStream in = new ByteArrayInputStream(certBytes);
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                certificate = (X509Certificate) cf.generateCertificate(in);
            }

            // Extract CRLs (GuardTime is not currently using CRLs field)
            ASN1Set rawCrls = signedData.getCRLs();
            crls = ((rawCrls == null) ? null : rawCrls.getEncoded(ASN1Encoding.DER));

            // Extract and check signer info
            ASN1Set signerInfos = signedData.getSignerInfos();
            // RFC 3161 requires signer info list to contain exactly one entry
            if (signerInfos.size() != 1) {
                throw new Asn1FormatException("wrong number of signer infos found: " + signerInfos.size());
            }
            signerInfo = new SignerInfo(signerInfos.getObjectAt(0).toASN1Primitive());
            // Make sure digest algorithm is contained in digest algorithm list
            // TODO: check disabled as this problem is not critical.
            //String digestAlgorithmOid = signerInfo.getDigestAlgorithm();
            //if (!digestAlgorithms.contains(digestAlgorithmOid)) {
            //	throw new Asn1FormatException("digest algorithm not found in list: " + digestAlgorithmOid);
            //}
        } catch (Asn1FormatException e) {
            throw e;
        } catch (Exception e) {
            // Also catches IllegalArgumentException, NullPointerException, etc.
            throw new Asn1FormatException("signed data has invalid format", e);
        }
    }
}
