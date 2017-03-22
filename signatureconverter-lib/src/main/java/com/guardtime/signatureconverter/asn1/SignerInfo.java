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
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;


/**
 * <a target="_blank" href="http://www.ietf.org/rfc/rfc2630.txt">RFC 2630</a>
 * structure {@code SignerInfo} ({@code contentInfo.signerInfos[i]}).
 *
 * <pre>
 * SignerInfo ::= SEQUENCE {
 *    version                   INTEGER  { v0(0), v1(1), v2(2), v3(3), v4(4) },
 *    issuerAndSerialNumber     IssuerAndSerialNumber,
 *    digestAlgorithm           AlgorithmIdentifier,
 *    signedAttributes          [0] IMPLICIT Attributes OPTIONAL,
 *    signatureAlgorithm        AlgorithmIdentifier,
 *    signature                 OCTET STRING,
 *    unsignedAttributes        [1] IMPLICIT Attributes OPTIONAL
 * }
 * </pre>
 *
 * @since 0.4
 */
public final class SignerInfo
        extends Asn1Wrapper {
    public static final int VERSION = 1;
    public static final String CONTENT_TYPE_ID = "1.2.840.113549.1.9.3"; // id-contentType
    public static final String CONTENT_TYPE = "1.2.840.113549.1.9.16.1.4"; // id-ct-TSTInfo
    public static final String MESSAGE_DIGEST_ID = "1.2.840.113549.1.9.4"; // id-messageDigest
    public static final String SIGNATURE_ALGORITHM = "1.3.6.1.4.1.27868.4.1"; // id-gt-TimeSignatureAlg

    private org.bouncycastle.asn1.cms.SignerInfo signerInfo;
    private int version;
    private String issuerName;
    private BigInteger serialNumber;
    private String digestAlgorithm;
    private byte[] messageDigest;
    private byte[] signedAttrs;
    private String signatureAlgorithm;
    private TimeSignature signature;
    private byte[] unsignedAttrs;

    private byte[] signedAttrsBytesBeforeMessageImprint;
    private byte[] signedAttrsBytesAfterMessageImprint;


    /**
     * Parses a DER-encoded {@code SignerInfo} out from the given input stream.
     *
     * @param in the input stream to read data from.
     * @return the {@code SignerInfo} object.
     * @throws com.guardtime.signatureconverter.asn1.Asn1FormatException if the data read from
     *                                                                   {@code in} does not
     *                                                                   represent a valid {@code
     *                                                                   SignerInfo} object.
     * @throws java.io.IOException                                       if {@code in} throws one.
     */
    public static SignerInfo getInstance(InputStream in)
            throws Asn1FormatException, IOException {
        if (in == null) {
            throw new IllegalArgumentException("invalid input stream: null");
        }

        try {
            ASN1Object obj = Asn1Util.readASN1Object(in);
            return new SignerInfo(obj);
        } catch (IOException e) {
            if (isAsnParserException(e)) {
                throw new Asn1FormatException("signer info has invalid format", e);
            } else {
                throw e;
            }
        } catch (IllegalArgumentException e) {
            if (isAsnParserException(e)) {
                throw new Asn1FormatException("signer info has invalid format", e);
            } else {
                throw e;
            }
        }
    }


    /**
     * Returns the DER representation of the {@code SignerInfo}.
     *
     * @return a DER byte array, or {@code null} on error.
     */
    public byte[] getDerEncoded() {
        try {
            return signerInfo.getEncoded(ASN1Encoding.DER);
        } catch (IOException e) {
            return null;
        }
    }

    /**
     * Get all signed attributes bytes before message imprint
     *
     * @return bytes before imprint
     */
    public byte[] getSignedAttrsBytesBeforeMessageImprint() {
        return signedAttrsBytesBeforeMessageImprint;
    }

    /**
     * Get all signed attributes bytes after message imprint
     *
     * @return bytes after imprint
     */
    public byte[] getSignedAttrsBytesAfterMessageImprint() {
        return signedAttrsBytesAfterMessageImprint;
    }

    /**
     * Returns the version number of the syntax of the {@code SignerInfo} object.
     * <p>
     * The current version is {@link #VERSION}.
     *
     * @return the value of the {@code version} field of this {@code SignerInfo} object.
     */
    public int getVersion() {
        return version;
    }

    /**
     * Returns the {@code issuerName} component of the {@code signerIdentifier}
     * field of the {@code SignerInfo} object.
     *
     * @return the name of the CA that issued the certificate for the key used to create the PKI
     * signature embedded in the {@link com.guardtime.signatureconverter.asn1.TimeSignature}.
     */
    public String getIssuerName() {
        return issuerName;
    }

    /**
     * Returns the {@code serialNumber} component of the
     * {@code signerIdentifier} field of the {@code SignerInfo} object.
     *
     * @return the serial number of the certificate for the key used to create the PKI signature
     * embedded in the {@link com.guardtime.signatureconverter.asn1.TimeSignature}.
     */
    public BigInteger getSerialNumber() {
        return serialNumber;
    }

    /**
     * Returns the identifier of the digest algorithm used to hash the
     * {@code TSTInfo} structure to create the value of the
     * {@code message-digest} attribute and also to hash the
     * {@code SignedAttributes} structure for signing it.
     *
     * @return the OID of the digest algorithm.
     */
    public String getDigestAlgorithm() {
        return digestAlgorithm;
    }

    /**
     * Returns the value of the {@code message-digest} attribute
     * from the {@code SignedAttributes} structure.
     *
     * @return the value of the message digest.
     */
    public byte[] getMessageDigest() {
        return Util.copyOf(messageDigest);
    }

    /**
     * Returns the DER representation of the {@code SignedAttributes}.
     *
     * @return a DER byte array.
     */
    public byte[] getEncodedSignedAttrs() {
        return Util.copyOf(signedAttrs);
    }

    /**
     * Returns the identifier of the signature algorithm used to sign the
     * {@code SignedAttributes} structure to create the value of the
     * {@code Signature} field.
     * <p>
     * For GuardTime timestamps, this is always {@link #SIGNATURE_ALGORITHM}.
     *
     * @return the OID of the signature algorithm.
     */
    public String getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    /**
     * Returns the signature.
     *
     * @return the {@link com.guardtime.signatureconverter.asn1.TimeSignature} object.
     */
    public TimeSignature getSignature() {
        return signature;
    }

    /**
     * Returns the DER representation of the {@code UnsignedAttributes}.
     *
     * @return a DER byte array.
     */
    public byte[] getEncodedUnsignedAttrs() {
        return Util.copyOf(unsignedAttrs);
    }


    /**
     * Checks whether the {@code TimeSignature} in this {@code SignerInfo} is
     * extended.
     * <p>
     * An extended signature is traceable to a control publication without any
     * extra information. An unextended signature needs additional information
     * from the online verification service.
     *
     * @return {@code true} if the signature is extended, {@code false} otherwise.
     * @see com.guardtime.signatureconverter.asn1.CertToken
     */
    public boolean isExtended() {
        return signature.isExtended();
    }


    /**
     * Class constructor.
     *
     * @param obj ASN.1 representation of signer info.
     * @throws com.guardtime.signatureconverter.asn1.Asn1FormatException if provided ASN.1 object
     *                                                                   has invalid format.
     */
    SignerInfo(ASN1Encodable obj)
            throws Asn1FormatException {
        try {
            signerInfo = org.bouncycastle.asn1.cms.SignerInfo.getInstance(obj);

            // Extract and check version
            //
            // Since we use the IssuerAndSerialNumber option to identify the
            // signer's certificate, the version has to be 1.
            BigInteger ver = signerInfo.getVersion().getValue();
            if (!ver.equals(BigInteger.valueOf(VERSION))) {
                throw new Asn1FormatException("invalid signer info version: " + ver);
            }
            version = ver.intValue();

            // Extract the signer's certificate identification
            IssuerAndSerialNumber sid = IssuerAndSerialNumber.getInstance(signerInfo.getSID().toASN1Primitive());
            issuerName = sid.getName().toString();
            serialNumber = sid.getSerialNumber().getValue();

            // Extract the digest algorithm ID
            digestAlgorithm = signerInfo.getDigestAlgorithm().getAlgorithm().getId();
            Asn1Util.checkDigestAlgorithm(digestAlgorithm);

            // Extract and check the signed attributes
            //
            // The content-type and message-digest attributes must be present.
            ASN1Set sigAttrs = signerInfo.getAuthenticatedAttributes();
            if (sigAttrs == null) {
                throw new Asn1FormatException("no signed attributes");
            }


            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

            outputStream.write(Asn1Util.getASN1ObjectHeader(sigAttrs));
            outputStream.write(sigAttrs.getObjectAt(0).toASN1Primitive().getEncoded(ASN1Encoding.DER));

            ASN1Sequence attrDataSequence = ASN1Sequence.getInstance(sigAttrs.getObjectAt(1));
            outputStream.write(Asn1Util.getASN1ObjectHeader(attrDataSequence));
            outputStream.write(attrDataSequence.getObjectAt(0).toASN1Primitive().getEncoded(ASN1Encoding.DER));

            ASN1Set attrData = ASN1Set.getInstance(attrDataSequence.getObjectAt(1));
            outputStream.write(Asn1Util.getASN1ObjectHeader(attrData));
            outputStream.write(Asn1Util.getASN1ObjectHeader(attrData.getObjectAt(0).toASN1Primitive()));

            signedAttrsBytesBeforeMessageImprint = outputStream.toByteArray();

            outputStream = new ByteArrayOutputStream();
            for (int i = 2; i < sigAttrs.size(); i++) {
                outputStream.write(sigAttrs.getObjectAt(i).toASN1Primitive().getEncoded(ASN1Encoding.DER));
            }

            signedAttrsBytesAfterMessageImprint = outputStream.toByteArray();

            ASN1Encodable ct = Asn1Util.getAttributeValue(sigAttrs, CONTENT_TYPE_ID);
            if (ct == null || !(new ASN1ObjectIdentifier(CONTENT_TYPE).equals(ct))) {
                throw new Asn1FormatException("invalid content-type signed attribute value");
            }
            ASN1Encodable md = Asn1Util.getAttributeValue(sigAttrs, MESSAGE_DIGEST_ID);
            if (md == null || !(md instanceof DEROctetString)) {
                throw new Asn1FormatException("invalid message-digest signed attribute");
            }
            messageDigest = ((ASN1OctetString) md).getOctets();
            signedAttrs = sigAttrs.getEncoded(ASN1Encoding.DER);

            // Extract and check the signature algorithm ID
            signatureAlgorithm = signerInfo.getDigestEncryptionAlgorithm().getAlgorithm().getId();
            if (!signatureAlgorithm.equals(SIGNATURE_ALGORITHM)) {
                throw new Asn1FormatException("invalid signature algorithm: " + signatureAlgorithm);
            }

            // Extract the signature
            signature = new TimeSignature(ASN1Primitive.fromByteArray(signerInfo.getEncryptedDigest().getOctets()));

            // Extract the unsigned attributes
            ASN1Set unsigAttrs = signerInfo.getUnauthenticatedAttributes();
            unsignedAttrs = ((unsigAttrs == null) ? null : unsigAttrs.getEncoded(ASN1Encoding.DER));
        } catch (Asn1FormatException e) {
            throw e;
        } catch (Exception e) {
            // Also catches IllegalArgumentException, NullPointerException, etc.
            throw new Asn1FormatException("signer info has invalid format", e);
        }
    }
}
