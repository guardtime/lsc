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

import java.io.IOException;
import java.io.InputStream;


/**
 * <a target="_blank" href="http://www.ietf.org/rfc/rfc3161.txt">RFC 3161</a> structure {@code
 * MessageImprint} ({@code contentInfo.content.encapContentInfo.eContent.messageImprint}).
 *
 * <pre>
 * MessageImprint ::= SEQUENCE {
 *    hashAlgorithm AlgorithmIdentifier,
 *    hashedMessage OCTET STRING
 * }
 * </pre>
 *
 * @since 0.4
 */
public final class MessageImprint
        extends Asn1Wrapper {
    private org.bouncycastle.asn1.tsp.MessageImprint messageImprint;
    private String hashAlgorithm;


    /**
     * Parses a DER-encoded {@code MessageImprint} out from the given input stream.
     *
     * @param in the input stream to read data from.
     * @return the {@code MessageImprint} object.
     * @throws com.guardtime.signatureconverter.asn1.Asn1FormatException if the data read from
     *                                                                   {@code in} does not
     *                                                                   represent a valid {@code
     *                                                                   MessageImprint} object.
     * @throws java.io.IOException                                       if {@code in} throws one.
     */
    public static MessageImprint getInstance(InputStream in)
            throws Asn1FormatException, IOException {
        if (in == null) {
            throw new IllegalArgumentException("invalid input stream: null");
        }

        try {
            ASN1Object obj = Asn1Util.readASN1Object(in);
            return new MessageImprint(obj);
        } catch (IOException e) {
            if (isAsnParserException(e)) {
                throw new Asn1FormatException("message imprint has invalid format", e);
            } else {
                throw e;
            }
        } catch (IllegalArgumentException e) {
            if (isAsnParserException(e)) {
                throw new Asn1FormatException("message imprint has invalid format", e);
            } else {
                throw e;
            }
        }
    }


    /**
     * Returns the DER representation of the {@code MessageImprint}.
     *
     * @return a DER byte array, or {@code null} on error.
     */
    public byte[] getDerEncoded() {
        try {
            return messageImprint.getEncoded(ASN1Encoding.DER);
        } catch (IOException e) {
            return null;
        }
    }


    /**
     * Returns the identifier of the hash algorithm used to produce the data
     * hash in this message imprint.
     *
     * @return the algorithm ID.
     */
    public String getHashAlgorithm() {
        return hashAlgorithm;
    }

    /**
     * Returns the data hash from this message imprint.
     *
     * @return the data hash.
     */
    public byte[] getHashedMessage() {
        return Util.copyOf(messageImprint.getHashedMessage());
    }


    /**
     * Class constructor.
     *
     * @param obj ASN.1 representation of message imprint.
     * @throws com.guardtime.signatureconverter.asn1.Asn1FormatException if provided ASN.1 object
     *                                                                   has invalid format.
     */
    MessageImprint(ASN1Encodable obj)
            throws Asn1FormatException {
        try {
            messageImprint = org.bouncycastle.asn1.tsp.MessageImprint.getInstance(obj);

            hashAlgorithm = messageImprint.getHashAlgorithm().getAlgorithm().getId();
        } catch (Exception e) {
            throw new Asn1FormatException("message imprint has invalid format", e);
        }
    }
}
