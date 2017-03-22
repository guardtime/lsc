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

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERNull;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CodingErrorAction;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

/**
 * GuardTime structure for bibliographic references:
 * {@code contentInfo.content.signerInfo.signature.pubReferences},
 * {@code contentInfo.content.signerInfo.signature.pkSignature.keyCommitmentRef}.
 * <p>
 * Note that the reference lists are tagged differently in different contexts
 * ([0] for PKI key commitment references, [1] for publication references in
 * SignatureInfo, untagged in extender responses and publications files) and
 * the code for the containing object is expected to handle the tagging and
 * untagging.
 *
 * @since 0.4.7
 */
public final class References extends Asn1Wrapper {
    private ASN1Set references;

    /**
     * Parses a DER-encoded {@code References} out from the given input stream.
     *
     * @param in the input stream to read data from.
     * @return the {@code References} object.
     * @throws Asn1FormatException if the data read from {@code in} does not represent a valid
     *                             {@code References} object.
     * @throws java.io.IOException if {@code in} throws one.
     */
    public static References getInstance(InputStream in)
            throws Asn1FormatException, IOException {
        if (in == null) {
            throw new IllegalArgumentException("invalid input stream: null");
        }

        try {
            ASN1Object obj = Asn1Util.readASN1Object(in);
            return new References(obj);
        } catch (IOException e) {
            if (isAsnParserException(e)) {
                throw new Asn1FormatException("references have invalid format", e);
            } else {
                throw e;
            }
        } catch (IllegalArgumentException e) {
            if (isAsnParserException(e)) {
                throw new Asn1FormatException("references have invalid format", e);
            } else {
                throw e;
            }
        }
    }

    /**
     * Returns the DER representation of the {@code References}.
     *
     * @return a DER byte array, or {@code null} on error.
     */
    public byte[] getDerEncoded() {
        try {
            return references.getEncoded(ASN1Encoding.DER);
        } catch (IOException e) {
            return null;
        }
    }

    public List toStringList() {
        List res = new ArrayList();
        Enumeration e = references.getObjects();
        while (e.hasMoreElements()) {
            Object nextElement = e.nextElement();
            if (nextElement instanceof DERNull) {
                res.add("");
            } else {
                byte[] data = ((ASN1OctetString) nextElement).getOctets();
                if (data != null && data.length >= 2 && data[0] == 0 && data[1] == 1) {
                    // the rest should be an UTF-8 encoded string
                    try {
                        CharsetDecoder dec = Charset.forName("UTF-8").newDecoder();
                        dec.onMalformedInput(CodingErrorAction.REPORT);
                        res.add(dec.decode(ByteBuffer.wrap(data, 2, data.length - 2)).toString());
                    } catch (Exception x) {
                        res.add(Base16.encodeWithColons(data));
                    }
                } else if (data != null) {
                    res.add(Base16.encodeWithColons(data));
                } else {
                    res.add("");
                }
            }
        }
        return res;
    }

    /**
     * Returns a reference to the embedded ASN1Set object.
     *
     * @return reference to the wrapped set object.
     */
    public ASN1Set getReferences() {
        return references;
    }

    /**
     * Class constructor.
     *
     * @param obj ASN.1 representation of the references.
     * @throws Asn1FormatException if provided ASN.1 object has invalid format.
     */
    References(ASN1Encodable obj) throws Asn1FormatException {
        try {
            references = ASN1Set.getInstance(obj);
            Enumeration e = references.getObjects();
            while (e.hasMoreElements()) {
                Object o = e.nextElement();
                if (!(o instanceof DERNull) && !(o instanceof ASN1OctetString)) {
                    throw null;
                }
            }
        } catch (Exception e) {
            throw new Asn1FormatException("references have invalid format", e);
        }
    }
}
