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
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Enumeration;


/**
 * ASN.1 related utility functions.
 */
abstract class Asn1Util {
    private static String[] supportedDigestAlgorithms = {
            TeleTrusTObjectIdentifiers.ripemd160.getId(),
            OIWObjectIdentifiers.idSHA1.getId(),
            NISTObjectIdentifiers.id_sha224.getId(),
            NISTObjectIdentifiers.id_sha256.getId(),
            NISTObjectIdentifiers.id_sha384.getId(),
            NISTObjectIdentifiers.id_sha512.getId()
    };

    /**
     * Checks that the given digest algorithm is supported.
     *
     * @param algOid algorithm OID.
     * @throws com.guardtime.signatureconverter.asn1.Asn1FormatException if algorithm is not
     *                                                                   supported.
     */
    static void checkDigestAlgorithm(String algOid)
            throws Asn1FormatException {
        for (int i = 0; i < supportedDigestAlgorithms.length; i++) {
            if (algOid.equals(supportedDigestAlgorithms[i])) {
                return;
            }
        }

        throw new Asn1FormatException("digest algorithm not supported: " + algOid);
    }

    /**
     * Verifies that the given extensions list does not contain any critical
     * extensions.
     *
     * @param exts the extensions list to check.
     * @throws com.guardtime.signatureconverter.asn1.Asn1FormatException if the lists is not
     *                                                                   properly formatted or
     *                                                                   contains critical extensions.
     */
    static void checkExtensions(Extensions exts)
            throws Asn1FormatException {
        if (exts == null) {
            // no extensions, nothing to check
            return;
        }
        Enumeration e = exts.oids();
        if (!e.hasMoreElements()) {
            // empty extensions lists are not allowed per X.509 specifications
            throw new Asn1FormatException("empty extensions list");
        }
        while (e.hasMoreElements()) {
            ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier((String) e.nextElement());
            Extension ext = exts.getExtension(oid);
            if (ext == null) {
                // should never happen, but...
                throw new Asn1FormatException("empty extension " + oid.getId());
            }
            if (ext.isCritical()) {
                throw new Asn1FormatException("unknown critical extension " + oid.getId());
            }
        }
    }

    /**
     * Extracts the value of the specified attribute from the given attribute
     * set.
     *
     * @param attrs the attribute set to search; this must not be {@code null}.
     * @param oid   the OID of the attribute to look for.
     * @return the value of the attribute.
     * @throw Asn1FormatException if the attribute does not have exactly one single value in the
     * set.
     */
    static ASN1Encodable getAttributeValue(ASN1Set attrs, String oid)
            throws Asn1FormatException {
        ASN1ObjectIdentifier asnOid = new ASN1ObjectIdentifier(oid);
        ASN1Encodable val = null;
        int count = 0;
        for (int i = 0; i < attrs.size(); ++i) {
            Attribute attr = Attribute.getInstance(attrs.getObjectAt(i));
            if (attr.getAttrType().equals(asnOid)) {
                ASN1Set set = attr.getAttrValues();
                if (set.size() < 1) {
                    throw new Asn1FormatException("empty attribute " + oid);
                }
                if (set.size() > 1) {
                    throw new Asn1FormatException("multi-valued attribute " + oid);
                }
                val = set.getObjectAt(0);
                ++count;
            }
        }
        if (count < 1) {
            throw new Asn1FormatException("no attribute " + oid);
        }
        if (count > 1) {
            throw new Asn1FormatException("multiple instances of attribute " + oid);
        }
        return val;
    }

    /**
     * Converts an array of bytes into an ASN1Object.
     */
    public static ASN1Object readASN1Object(byte[] data) throws IOException {
        ASN1InputStream asn1is = new ASN1InputStream(data);
        try {
            ASN1Object asn1object = asn1is.readObject();
            return asn1object;
        } finally {
            asn1is.close();
        }
    }

    /**
     * Converts an Inputstream into an ASN1Object.
     */
    public static ASN1Object readASN1Object(InputStream is) throws IOException {
        ASN1InputStream asn1is = new ASN1InputStream(is);
        try {
            ASN1Object asn1object = asn1is.readObject();
            return asn1object;
        } finally {
            asn1is.close();
        }
    }


    public static byte[] getASN1ObjectHeader(ASN1Object asn1Object) throws IOException {
        InputStream inputStream = new ByteArrayInputStream(asn1Object.getEncoded(ASN1Encoding.DER));
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(inputStream.read());
        int length = inputStream.read() & 0xFF;
        byte[] lengthBytes;
        if (length > 127) {
            int lengthBytesSize = length & 127;
            lengthBytes = new byte[lengthBytesSize];
            inputStream.read(lengthBytes, 0, lengthBytesSize);
            outputStream.write(length);
        } else {
            lengthBytes = new byte[1];
            lengthBytes[0] = (byte) length;
        }

        outputStream.write(lengthBytes);
        inputStream.close();
        return outputStream.toByteArray();
    }
}


/**
 * ASN.1 object wrapper.
 */
abstract class Asn1Wrapper {
    abstract public byte[] getDerEncoded();

    /**
     * Starting with version 1.47, the ASN.1 parser in BC throws generic
     * IOExceptions in several cases where some sort of ASN.1 format exception
     * would be more appropriate (for example, when an unknown ASN.1 tag or
     * unsupported length encoding is encountered).
     * <p>
     * This method analyzes the stack trace from an exception and tries to
     * detect such a situation with the goal that the exception could then be
     * wrapped into a more appropriate exception type by the calling code in the
     * GT API for the benefit of error handling in client code.
     * <p>
     * For consistency of results, we additionally apply the same logic to some
     * runtime exception types that have also been used to signal conditions
     * that really are ASN.1 format errors.
     *
     * @param e the exception to be analyzed.
     * @return {@code true}, if {@code e} appears to be caused by an ASN.1 syntax error.
     */
    protected static boolean isAsnParserException(Exception e) {
        StackTraceElement trace[] = e.getStackTrace();
        return trace.length > 0
                && trace[0] != null
                && trace[0].getClassName() != null
                && (trace[0].getClassName().startsWith("org.bouncycastle.asn1.")
                || trace[0].getClassName().startsWith("com.guardtime.signatureconverter.asn1."));
    }
}
