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

package com.guardtime.signatureconverter;

import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.hashing.HashAlgorithm;
import com.guardtime.ksi.tlv.TLVElement;
import com.guardtime.ksi.util.Base16;

import org.testng.Assert;
import org.testng.annotations.Test;

import java.io.ByteArrayInputStream;
import java.util.LinkedList;

public class AggregationHashChainBuilderTest {
    private static final byte[] AGGREGATION_HASH_CHAIN_BYTES = {
            1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
            1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2,
            1, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3,
            1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 19,
    };


    private static final DataHash INPUT_HASH = new DataHash(HashAlgorithm.SHA2_256, new byte[32]);
    private static final DataHash SIBLING_HASH = new DataHash(HashAlgorithm.SHA2_256, new byte[]{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1});

    @Test
    public void testReadLink() throws Exception {
        AggregationHashChainBuilder builder = new AggregationHashChainBuilder();
        builder.setInputStream(new ByteArrayInputStream(AGGREGATION_HASH_CHAIN_BYTES));
        builder.setInputHash(INPUT_HASH);
        LinkedList<TLVElement> elements = builder.build();
        Assert.assertEquals(elements.size(), 2);
        Assert.assertEquals(elements.get(1).getChildElements(0x5).get(0).getDecodedDataHash(), new DataHash(Base16.decode("019FA04C39634610E34ABF4FB2FD812D481939BE20026FD82DD406531832B49878")));
    }

    @Test
    public void testLinkInputHash() {
        AggregationHashChainBuilder builder = new AggregationHashChainBuilder();
        DataHash linkInputHash = builder.getLinkInputHash(INPUT_HASH, HashAlgorithm.SHA2_256, true);
        Assert.assertEquals(linkInputHash, new DataHash(HashAlgorithm.SHA2_256, Base16.decode("1a7dfdeaffeedac489287e85be5e9c049a2ff6470f55cf30260f55395ac1b159")));
    }

    @Test
    public void testHashStepLeft() {
        AggregationHashChainBuilder builder = new AggregationHashChainBuilder();
        DataHash dataHash = builder.hashStep(HashAlgorithm.SHA2_256, 0x7, INPUT_HASH.getImprint(), SIBLING_HASH.getImprint(), (byte) 75);
        Assert.assertEquals(dataHash, new DataHash(HashAlgorithm.SHA2_256, Base16.decode("f32c21885bb4ec418bf2dba729df71b5345a180c63ddb6e063173b113ff0ee5f")));
    }

    @Test
    public void testHashStepRight() {
        AggregationHashChainBuilder builder = new AggregationHashChainBuilder();
        DataHash dataHash = builder.hashStep(HashAlgorithm.SHA2_256, 0x8, INPUT_HASH.getImprint(), SIBLING_HASH.getImprint(), (byte) 75);
        Assert.assertEquals(dataHash, new DataHash(HashAlgorithm.SHA2_256, Base16.decode("1241d5cf78cb9b55f6f5573ef3c893deb4d5f0459b489b1b961f47f9a789078f")));
    }

    @Test(expectedExceptions = Exception.class, expectedExceptionsMessageRegExp = "No links found in aggregation hash chain.")
    public void testEmptyInputStream() throws Exception {
        AggregationHashChainBuilder builder = new AggregationHashChainBuilder();
        builder.setInputStream(new ByteArrayInputStream(new byte[0]));
        builder.setInputHash(INPUT_HASH);
        builder.build();
    }

    @Test(expectedExceptions = Exception.class, expectedExceptionsMessageRegExp = "Invalid link, end of stream after algorithm byte.")
    public void testInvalidInputStreamDataWithAlgorithmByteOnly() throws Exception {
        AggregationHashChainBuilder builder = new AggregationHashChainBuilder();
        builder.setInputStream(new ByteArrayInputStream(new byte[]{1}));
        builder.setInputHash(INPUT_HASH);
        builder.build();
    }

    @Test(expectedExceptions = Exception.class, expectedExceptionsMessageRegExp = "Invalid hash step direction: 2")
    public void testInvalidInputStreamDataWithInvalidDirection() throws Exception {
        AggregationHashChainBuilder builder = new AggregationHashChainBuilder();
        builder.setInputStream(new ByteArrayInputStream(new byte[]{1, 2}));
        builder.setInputHash(INPUT_HASH);
        builder.build();
    }

    @Test(expectedExceptions = Exception.class, expectedExceptionsMessageRegExp = "Invalid link, end of stream after direction byte.")
    public void testInvalidInputStreamDataWithoutHashAndLevel() throws Exception {
        AggregationHashChainBuilder builder = new AggregationHashChainBuilder();
        builder.setInputStream(new ByteArrayInputStream(new byte[]{1, 0}));
        builder.setInputHash(INPUT_HASH);
        builder.build();
    }

    @Test(expectedExceptions = Exception.class, expectedExceptionsMessageRegExp = "unsupported algorithm GTID: 50")
    public void testInvalidInputStreamDataIncorrectHashAlgorithm() throws Exception {
        AggregationHashChainBuilder builder = new AggregationHashChainBuilder();
        builder.setInputStream(new ByteArrayInputStream(new byte[]{1, 0, 50}));
        builder.setInputHash(INPUT_HASH);
        builder.build();
    }

    @Test(expectedExceptions = Exception.class, expectedExceptionsMessageRegExp = "Invalid link, not enough data for hash imprint.")
    public void testInvalidInputStreamDataIncorrectHash() throws Exception {
        AggregationHashChainBuilder builder = new AggregationHashChainBuilder();
        builder.setInputStream(new ByteArrayInputStream(new byte[]{1, 0, 1}));
        builder.setInputHash(INPUT_HASH);
        builder.build();
    }

    @Test(expectedExceptions = Exception.class, expectedExceptionsMessageRegExp = "Invalid hash step level: 0")
    public void testInvalidInputStreamDataIncorrectLevel() throws Exception {
        AggregationHashChainBuilder builder = new AggregationHashChainBuilder();
        builder.setInputStream(new ByteArrayInputStream(new byte[]{1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}));
        builder.setInputHash(INPUT_HASH);
        builder.build();
    }

    @Test(expectedExceptions = Exception.class, expectedExceptionsMessageRegExp = "Legacy ID second byte must be 0")
    public void testInvalidInputStreamDataIncorrectLegacyIdSecondByte() throws Exception {
        AggregationHashChainBuilder builder = new AggregationHashChainBuilder();
        builder.setInputStream(new ByteArrayInputStream(new byte[]{1, 0, 3, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3}));
        builder.setInputHash(INPUT_HASH);
        builder.build();
    }

    @Test(expectedExceptions = Exception.class, expectedExceptionsMessageRegExp = "Bytes after the legacy ID string must be 0")
    public void testInvalidInputStreamDataIncorrectLegacyIdInvalidLength() throws Exception {
        AggregationHashChainBuilder builder = new AggregationHashChainBuilder();
        builder.setInputStream(new ByteArrayInputStream(new byte[]{1, 0, 3, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3}));
        builder.setInputHash(INPUT_HASH);
        builder.build();
    }


    @Test(expectedExceptions = Exception.class, expectedExceptionsMessageRegExp = "Invalid aggregation hash chain input stream: null")
    public void testInvalidInputStream() throws Exception {
        AggregationHashChainBuilder builder = new AggregationHashChainBuilder();
        builder.build();
    }

    @Test(expectedExceptions = Exception.class, expectedExceptionsMessageRegExp = "Invalid input hash: null")
    public void testInvalidInputHash() throws Exception {
        AggregationHashChainBuilder builder = new AggregationHashChainBuilder();
        builder.setInputStream(new ByteArrayInputStream(new byte[0]));
        builder.build();
    }


}