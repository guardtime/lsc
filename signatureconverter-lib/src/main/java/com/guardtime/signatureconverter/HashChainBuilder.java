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
import com.guardtime.ksi.hashing.DataHasher;
import com.guardtime.ksi.hashing.HashAlgorithm;
import com.guardtime.ksi.tlv.TLVElement;
import com.guardtime.signatureconverter.tsp.LegacyHashAlgorithm;

import java.io.InputStream;

public class HashChainBuilder {

    protected InputStream inputStream;
    protected DataHash inputHash;

    protected TLVElement getLinkElement(byte direction) throws Exception {
        if (direction == 0) {
            return new TLVElement(false, false, 0x8);
        }

        if (direction == 1) {
            return new TLVElement(false, false, 0x7);
        }

        throw new Exception("Invalid hash step direction: " + direction);
    }

    protected Link readLink(DataHash inputHash, int previousLevel, boolean isFirst) throws Exception {
        int algorithmByte = inputStream.read();
        if (algorithmByte == -1) {
            return null;
        }

        Link link = new Link();

        // [0] -- hash algorithm
        link.algorithm = HashAlgorithm.getById(algorithmByte);
        link.inputHash = getLinkInputHash(inputHash, link.algorithm, isFirst);

        // [1] -- direction
        int direction = inputStream.read();
        if (direction == -1) {
            throw new Exception("Invalid link, end of stream after algorithm byte.");
        }
        TLVElement linkTlvElement = getLinkElement((byte) direction);

        // [2 .. size - 2] -- sibling data imprint
        int siblingLegacyHashAlgorithmByte = inputStream.read();
        if (siblingLegacyHashAlgorithmByte == -1) {
            throw new Exception("Invalid link, end of stream after direction byte.");
        }
        LegacyHashAlgorithm siblingLegacyHashAlgorithm = LegacyHashAlgorithm.getByGtid(siblingLegacyHashAlgorithmByte);
        byte[] siblingHashImprint = new byte[siblingLegacyHashAlgorithm.getHashLength() + 1];
        siblingHashImprint[0] = (byte) siblingLegacyHashAlgorithm.getGtid();
        int siblingHashImprintByteLength = inputStream.read(siblingHashImprint, 1, siblingLegacyHashAlgorithm.getHashLength());
        if (siblingHashImprintByteLength != siblingLegacyHashAlgorithm.getHashLength()) {
            throw new Exception("Invalid link, not enough data for hash imprint.");
        }
        setLinkTlvElementContent(linkTlvElement, siblingLegacyHashAlgorithm, siblingHashImprint);

        // [size - 1] -- level
        link.level = inputStream.read() & 0xFF;
        setLinkTlvElementLevel(linkTlvElement, link.level, previousLevel);
        link.resultHash = hashStep(link.algorithm, linkTlvElement.getType(), siblingHashImprint, link.inputHash.getImprint(), (byte) link.level);
        link.nextLink = readLink(link.resultHash, link.level, false);
        link.element = linkTlvElement;
        return link;
    }

    protected DataHash hashStep(HashAlgorithm algorithm, int direction, byte[] siblingHashImprint, byte[] inputHashImprint, byte level) {
        DataHasher hasher = new DataHasher(algorithm);

        if (direction == 0x8) {
            hasher.addData(siblingHashImprint);
            hasher.addData(inputHashImprint);
        } else {
            hasher.addData(inputHashImprint);
            hasher.addData(siblingHashImprint);
        }

        hasher.addData(new byte[]{level});

        return hasher.getHash();
    }

    public void setInputStream(InputStream inputStream) {
        this.inputStream = inputStream;
    }

    public void setInputHash(DataHash inputHash) {
        this.inputHash = inputHash;
    }

    protected void setLinkTlvElementLevel(TLVElement linkTlvElement, int level, int previousLevel) throws Exception {

    }

    protected void setLinkTlvElementContent(TLVElement linkTlvElement, LegacyHashAlgorithm siblingLegacyHashAlgorithm, byte[] siblingHashImprint) throws Exception {
        linkTlvElement.setContent(siblingHashImprint);
    }

    protected DataHash getLinkInputHash(DataHash inputHash, HashAlgorithm algorithm, boolean isFirst) {
        return inputHash;
    }

    protected static class Link {
        public HashAlgorithm algorithm;
        public DataHash inputHash;
        public DataHash resultHash;
        public TLVElement element;
        public Link nextLink;
        public int level;

    }
}
