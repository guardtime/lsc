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
import com.guardtime.ksi.tlv.TLVParserException;
import com.guardtime.ksi.unisignature.AggregationHashChain;
import com.guardtime.signatureconverter.tsp.LegacyHashAlgorithm;

import java.util.LinkedList;
import java.util.List;
import java.util.ListIterator;

class AggregationHashChainBuilder extends HashChainBuilder {

    private static final int STATE_LEVEL = 19;
    private static final int NATIONAL_LEVEL = 39;
    private static final int TOP_LEVEL = 60;


    private DataHash outputHash;

    public LinkedList<TLVElement> build() throws Exception {
        if (inputStream == null) {
            throw new Exception("Invalid aggregation hash chain input stream: null");
        }

        if (inputHash == null) {
            throw new Exception("Invalid input hash: null");
        }

        TLVElement aggregationHashChain = new TLVElement(false, false, AggregationHashChain.ELEMENT_TYPE);
        LinkedList<TLVElement> chains = new LinkedList<TLVElement>();
        chains.add(aggregationHashChain);

        Link link = readLink(inputHash, 0, true);
        if (link == null) {
            throw new Exception("No links found in aggregation hash chain.");
        }

        aggregationHashChain.addChildElement(TLVElement.create(0x5, link.inputHash));
        aggregationHashChain.addChildElement(TLVElement.create(0x6, link.algorithm.getId()));

        while (link != null) {
            if (aggregationHashChain.getChildElements().size() > 2 && link.nextLink != null && (link.nextLink.level == STATE_LEVEL || link.nextLink.level == NATIONAL_LEVEL || link.nextLink.level == TOP_LEVEL)) {
                aggregationHashChain = new TLVElement(false, false, AggregationHashChain.ELEMENT_TYPE);
                chains.add(aggregationHashChain);
                aggregationHashChain.addChildElement(TLVElement.create(0x5, link.inputHash));
                aggregationHashChain.addChildElement(TLVElement.create(0x6, link.algorithm.getId()));
            }

            if (link.nextLink == null) {
                outputHash = link.resultHash;
            }

            aggregationHashChain.addChildElement(link.element);
            link = link.nextLink;
        }

        /*
            Add chain indices to aggregation hash chains
         */
        attachChainIndices(chains);

        return chains;
    }


    private void attachChainIndices(List<TLVElement> chains) throws TLVParserException {
        List<TLVElement> chainIndexes = new LinkedList<TLVElement>();
        for (int i = chains.size() - 1; i >= 0; i--) {
            TLVElement aggregationHashChain = chains.get(i);
            long chainIndex = calculateChainIndex(aggregationHashChain);

            chainIndexes.add(TLVElement.create(0x3, chainIndex));
            for (TLVElement index : chainIndexes) {
                aggregationHashChain.addChildElement(index);
            }
        }
    }

    private long calculateChainIndex(TLVElement aggregationHashChain) {
        List<TLVElement> childElements = aggregationHashChain.getChildElements();
        ListIterator<TLVElement> listIterator = childElements.listIterator(childElements.size());
        long chainIndex = 1;
        while (listIterator.hasPrevious()) {
            TLVElement child = listIterator.previous();
            if (child.getType() != 0x7 && child.getType() != 0x8) {
                continue;
            }

            chainIndex <<= 1;
            if (child.getType() == 0x7) {
                chainIndex |= 1;
            }
        }

        return chainIndex;
    }

    public DataHash getOutputHash() {
        return outputHash;
    }

    @Override
    protected void setLinkTlvElementLevel(TLVElement linkTlvElement, int level, int previousLevel) throws Exception {
        if (level <= previousLevel) {
            throw new Exception("Invalid hash step level: " + level);
        }

        if (previousLevel + 1 < level) {
            linkTlvElement.addChildElement(TLVElement.create(0x1, (long) level - previousLevel - 1));
        }
    }

    @Override
    protected void setLinkTlvElementContent(TLVElement linkTlvElement, LegacyHashAlgorithm siblingLegacyHashAlgorithm, byte[] siblingHashImprint) throws Exception {
        TLVElement linkSiblingHash;
        if (siblingLegacyHashAlgorithm.getGtid() == LegacyHashAlgorithm.SHA224.getGtid()) {
            linkSiblingHash = new TLVElement(false, false, 0x3);
            if (siblingHashImprint[1] != 0) {
                throw new Exception("Legacy ID second byte must be 0");
            }

            for (int i = siblingHashImprint[2] + 3; i < siblingLegacyHashAlgorithm.getHashLength() + 1; i++) {
                if (siblingHashImprint[i] != 0) {
                    throw new Exception("Bytes after the legacy ID string must be 0");
                }
            }

        } else {
            linkSiblingHash = new TLVElement(false, false, 0x2);
        }

        linkSiblingHash.setContent(siblingHashImprint);
        linkTlvElement.addChildElement(linkSiblingHash);
    }

    @Override
    protected DataHash getLinkInputHash(DataHash inputHash, HashAlgorithm algorithm, boolean isFirst) {
        if (isFirst) {
            DataHasher hasher = new DataHasher(algorithm);
            hasher.addData(inputHash.getImprint());
            inputHash = hasher.getHash();
        }

        return inputHash;
    }

}
