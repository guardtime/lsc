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

import com.guardtime.ksi.tlv.TLVElement;
import com.guardtime.ksi.unisignature.CalendarHashChain;

import java.util.LinkedList;
import java.util.List;
import java.util.ListIterator;

class CalendarHashChainBuilder extends HashChainBuilder {


    private long publicationTime;

    public TLVElement build() throws Exception {
        if (inputStream == null) {
            throw new Exception("Invalid calendar hash chain bytes inside legacy signature: No bytes found");
        }

        if (inputHash == null) {
            throw new Exception("Invalid input hash: null");
        }

        TLVElement calendarHashChain = new TLVElement(false, false, CalendarHashChain.ELEMENT_TYPE);
        calendarHashChain.addChildElement(TLVElement.create(0x1, publicationTime));
        calendarHashChain.addChildElement(TLVElement.create(0x5, inputHash));

        Link link = readLink(inputHash, 0, true);
        LinkedList<TLVElement> links = new LinkedList<TLVElement>();
        while (link != null) {
            links.add(link.element);
            calendarHashChain.addChildElement(link.element);
            link = link.nextLink;
        }

        calendarHashChain.addChildElement(TLVElement.create(0x2, calculateRegistrationTime(links, publicationTime)));
        return calendarHashChain;
    }

    private long calculateRegistrationTime(List<TLVElement> links, long publicationTime) throws Exception {
        long registrationTime = 0;

        // iterate over the chain in reverse
        ListIterator<TLVElement> li = links.listIterator(links.size());
        while (li.hasPrevious()) {
            if (publicationTime <= 0) {
                throw new Exception("Calendar hash chain shape is inconsistent with publication time");
            }

            TLVElement link = li.previous();
            if (link.getType() != 0x8) {
                publicationTime = highBit(publicationTime) - 1;
            } else {
                registrationTime = registrationTime + highBit(publicationTime);
                publicationTime = publicationTime - highBit(publicationTime);
            }
        }

        if (publicationTime != 0) {
            throw new Exception("Calendar hash chain shape inconsistent with publication time");
        }

        return registrationTime;
    }

    private long highBit(long r) {
        return 1L << (63 - Long.numberOfLeadingZeros(r));
    }

    public void setPublicationTime(long publicationTime) {
        this.publicationTime = publicationTime;
    }
}
