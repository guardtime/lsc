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

import com.guardtime.ksi.KSI;
import com.guardtime.ksi.KSIBuilder;
import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.hashing.DataHasher;
import com.guardtime.ksi.hashing.HashAlgorithm;
import com.guardtime.ksi.publication.PublicationsFile;
import com.guardtime.ksi.service.client.KSIServiceCredentials;
import com.guardtime.ksi.service.client.http.HttpClientSettings;
import com.guardtime.ksi.service.http.simple.SimpleHttpClient;
import com.guardtime.ksi.tlv.TLVElement;
import com.guardtime.ksi.trust.X509CertificateSubjectRdnSelector;
import com.guardtime.ksi.unisignature.KSISignature;
import com.guardtime.ksi.unisignature.RFC3161Record;
import com.guardtime.ksi.unisignature.inmemory.InMemoryKsiSignatureFactory;
import com.guardtime.signatureconverter.asn1.ContentInfo;
import com.guardtime.signatureconverter.asn1.SignerInfo;
import com.guardtime.signatureconverter.asn1.TimeSignature;
import com.guardtime.signatureconverter.asn1.TstInfo;
import com.guardtime.signatureconverter.tsp.LegacyHashAlgorithm;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.util.LinkedList;
import java.util.List;

public class SignatureConverter {

    private final String DUMMY_URL = "http://.";
    private KSI ksi;

    public SignatureConverter(String extendingUrl, String loginId, String loginKey, String publicationsFileUrl, String pubFileCertVerificationConstraint) throws KSIException {
        SimpleHttpClient httpClient = new SimpleHttpClient(new HttpClientSettings(DUMMY_URL, extendingUrl, publicationsFileUrl, new KSIServiceCredentials(loginId, loginKey)));

        this.ksi = new KSIBuilder()
                .setKsiProtocolSignerClient(httpClient)
                .setKsiProtocolExtenderClient(httpClient)
                .setKsiProtocolPublicationsFileClient(httpClient)
                .setPublicationsFileTrustedCertSelector(new X509CertificateSubjectRdnSelector(pubFileCertVerificationConstraint))
                .build();
    }

    public SignatureConverter(KSI ksi) {
        if (ksi == null) {
            throw new IllegalArgumentException("Invalid argument ksi: null");
        }

        this.ksi = ksi;
    }

    public KSISignature convert(InputStream inputStream) throws Exception {
        ContentInfo contentInfo = ContentInfo.getInstance(inputStream);
        SignerInfo signerInfo = contentInfo.getContent().getSignerInfo();
        TstInfo tstInfo = contentInfo.getContent().getEContent();
        /*
            Get input hash
         */
        byte[] signedAttrs = signerInfo.getEncodedSignedAttrs();
        if (signedAttrs == null) {
            throw new IllegalArgumentException("Invalid signed attrs: null");
        }
        TimeSignature legacySignature = signerInfo.getSignature();
        long publicationTime = legacySignature.getPublishedData().getPublicationId().longValue();
        HashAlgorithm digestAlgorithm = HashAlgorithm.getById(LegacyHashAlgorithm.getByOid(signerInfo.getDigestAlgorithm()).getGtid());
        DataHash inputHash = new DataHasher(digestAlgorithm).addData(signedAttrs).getHash();

        AggregationHashChainBuilder aggregationHashChainBuilder = new AggregationHashChainBuilder();
        aggregationHashChainBuilder.setInputStream(new ByteArrayInputStream(legacySignature.getLocation()));
        aggregationHashChainBuilder.setInputHash(inputHash);
        LinkedList<TLVElement> aggregationHashChainTlvElementList = aggregationHashChainBuilder.build();

        CalendarHashChainBuilder calendarHashChainBuilder = new CalendarHashChainBuilder();
        calendarHashChainBuilder.setInputStream(new ByteArrayInputStream(legacySignature.getHistory()));
        calendarHashChainBuilder.setInputHash(aggregationHashChainBuilder.getOutputHash());
        calendarHashChainBuilder.setPublicationTime(publicationTime);
        TLVElement calendarHashChainTlvElement = calendarHashChainBuilder.build();

        for (TLVElement chain : aggregationHashChainTlvElementList) {
            chain.addChildElement(TLVElement.create(0x2, calendarHashChainTlvElement.getFirstChildElement(0x2).getDecodedLong()));
        }

        /*
            RFC3161Record
         */
        DataHash documentHash = new DataHash(HashAlgorithm.getById(LegacyHashAlgorithm.getByOid(tstInfo.getMessageImprint().getHashAlgorithm()).getGtid()), tstInfo.getMessageImprint().getHashedMessage());
        TLVElement rfc3161RecordTlvElement = new TLVElement(false, false, RFC3161Record.ELEMENT_TYPE);
        rfc3161RecordTlvElement.addChildElement(TLVElement.create(0x2, calendarHashChainTlvElement.getFirstChildElement(0x2).getDecodedLong()));
        List<TLVElement> firstAggregationChainIndexes = aggregationHashChainTlvElementList.getFirst().getChildElements(0x3);
        for (TLVElement chainIndex : firstAggregationChainIndexes) {
            rfc3161RecordTlvElement.addChildElement(chainIndex);
        }
        rfc3161RecordTlvElement.addChildElement(TLVElement.create(0x5, documentHash));
        /*
            TstInfo
         */
        TLVElement tstInfoPrefixTlvElement = new TLVElement(false, false, 0x10);
        tstInfoPrefixTlvElement.setContent(tstInfo.getBytesBeforeHashedMessage());
        rfc3161RecordTlvElement.addChildElement(tstInfoPrefixTlvElement);

        TLVElement tstInfoSuffixTlvElement = new TLVElement(false, false, 0x11);
        tstInfoSuffixTlvElement.setContent(tstInfo.getBytesAfterHashedMessage());
        rfc3161RecordTlvElement.addChildElement(tstInfoSuffixTlvElement);

        rfc3161RecordTlvElement.addChildElement(TLVElement.create(0x12, documentHash.getAlgorithm().getId()));

        /*
            Signed attributes
         */
        TLVElement signedAttrsPrefixTlvElement = new TLVElement(false, false, 0x13);
        signedAttrsPrefixTlvElement.setContent(signerInfo.getSignedAttrsBytesBeforeMessageImprint());
        rfc3161RecordTlvElement.addChildElement(signedAttrsPrefixTlvElement);

        TLVElement signedAttrsSuffixTlvElement = new TLVElement(false, false, 0x14);
        signedAttrsSuffixTlvElement.setContent(signerInfo.getSignedAttrsBytesAfterMessageImprint());
        rfc3161RecordTlvElement.addChildElement(signedAttrsSuffixTlvElement);
        rfc3161RecordTlvElement.addChildElement(TLVElement.create(0x15, digestAlgorithm.getId()));

        TLVElement signatureTlvElement = new TLVElement(false, false, 0x800);
        for (TLVElement aggregationHashChain : aggregationHashChainTlvElementList) {
            signatureTlvElement.addChildElement(aggregationHashChain);
        }
        signatureTlvElement.addChildElement(calendarHashChainTlvElement);
        signatureTlvElement.addChildElement(rfc3161RecordTlvElement);

        KSISignature ksiSignature = new InMemoryKsiSignatureFactory().createSignature(signatureTlvElement, documentHash);

        PublicationsFile publicationsFile = this.ksi.getPublicationsFile();
        ksiSignature = this.ksi.extend(ksiSignature, publicationsFile.getPublicationRecord(ksiSignature.getPublicationTime()));
        return ksiSignature;
    }

}
