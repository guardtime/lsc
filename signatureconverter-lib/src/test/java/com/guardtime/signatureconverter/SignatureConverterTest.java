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

import com.guardtime.signatureconverter.asn1.Asn1FormatException;

import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.io.InputStream;
import java.util.Properties;

public class SignatureConverterTest {

    private SignatureConverter converter;

    @BeforeMethod
    public void setUp() throws Exception {
        InputStream propertiesStream = Thread.currentThread().getContextClassLoader().getResourceAsStream("test.properties");
        Properties properties = new Properties();
        properties.load(propertiesStream);
        converter = new SignatureConverter(
                properties.getProperty("extender.url"), properties.getProperty("extender.login.user"),
                properties.getProperty("extender.login.key"), properties.getProperty("publicationsfile.url"),
                properties.getProperty("publicationsfile.constraint")
        );
        propertiesStream.close();
    }

    @Test
    public void testParse() throws Exception {
        InputStream inputStream = Thread.currentThread().getContextClassLoader().getResourceAsStream("TestData.txt.2015-01.gtts2");
        try {
            converter.convert(inputStream);
        } finally {
            inputStream.close();
        }
    }

    @Test (expectedExceptions = Asn1FormatException.class, expectedExceptionsMessageRegExp = "content info has invalid format")
    public void testParseNotLegacySignature_ThrowsAsn1FormatException() throws Exception {
        InputStream inputStream = Thread.currentThread().getContextClassLoader().getResourceAsStream("test.properties");
        try {
            converter.convert(inputStream);
        } finally {
            inputStream.close();
        }
    }

    @Test (expectedExceptions = IllegalArgumentException.class, expectedExceptionsMessageRegExp = "Invalid argument ksi: null")
    public void testSignatureConverterWithKsiNull_ThrowsInvalidArgumentException() throws Exception {
        SignatureConverter invalidConverter = new SignatureConverter(null);
    }
}