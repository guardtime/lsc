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

import com.guardtime.ksi.unisignature.KSISignature;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;

public class SignatureConverterApp {

    public static void main(String[] args) throws Exception {
        Options options = new Options();
        Option option;

        option = new Option("X", true, "Extending service (KSI Extender) URL.");
        option.setRequired(true);
        options.addOption(option);

        option = new Option(null, "ext-user", true, "Username for extending service.");
        option.setRequired(true);
        options.addOption(option);

        option = new Option(null, "ext-key", true, "HMAC key for extending service.");
        option.setRequired(true);
        options.addOption(option);

        option = new Option("P", true, "Publications file URL.");
        option.setRequired(true);
        options.addOption(option);

        option = new Option(null, "cnstr", true, "Publications file certificate qualification constraint.");
        option.setRequired(true);
        options.addOption(option);

        options.addOption("o", true, "Output file name for converted KSI signature.");
        options.addOption("h", "help", false, "Show help");

        CommandLineParser parser = new DefaultParser();
        CommandLine commandLine = null;
        try {
            commandLine = parser.parse(options, args);
        } catch (Exception ex) {
            for (String arg : args) {
                if (arg.matches("(-?)-help") || arg.matches("(-?)-h")){
                    printHelpAndExit(options, 0);
                }
            }
            System.err.println("Error occurred while parsing input arguments: " + ex.getMessage());
            printHelpAndExit(options, 1);
        }

        if (commandLine.hasOption("help")) {
            printHelpAndExit(options, 0);
        }

        SignatureConverter signatureConverter = new SignatureConverter(
                commandLine.getOptionValue("X"),
                commandLine.getOptionValue("ext-user"),
                commandLine.getOptionValue("ext-key"),
                commandLine.getOptionValue("P"),
                commandLine.getOptionValue("cnstr"));

        KSISignature signature;
        InputStream inputStream = System.in;
        try {
            // If input file is not defined, read from pipeline, else read from file.
            if (!(commandLine.getArgList().size() == 0)) {
                File inputFile = new File(commandLine.getArgList().get(0));
                if (inputFile.isFile()) {
                    inputStream = new FileInputStream(inputFile);
                } else {
                    throw new Exception("Input file does not exist or is not a file.");
                }
            }
            signature = signatureConverter.convert(inputStream);
        } finally {
            inputStream.close();
        }

        OutputStream outputStream = System.out;
        try {
            if (commandLine.hasOption("o")) {
                String outputFile = commandLine.getOptionValue("o");
                if (outputFile == null || outputFile.length() == 0) {
                    throw new Exception("Invalid output file name.");
                }
                if (new File(outputFile).exists()) {
                    throw new Exception("Output file already exists.");
                }
                outputStream = new FileOutputStream(outputFile);
            }
            signature.writeTo(outputStream);
        } finally {
            outputStream.close();
        }
    }

    private static void printHelpAndExit(Options options, int status) throws Exception {
        HelpFormatter helpFormatter = new HelpFormatter();
        helpFormatter.printHelp("java -jar signatureconverter-app-<version>.jar", options);
        System.exit(status);
    }


}
