# Legacy to KSI Signature Converter #

Guardtime Keyless Signature Infrastructure (KSI) is an industrial scale blockchain platform that cryptographically ensures data integrity and proves time of existence. Its keyless signatures, based on hash chains, link data to global calendar blockchain. The checkpoints of the blockchain, published in newspapers and electronic media, enable long term integrity of any digital asset without the need to trust any system. There are many applications for KSI, a classical example is signing of any type of logs - system logs, financial transactions, call records, etc. For more, see https://guardtime.com

Legacy to KSI Signature Converter is tool for converting legacy signatures to KSI format. The conversion functionality is available as a Java library to be integrated into another application as well as a command-line tool to be used directly from the shell and perform scripting. Access to the KSI extending service is required for the conversion.

## Installation ##
```
mvn clean install
```

The built JAR files are `signatureconverter-app/target/signatureconverter-app-<version>.jar` (command-line tool) and `signatureconverter-lib/target/signatureconverter-lib-<version>.jar` (library).

## Usage ##

### Use as a Command-line Tool ###

```
java [-Dlogback.configurationFile=logback-configuration-file] -jar signatureconverter-app-<version>.jar <options> [legacy-signature-file]  
```

Where `<options>` are:

```
  -X <arg>           Extending service (KSI Extender) URL.
  --ext-user <arg>   Username for extending service.
  --ext-key <arg>    HMAC key for extending service.
  -P <arg>           Publications file URL ('http://verify.guardtime.com/ksi-publications.bin' for Guardtime KSI service).
  --cnstr <arg>      Publications file certificate qualification constraint ('E=publications@guardtime.com' for Guardtime KSI service).
  --help             Show help.
   -o <arg>          Output file name for converted KSI signature.
 ```

When the legacy signature file is not specified, the standard input is used. When the output KSI signature file is not specified, it is written to standard output.

### Using as a Library ###

Add the `signatureconverter-lib-<version>.jar` to classpath of your project.

Code example:

```java
  SignatureConverter signatureConverter =
    new SignatureConverter("extender-url", "ext-user", "ext-key", "http://verify.guardtime.com/ksi-publications.bin", "E=publications@guardtime.com");

    try {
      InputStream inputStreamOfLegacySignature = new FileInputStream("legacy-sig.gtts");
      KSISignature signature = signatureConverter.convert(inputStreamOfLegacySignature);
      inputStreamOfLegacySignature.close();

      OutputStream outputStreamOfKsiSignature = new FileOutputStream("ksi-sig.ksig");
      signature.writeTo(outputStreamOfKsiSignature);
      outputStreamOfKsiSignature.close();
    } catch (Throwable t) {
      t.printStackTrace();
    }
```

## Dependencies ##

| Dependency                     | Version  | License type | Source                                                 | Notes |
|:-------------------------------|:---------|:-------------|:-------------------------------------------------------|:------|
| ksi-api                        | 4.10.117 | Apache 2.0   | https://github.com/guardtime/ksi-java-sdk              |       |
| ksi-service-client-simple-http | 4.10.117 | Apache 2.0   | https://github.com/guardtime/ksi-java-sdk              |       |
| slf4j-api                      | 1.7.14   | MIT          | https://www.slf4j.org/download.html                    |       |
| commons-cli                    | 1.3.1    | Apache 2.0   | http://svn.apache.org/viewvc/commons/proper/cli/trunk/ |       |

All dependencies are automatically included in the built JAR file.

## Compatibility ##

Java 1.5 or newer.

## License ##

See LICENSE file.
