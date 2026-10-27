// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Calú
package brg;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.service.crl.OnlineCRLSource;
import eu.europa.esig.dss.service.ocsp.OnlineOCSPSource;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

/**
 * SPK-03 test validator.
 * Usage: Validate <signed-file> <trust-anchor.pem>[,more.pem] <report-dir> [detached-original]
 */
public class Validate {
    public static void main(String[] args) throws Exception {
        CommonTrustedCertificateSource trusted = new CommonTrustedCertificateSource();
        for (String pem : args[1].split(",")) {
            trusted.addCertificate(DSSUtils.loadCertificate(new File(pem)));
        }
        CommonCertificateVerifier verifier = new CommonCertificateVerifier();
        verifier.setTrustedCertSources(trusted);
        verifier.setCrlSource(new OnlineCRLSource());
        verifier.setOcspSource(new OnlineOCSPSource());
        verifier.setAIASource(new eu.europa.esig.dss.spi.x509.aia.DefaultAIASource());

        SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(new FileDocument(args[0]));
        validator.setCertificateVerifier(verifier);
        if (args.length > 3) {
            validator.setDetachedContents(java.util.Collections.<DSSDocument>singletonList(new FileDocument(args[3])));
        }
        Reports reports = validator.validateDocument();
        SimpleReport sr = reports.getSimpleReport();
        for (String id : sr.getSignatureIdList()) {
            System.out.printf("%s | formato=%s | indicacion=%s | sub=%s%n",
                    id, sr.getSignatureFormat(id), sr.getIndication(id), sr.getSubIndication(id));
            for (eu.europa.esig.dss.jaxb.object.Message e : sr.getAdESValidationErrors(id)) System.out.println("   ERROR: " + e.getValue());
            for (eu.europa.esig.dss.jaxb.object.Message w : sr.getAdESValidationWarnings(id)) System.out.println("   AVISO: " + w.getValue());
        }
        if (sr.getSignatureIdList().isEmpty()) System.out.println("Sin firmas detectadas");
        Path out = java.nio.file.Paths.get(args[2]);
        Files.createDirectories(out);
        Files.write(out.resolve("simple-report.xml"), reports.getXmlSimpleReport().getBytes("UTF-8"));
        Files.write(out.resolve("detailed-report.xml"), reports.getXmlDetailedReport().getBytes("UTF-8"));
    }
}
