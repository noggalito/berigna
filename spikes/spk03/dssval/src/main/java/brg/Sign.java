// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 noggalito
package brg;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.service.tsp.OnlineTSPSource;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.spi.x509.revocation.crl.ExternalResourcesCRLSource;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.ExternalResourcesOCSPSource;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.signature.XAdESService;

import java.io.File;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.List;

/**
 * XAdES signed by DSS 6.2 with a key of the test PKI, for PR-INT-06 (DSS signatures verified
 * by berigna). DSS computes what to sign; the key signs it here, so no token module is needed.
 * Revocation data comes from files: the test PKI publishes no URLs.
 *
 * Usage: Sign <document> <ENVELOPED|ENVELOPING|DETACHED> <B|T|LT|LTA> <key.pk8> <leaf.pem,ca.pem,root.pem>
 *             <output> [tsa-url] [crl.der,ocsp.der,...]
 */
public class Sign {
    public static void main(String[] args) throws Exception {
        String[] chain = args[4].split(",");
        CertificateToken leaf = DSSUtils.loadCertificate(new File(chain[0]));
        CertificateToken ca = DSSUtils.loadCertificate(new File(chain[1]));
        CertificateToken root = DSSUtils.loadCertificate(new File(chain[2]));

        CommonTrustedCertificateSource trusted = new CommonTrustedCertificateSource();
        trusted.addCertificate(root);
        CommonCertificateVerifier verifier = new CommonCertificateVerifier();
        verifier.setTrustedCertSources(trusted);
        if (args.length > 7) {
            List<DSSDocument> crls = new ArrayList<>();
            List<DSSDocument> ocsps = new ArrayList<>();
            for (String path : args[7].split(",")) {
                // by the file name only: the folder name must not change the kind
                (new File(path).getName().contains("ocsp") ? ocsps : crls).add(new FileDocument(path));
            }
            verifier.setCrlSource(new ExternalResourcesCRLSource(crls.toArray(new DSSDocument[0])));
            verifier.setOcspSource(new ExternalResourcesOCSPSource(ocsps.toArray(new DSSDocument[0])));
        }
        XAdESService service = new XAdESService(verifier);
        if (args.length > 6 && !args[6].isEmpty()) {
            service.setTspSource(new OnlineTSPSource(args[6]));
        }

        XAdESSignatureParameters parameters = new XAdESSignatureParameters();
        parameters.setSignatureLevel(SignatureLevel.valueOf("XAdES_BASELINE_" + args[2]));
        parameters.setSignaturePackaging(SignaturePackaging.valueOf(args[1]));
        parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
        parameters.setSigningCertificate(leaf);
        parameters.setCertificateChain(java.util.Arrays.asList(leaf, ca));

        DSSDocument document = new FileDocument(args[0]);
        ToBeSigned toBeSigned = service.getDataToSign(document, parameters);
        PrivateKey key = KeyFactory.getInstance("RSA")
                .generatePrivate(new PKCS8EncodedKeySpec(Files.readAllBytes(new File(args[3]).toPath())));
        Signature signer = Signature.getInstance("SHA256withRSA");
        signer.initSign(key);
        signer.update(toBeSigned.getBytes());
        SignatureValue value = new SignatureValue(SignatureAlgorithm.RSA_SHA256, signer.sign());
        service.signDocument(document, parameters, value).save(args[5]);
    }
}
