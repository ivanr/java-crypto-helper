import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509ExtensionUtils;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;

public class SelfSignedCertificate {

    public static void main(String[] args) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair keyPair = generator.generateKeyPair();
        PublicKey certPublicKey = keyPair.getPublic();
        PrivateKey issuerPrivateKey = keyPair.getPrivate();

        X509Certificate c = generate(
                issuerPrivateKey,
                certPublicKey,
                "SHA256withRSA",
                new X500Name("CN=TEST"),
                new Date(1_598_918_400_000L),
                new Date(1_598_918_400_000L + 398 * 86_400_000L));
        //System.out.println(c);

        FileOutputStream f = new FileOutputStream("test.crt");
        f.write(c.getEncoded());
        f.close();
    }

    public static X509Certificate generate(final PrivateKey issuerPrivateKey,
                                           final PublicKey certPublicKey,
                                           final String hashAlgorithm,
                                           final X500Name x500Name,
                                           final int days)
            throws OperatorCreationException, CertificateException, IOException
    {
        final Instant now = Instant.now();
        final Date notBefore = Date.from(now);
        final Date notAfter = Date.from(now.plus(Duration.ofDays(days)));
        return generate(issuerPrivateKey, certPublicKey, hashAlgorithm, x500Name, notBefore, notAfter);
    }

    public static X509Certificate generate(final PrivateKey issuerPrivateKey,
                                           final PublicKey certPublicKey,
                                           final String hashAlgorithm,
                                           final X500Name x500Name,
                                           final Date notBefore,
                                           final Date notAfter)
            throws OperatorCreationException, CertificateException, IOException
    {
        final ContentSigner contentSigner = new JcaContentSignerBuilder(hashAlgorithm).build(issuerPrivateKey);

        final Instant now = Instant.now();

        final X509v3CertificateBuilder certificateBuilder =
                new JcaX509v3CertificateBuilder(x500Name,
                        BigInteger.valueOf(now.toEpochMilli()),
                        notBefore,
                        notAfter,
                        x500Name,
                        certPublicKey)
                        .addExtension(createAuthorityKeyIdentifierExtension(certPublicKey))
                        .addExtension(createSubjectKeyIdentifierExtension(certPublicKey))
                        .addExtension(Extension.basicConstraints, true, new BasicConstraints(true))
                //.addExtension(createCtPoisonExtension())
                ;

        return new JcaX509CertificateConverter()
                .setProvider(new BouncyCastleProvider())
                .getCertificate(certificateBuilder.build(contentSigner));
    }

    private static Extension createAuthorityKeyIdentifierExtension(final Key key) throws OperatorCreationException, IOException {
        return Extension.create(
                Extension.authorityKeyIdentifier,
                false,
                createAuthorityKeyId(key));
    }

    private static AuthorityKeyIdentifier createAuthorityKeyId(final Key key) throws OperatorCreationException {
        return new X509ExtensionUtils(new BcDigestCalculatorProvider().get(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1)))
                .createAuthorityKeyIdentifier(SubjectPublicKeyInfo.getInstance(key.getEncoded()));
    }

    private static Extension createCtPoisonExtension() throws IOException {
        return Extension.create(
                new ASN1ObjectIdentifier("1.3.6.1.4.1.11129.2.4.3"),
                true,
                //ASN1Primitive.fromByteArray(new byte[] { 0x05, 0x00})
                DERNull.INSTANCE
        );
    }

    private static Extension createSubjectKeyIdentifierExtension(final Key key) throws OperatorCreationException, IOException {
        return Extension.create(
                Extension.subjectKeyIdentifier,
                false,
                createSubjectKeyId(key));
    }

    private static SubjectKeyIdentifier createSubjectKeyId(final Key key) throws OperatorCreationException {
        return new X509ExtensionUtils(new BcDigestCalculatorProvider().get(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1)))
                .createSubjectKeyIdentifier(SubjectPublicKeyInfo.getInstance(key.getEncoded()));
    }
}
