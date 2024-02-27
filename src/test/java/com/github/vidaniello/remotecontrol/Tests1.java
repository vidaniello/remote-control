package com.github.vidaniello.remotecontrol;

import java.io.File;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.Writer;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.encoders.Base64;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

public class Tests1 {
	
	static {
		// Log4j from 2.17.>, use this if the config file is not under ssl socket
		//System.setProperty("log4j2.Configuration.allowedProtocols", "http");

		// URL file di configurazione Log4j2
		System.setProperty("log4j.configurationFile",
				"https://gist.github.com/vidaniello/c20e29cdffb407ec5d3c773fb92786b9/raw/92c8e809f51133ef56e4867a6cabb0744ee6b9b6/log4j2.xml");

		// Tips per java.util.logging
		System.setProperty("java.util.logging.manager", "org.apache.logging.log4j.jul.LogManager");

		// private org.apache.logging.log4j.Logger log =
		// org.apache.logging.log4j.LogManager.getLogger();
	}
	
	
	private Logger log = LogManager.getLogger();
	
	//private String multicastAddress = "230.1.5.5";
	//private int receiverPort = 34345;
	
	@Test
	public void testUtilSSL() {
		try {
			
			
			
			
		}catch (Exception e) {
			log.error(e.getMessage(),e);
		}
	}
	@Test
	public void testssl() {
		try {
			
			//https://gist.github.com/vivekkr12/c74f7ee08593a8c606ed96f4b62a208a
			
			String BC_PROVIDER = "BC";
			String keyAlg = "RSA";
			String SIGNATURE_ALGORITHM = "SHA256withRSA";
			
			Security.addProvider(new BouncyCastleProvider());
			
			KeyPairGenerator kpg = KeyPairGenerator.getInstance(keyAlg, BC_PROVIDER);
			kpg.initialize(2048);
		    
		    
	        Calendar calendar = Calendar.getInstance();
	        calendar.add(Calendar.DATE, -1);
	        Date startDate = calendar.getTime();

	        calendar.add(Calendar.YEAR, 1);
	        Date endDate = calendar.getTime();
	        
	        
	        // First step is to create a root certificate
	        // First Generate a KeyPair,
	        // then a random serial number
	        // then generate a certificate using the KeyPair
	        KeyPair rootKeyPair = kpg.generateKeyPair();
		    PublicKey rootPubKey = rootKeyPair.getPublic();
		    PrivateKey rootPrivKey = rootKeyPair.getPrivate();
		    BigInteger rootSerialNum = new BigInteger(Long.toString(new SecureRandom().nextLong()));
		    
		    
		    X500NameBuilder nBuli = new X500NameBuilder(BCStyle.INSTANCE);
		    nBuli.addRDN(BCStyle.CN, "root-cert");
		    nBuli.addRDN(BCStyle.OU, "OrganizationalUnit");
		    nBuli.addRDN(BCStyle.O, "Organization");
		    nBuli.addRDN(BCStyle.EmailAddress, "email@email.com");
		    X500Name rootCertIssuer = nBuli.build();
		    X500Name rootCertSubject = rootCertIssuer;
		    
		    ContentSigner rootCertContentSigner = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM).setProvider(BC_PROVIDER).build(rootPrivKey);
		    X509v3CertificateBuilder rootCertBuilder = new JcaX509v3CertificateBuilder(rootCertIssuer, rootSerialNum, startDate, endDate, rootCertSubject, rootPubKey);
		    
	        // Add Extensions
	        // A BasicConstraint to mark root certificate as CA certificate
	        JcaX509ExtensionUtils rootCertExtUtils = new JcaX509ExtensionUtils();
	        rootCertBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
	        rootCertBuilder.addExtension(Extension.subjectKeyIdentifier, false, rootCertExtUtils.createSubjectKeyIdentifier(rootPubKey));
		    
	        X509CertificateHolder rootCertHolder = rootCertBuilder.build(rootCertContentSigner);
	        X509Certificate rootCert = new JcaX509CertificateConverter().setProvider(BC_PROVIDER).getCertificate(rootCertHolder);
	        
	        writeToFilePEMFormat(rootCert, "root-cert.cer");
	        //exportKeyPairToKeystoreFile(BC_PROVIDER, rootKeyPair, rootCert, "root-cert", "root-cert.pfx", "PKCS12", "pass");
	        
	        // Generate a new KeyPair and sign it using the Root Cert Private Key
	        // by generating a CSR (Certificate Signing Request)
	        X500Name issuedCertSubject = new X500Name("CN=issued-cert");
	        BigInteger issuedCertSerialNum = new BigInteger(Long.toString(new SecureRandom().nextLong()));
	        KeyPair issuedCertKeyPair = kpg.generateKeyPair();
	        
	        PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(issuedCertSubject, issuedCertKeyPair.getPublic());
	        JcaContentSignerBuilder csrBuilder = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM).setProvider(BC_PROVIDER);
	        
	        // Sign the new KeyPair with the root cert Private Key
	        ContentSigner csrContentSigner = csrBuilder.build(rootPrivKey);
	        PKCS10CertificationRequest csr = p10Builder.build(csrContentSigner);
	        
	        
	        // Use the Signed KeyPair and CSR to generate an issued Certificate
	        // Here serial number is randomly generated. In general, CAs use
	        // a sequence to generate Serial number and avoid collisions
	        X509v3CertificateBuilder issuedCertBuilder = new X509v3CertificateBuilder(rootCertIssuer, issuedCertSerialNum, startDate, endDate, csr.getSubject(), csr.getSubjectPublicKeyInfo());

	        JcaX509ExtensionUtils issuedCertExtUtils = new JcaX509ExtensionUtils();
	        
	        // Add Extensions
	        // Use BasicConstraints to say that this Cert is not a CA
	        issuedCertBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
	        
	        // Add Issuer cert identifier as Extension
	        issuedCertBuilder.addExtension(Extension.authorityKeyIdentifier, false, issuedCertExtUtils.createAuthorityKeyIdentifier(rootCert));
	        issuedCertBuilder.addExtension(Extension.subjectKeyIdentifier, false, issuedCertExtUtils.createSubjectKeyIdentifier(csr.getSubjectPublicKeyInfo()));
	        
	        // Add intended key usage extension if needed
	        issuedCertBuilder.addExtension(Extension.keyUsage, false, new KeyUsage(KeyUsage.keyEncipherment));
	        
	        // Add DNS name is cert is to used for SSL
	        issuedCertBuilder.addExtension(Extension.subjectAlternativeName, false, new DERSequence(new ASN1Encodable[] {
	                new GeneralName(GeneralName.dNSName, "mydomain.local"),
	                new GeneralName(GeneralName.iPAddress, "127.0.0.1")
	        }));
	        
	        X509CertificateHolder issuedCertHolder = issuedCertBuilder.build(csrContentSigner);
	        X509Certificate issuedCert  = new JcaX509CertificateConverter().setProvider(BC_PROVIDER).getCertificate(issuedCertHolder);
	        
	        // Verify the issued cert signature against the root (issuer) cert
	        issuedCert.verify(rootCert.getPublicKey(), BC_PROVIDER);
	        
	        writeToFilePEMFormat(issuedCert, "issued-cert.cer");
	        //exportKeyPairToKeystoreFile(BC_PROVIDER, issuedCertKeyPair, issuedCert, "issued-cert", "issued-cert.pfx", "PKCS12", "pass");
	        
		} catch (Exception e) {
			log.error(e.getMessage(),e);
		}
	}
	
    void writeToFilePEMFormat(Object object, String fileName) throws Exception {
    	
        FileWriter certificateOut = new FileWriter(fileName);
        
        
        try(JcaPEMWriter pw = new JcaPEMWriter(certificateOut);){
        	pw.writeObject(object);
        }
        /*
        certificateOut.write("-----BEGIN CERTIFICATE-----".getBytes());
        certificateOut.write(Base64.encode(certificate.getEncoded()));
        certificateOut.write("-----END CERTIFICATE-----".getBytes());
        certificateOut.close();
        */
    }
    
    /*
    void exportKeyPairToKeystoreFile(String providerName, KeyPair keyPair, Certificate certificate, String alias, String fileName, String storeType, String storePass) throws Exception {
        KeyStore sslKeyStore = KeyStore.getInstance(storeType, providerName);
        sslKeyStore.load(null, null);
        sslKeyStore.setKeyEntry(alias, keyPair.getPrivate(),null, new Certificate[]{certificate});
        FileOutputStream keyStoreOs = new FileOutputStream(fileName);
        sslKeyStore.store(keyStoreOs, storePass.toCharArray());
    }
    */
	
	/*
	@Test @Disabled
	public void testReceiver() {
		ExecutorService service = Executors.newSingleThreadExecutor();
		try {
			
			MulticastReceiver mr = new MulticastReceiver(receiverPort, multicastAddress);
			
			service.submit(mr);
			
			Thread.sleep(480000);
			
			mr.close();
			
		} catch (Exception e) {
			log.error(e.getMessage(),e);
		} finally {
			service.shutdown();
		}
	}

	
	
	@Test @Disabled
	public void testPublisher() {
		
		try {
			
			MulticastPublisher mp = new MulticastPublisher(receiverPort, multicastAddress);
			
			mp.pubblish("Test send!");
			
		} catch (Exception e) {
			log.error(e.getMessage(),e);
		} finally {
			
		}
	}
*/
}
