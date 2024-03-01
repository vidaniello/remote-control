package com.github.vidaniello.remotecontrol;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateCrtKey;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.List;

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
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
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
	
	
	@BeforeAll
	public static void onStartTest() {
		UtilSSL.INSTANCE.setBasePath( UtilSSL.INSTANCE.getBasePath()+File.separatorChar+"testdir" );
	}
	//private String multicastAddress = "230.1.5.5";
	//private int receiverPort = 34345;
	
	@Test @Disabled
	public void testSslUtil() {
		try {
			
		    X500NameBuilder rootX500nameBuilder = new X500NameBuilder(BCStyle.INSTANCE);
		    rootX500nameBuilder.addRDN(BCStyle.CN, "root-cert-test");
		    rootX500nameBuilder.addRDN(BCStyle.OU, "OrganizationalUnit");
		    rootX500nameBuilder.addRDN(BCStyle.O, "Organization");
		    rootX500nameBuilder.addRDN(BCStyle.EmailAddress, "rootCAemail@email.com");
		    
		    X509Certificate rootCertificate = UtilSSL.INSTANCE.getOrNewOrRenewRootCertificate(rootX500nameBuilder.build(), false);
			
		    X500NameBuilder issuerX500nameBuilder = new X500NameBuilder(BCStyle.INSTANCE);
		    issuerX500nameBuilder.addRDN(BCStyle.CN, "issuer-cert-test");
		    issuerX500nameBuilder.addRDN(BCStyle.OU, "Issuer organization unit");
		    issuerX500nameBuilder.addRDN(BCStyle.O, "Issuer organization");
		    issuerX500nameBuilder.addRDN(BCStyle.EmailAddress, "issuerEmail@email.com");
		    
		    List<GeneralName> subjectAlternativeName = new ArrayList<>();
		    subjectAlternativeName.add(new GeneralName(GeneralName.dNSName, "issuerDomainName.local"));
		    subjectAlternativeName.add(new GeneralName(GeneralName.iPAddress, "192.168.0.1"));
		    
		    X500Name rootName = UtilSSL.INSTANCE.getX500NameFromCertificate(rootCertificate);
		    
		    X509Certificate issuerCertificate = UtilSSL.INSTANCE.getOrNewOrRenewCertificate(rootName, issuerX500nameBuilder.build(), subjectAlternativeName, false);
		    
		    issuerCertificate.verify( rootCertificate.getPublicKey(), Constants.defaultSecurityProvider);
		    
			int i = 0;
			
		}catch (Exception e) {
			log.error(e.getMessage(),e);
		}
	}
	
	@Test
	public void testCreateStoreAndReadKey2() {
		try {
			
			PrivateKey pkey = UtilSSL.INSTANCE.getOrNewCommonNamePrivateKey("TestRootCA");
			
			PrivateKey pkey2 = UtilSSL.INSTANCE.getOrNewCommonNamePrivateKey("TestRootCA");
			
			Assertions.assertTrue(pkey.equals(pkey2));
			
		}catch (Exception e) {
			log.error(e.getMessage(),e);
		}
	}
	
	@Test
	public void testCreateStoreAndReadKey() {
		try {
			
			KeyPair rootKeyPair = UtilSSL.INSTANCE.getKeyPairGenerator().generateKeyPair();
			PrivateKey pKey = rootKeyPair.getPrivate();
			PublicKey pubKey = rootKeyPair.getPublic();
			
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			UtilSSL.INSTANCE.writePrivateKeyToPEMFormat(pKey, "testpwd", baos);
			
			FileUtil.writeToFile(baos.toByteArray(), "test_rootPrivateKey.key");
			
			//Reading
			byte[] encryptedPemKey = FileUtil.readFromFile("test_rootPrivateKey.key");
				
			//Private key
			PrivateKey restoredPk = UtilSSL.INSTANCE.getPrivateKeyFromPEMFormat(encryptedPemKey, "testpwd");
			
			Assertions.assertTrue( pKey.equals(restoredPk) );
			
			//Public key
			PublicKey pubKeyRestored = UtilSSL.INSTANCE.getPublicKey((RSAPrivateCrtKey) restoredPk);
			
			Assertions.assertTrue( pubKey.equals(pubKeyRestored) );
			
		}catch (Exception e) {
			log.error(e.getMessage(),e);
		}
	}
	
	
	
	@Test
	public void testssl() {
		try {
						
					    
	        Calendar calendar = Calendar.getInstance();
	        calendar.add(Calendar.DATE, -1);
	        Date startDate = calendar.getTime();

	        calendar.add(Calendar.YEAR, 1);
	        Date endDate = calendar.getTime();
	        
	        
	        // First step is to create a root certificate
	        // First Generate a KeyPair,
	        // then a random serial number
	        // then generate a certificate using the KeyPair
	        KeyPair rootKeyPair = UtilSSL.INSTANCE.getKeyPairGenerator().generateKeyPair();
		   	
	        
		    X500NameBuilder nBuli = new X500NameBuilder(BCStyle.INSTANCE);
		    nBuli.addRDN(BCStyle.CN, "root-cert");
		    nBuli.addRDN(BCStyle.OU, "OrganizationalUnit");
		    nBuli.addRDN(BCStyle.O, "Organization");
		    nBuli.addRDN(BCStyle.EmailAddress, "email@email.com");
		    
		    X509Certificate rootCert = UtilSSL.INSTANCE.getNewRootCertificate(
		    		startDate, endDate, rootKeyPair.getPrivate(), rootKeyPair.getPublic(), nBuli.build());
	        
		    ByteArrayOutputStream baos = new ByteArrayOutputStream();
		    UtilSSL.INSTANCE.writeToPEMFormat(rootCert, baos);
	        //exportKeyPairToKeystoreFile(BC_PROVIDER, rootKeyPair, rootCert, "root-cert", "root-cert.pfx", "PKCS12", "pass");
		    FileUtil.writeToFile(baos.toByteArray(), "root-cert.cer");
	        
	        
	        
	        
	        // Generate a new KeyPair and sign it using the Root Cert Private Key
	        // by generating a CSR (Certificate Signing Request)
	        X500Name issuedCertSubject = new X500Name("CN=issued-cert");
	        BigInteger issuedCertSerialNum = new BigInteger(Long.toString(new SecureRandom().nextLong()));
	        KeyPair issuedCertKeyPair = UtilSSL.INSTANCE.getKeyPairGenerator().generateKeyPair();
	        
	        PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(issuedCertSubject, issuedCertKeyPair.getPublic());
	        JcaContentSignerBuilder csrBuilder = new JcaContentSignerBuilder(Constants.defaultSignatureAlgorithm).setProvider(Constants.defaultSecurityProvider);
	        
	        // Sign the new KeyPair with the root cert Private Key
	        ContentSigner csrContentSigner = csrBuilder.build(rootKeyPair.getPrivate());
	        PKCS10CertificationRequest csr = p10Builder.build(csrContentSigner);
	        
	        
	        // Use the Signed KeyPair and CSR to generate an issued Certificate
	        // Here serial number is randomly generated. In general, CAs use
	        // a sequence to generate Serial number and avoid collisions
	        X509v3CertificateBuilder issuedCertBuilder = 
	        		new X509v3CertificateBuilder(
	        				nBuli.build(), issuedCertSerialNum, startDate, endDate, 
	        				csr.getSubject(), csr.getSubjectPublicKeyInfo());

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
	        X509Certificate issuedCert  = new JcaX509CertificateConverter().setProvider(Constants.defaultSecurityProvider).getCertificate(issuedCertHolder);
	        
	        // Verify the issued cert signature against the root (issuer) cert
	        issuedCert.verify(rootCert.getPublicKey(), Constants.defaultSecurityProvider);
	        
	        
	        ByteArrayOutputStream baos2 = new ByteArrayOutputStream();
		    UtilSSL.INSTANCE.writeToPEMFormat(issuedCert, baos2);
		    FileUtil.writeToFile(baos2.toByteArray(), "issuer-cert.cer");
		    
	        //UtilSSL.INSTANCE.writeToPEMFormat(issuedCert, "issued-cert.cer");
	        //exportKeyPairToKeystoreFile(BC_PROVIDER, issuedCertKeyPair, issuedCert, "issued-cert", "issued-cert.pfx", "PKCS12", "pass");
	        
		} catch (Exception e) {
			log.error(e.getMessage(),e);
		}
	}
	
	
	
	/*
    void writeToFilePEMFormat(Object object, String fileName) throws Exception {
    	
        
        certificateOut.write("-----BEGIN CERTIFICATE-----".getBytes());
        certificateOut.write(Base64.encode(certificate.getEncoded()));
        certificateOut.write("-----END CERTIFICATE-----".getBytes());
        certificateOut.close();
        
    }
	 */
    
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
