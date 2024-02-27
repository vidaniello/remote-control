package com.github.vidaniello.remotecontrol;

import java.io.File;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * //https://gist.github.com/vivekkr12/c74f7ee08593a8c606ed96f4b62a208a
 * @author Vincenzo D'Aniello (vidaniello@gmail.com) github.com/vidaniello
 *
 */
public class UtilSSL {
	
	
	public static final UtilSSL INSTANCE = new UtilSSL();
	
	
	private UtilSSL() {
		
	}
	
	private String basePath;
	public synchronized void setBasePath(String basePath) {
		File bPath = new File(basePath);
		bPath.mkdirs();
		this.basePath = basePath;
	}
	
	public synchronized String getBasePath() {
		if(basePath==null)
			setBasePath(Constants.defaultBasePath);
		return basePath;
	}
	
	private KeyPairGenerator keyPairGenerator;
	public synchronized KeyPairGenerator getKeyPairGenerator() throws NoSuchAlgorithmException, NoSuchProviderException {
		
		if(keyPairGenerator==null) {
			keyPairGenerator = KeyPairGenerator.getInstance(Constants.defaultKeyAlgorithm, Constants.defaultSecurityProvider);
			keyPairGenerator.initialize(2048);
		}
		
		return keyPairGenerator;
	}
	
	public X509Certificate getNewRootCertificate(
			Date startDate, 
			Date expireDate, 
			KeyPair rootKeyPair, 
			X500NameBuilder nameBuilder
			) throws OperatorCreationException, CertIOException, NoSuchAlgorithmException, CertificateException {
		
		BigInteger rootSerialNum = new BigInteger(Long.toString(new SecureRandom().nextLong()));
		
		X500Name rootCertIssuer = nameBuilder.build();
	    X500Name rootCertSubject = rootCertIssuer;
	    
	    ContentSigner rootCertContentSigner = new JcaContentSignerBuilder(Constants.defaultSignatureAlgorithm)
	    		.setProvider(Constants.defaultSecurityProvider)
	    		.build(rootKeyPair.getPrivate());
	    
	    X509v3CertificateBuilder rootCertBuilder = 
	    		new JcaX509v3CertificateBuilder(
	    				rootCertIssuer, rootSerialNum, startDate, expireDate, 
	    				rootCertSubject, rootKeyPair.getPublic());
	    
        // Add Extensions
        // A BasicConstraint to mark root certificate as CA certificate
        JcaX509ExtensionUtils rootCertExtUtils = new JcaX509ExtensionUtils();
        rootCertBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        rootCertBuilder.addExtension(Extension.subjectKeyIdentifier, false, rootCertExtUtils.createSubjectKeyIdentifier(rootKeyPair.getPublic()));
	    
        X509CertificateHolder rootCertHolder = rootCertBuilder.build(rootCertContentSigner);
        X509Certificate rootCert = new JcaX509CertificateConverter()
        		.setProvider(Constants.defaultSecurityProvider)
        		.getCertificate(rootCertHolder);
		
		return rootCert;
	}

}
