package com.github.vidaniello.remotecontrol;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.Calendar;
import java.util.Date;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jcajce.provider.asymmetric.x509.CertificateFactory;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.PKCS8Generator;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcaPKCS8Generator;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8EncryptorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.pkcs.jcajce.JcePKCSPBEInputDecryptorProviderBuilder;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

/**
 * //https://gist.github.com/vivekkr12/c74f7ee08593a8c606ed96f4b62a208a
 * 
 * @author Vincenzo D'Aniello (vidaniello@gmail.com) github.com/vidaniello
 *
 */
public class UtilSSL {

	public static final UtilSSL INSTANCE = new UtilSSL();

	public static String PK_EXTENSION = ".key";
	public static String CERIFICATE_EXTENSION = ".cer";
	
	private Logger log = LogManager.getLogger();
	
	private UtilSSL() {

	}

	private String basePath;

	public synchronized void setBasePath(String basePath) {
		File bPath = new File(basePath);
		bPath.mkdirs();
		log.info("Base path: "+bPath.getAbsolutePath());
		this.basePath = basePath;
	}

	public synchronized String getBasePath() {
		if (basePath == null)
			setBasePath(Constants.defaultBasePath);
		return basePath;
	}

	private KeyPairGenerator keyPairGenerator;

	public synchronized KeyPairGenerator getKeyPairGenerator()
			throws NoSuchAlgorithmException, NoSuchProviderException {

		if (keyPairGenerator == null) {
			keyPairGenerator = KeyPairGenerator.getInstance(Constants.defaultKeyAlgorithm,
					Constants.defaultSecurityProvider);
			keyPairGenerator.initialize(2048);
		}

		return keyPairGenerator;
	}

	public X509Certificate getNewRootCertificate(Date startDate, Date expireDate, PrivateKey privateKey, 
			PublicKey publicKey, X500Name x500name)
			throws OperatorCreationException, CertIOException, NoSuchAlgorithmException, CertificateException {

		BigInteger rootSerialNum = new BigInteger(Long.toString(new SecureRandom().nextLong()));

		X500Name rootCertIssuer = x500name;
		X500Name rootCertSubject = rootCertIssuer;

		ContentSigner rootCertContentSigner = new JcaContentSignerBuilder(Constants.defaultSignatureAlgorithm)
				.setProvider(Constants.defaultSecurityProvider).build(privateKey);

		X509v3CertificateBuilder rootCertBuilder = new JcaX509v3CertificateBuilder(rootCertIssuer, rootSerialNum,
				startDate, expireDate, rootCertSubject, publicKey);

		// Add Extensions
		// A BasicConstraint to mark root certificate as CA certificate
		JcaX509ExtensionUtils rootCertExtUtils = new JcaX509ExtensionUtils();
		rootCertBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
		rootCertBuilder.addExtension(Extension.subjectKeyIdentifier, false,
				rootCertExtUtils.createSubjectKeyIdentifier(publicKey));

		X509CertificateHolder rootCertHolder = rootCertBuilder.build(rootCertContentSigner);
		X509Certificate rootCert = new JcaX509CertificateConverter().setProvider(Constants.defaultSecurityProvider)
				.getCertificate(rootCertHolder);

		return rootCert;
	}

	public void writeToPEMFormat(Object object, OutputStream os) throws IOException {
		OutputStreamWriter osw = new OutputStreamWriter(os);
		try (JcaPEMWriter pw = new JcaPEMWriter(osw);) {
			pw.writeObject(object);
		}
	}
	
	public X509Certificate getCertificateFromPEMFormat(byte[] certificate) throws CertificateException, IOException {
		PEMParser pemParser = new PEMParser(new InputStreamReader(new ByteArrayInputStream(certificate)));
		JcaX509CertificateConverter x509Converter = new JcaX509CertificateConverter()
				.setProvider(Constants.defaultSecurityProvider);
		
		return x509Converter.getCertificate((X509CertificateHolder) pemParser.readObject());
	}

	public X509Certificate getCertificateFromPEMFormat(File certFile) throws CertificateException, IOException {
		try(FileInputStream fis = new FileInputStream(certFile);){
			return getCertificateFromPEMFormat(fis.readAllBytes());
		}
	}
	
	public void writePrivateKeyToPEMFormat(PrivateKey privateKey, String password, OutputStream os) throws IOException, OperatorCreationException {

		JceOpenSSLPKCS8EncryptorBuilder encryptorBuilder = new JceOpenSSLPKCS8EncryptorBuilder(
				PKCS8Generator.PBE_SHA1_3DES);
		encryptorBuilder.setRandom(new SecureRandom());
		encryptorBuilder.setPassword(password.toCharArray());
		OutputEncryptor oe = encryptorBuilder.build();
		JcaPKCS8Generator gen = new JcaPKCS8Generator(privateKey,oe);
		PemObject obj = gen.generate();

		OutputStreamWriter osw = new OutputStreamWriter(os);
		try (JcaPEMWriter pw = new JcaPEMWriter(osw);) {
			pw.writeObject(obj);
		}
	}
	
	public void writePrivateKeyToPEMFormat(PrivateKey privateKey, String password, File file) throws IOException, OperatorCreationException {
		try(FileOutputStream fos = new FileOutputStream(file);){
			writePrivateKeyToPEMFormat(privateKey, password, fos);
		}
	}
	
	public PrivateKey getPrivateKeyFromPEMFormat(byte[] encryptedPemKey, String password) throws IOException, PKCSException {
		PemReader pemReader = new PemReader(new InputStreamReader(new ByteArrayInputStream(encryptedPemKey)));
		PemObject pemObj = pemReader.readPemObject();
		byte [] content = pemObj.getContent();
		PKCS8EncryptedPrivateKeyInfo epki = new PKCS8EncryptedPrivateKeyInfo(content);
		
		JcePKCSPBEInputDecryptorProviderBuilder builder =
	            new JcePKCSPBEInputDecryptorProviderBuilder().setProvider(Constants.defaultSecurityProvider);
		
		InputDecryptorProvider idp = builder.build(password.toCharArray());
		
		PrivateKeyInfo pki = epki.decryptPrivateKeyInfo(idp);
		
		JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider(Constants.defaultSecurityProvider);
		
		return converter.getPrivateKey(pki);
	}
	
	public synchronized PrivateKey getPrivateKeyFromPEMFormat(File file, String password) throws FileNotFoundException, IOException, PKCSException {
		try(FileInputStream fis = new FileInputStream(file);){
			return getPrivateKeyFromPEMFormat( fis.readAllBytes(), password );
		}
		
	}
	
	public PublicKey getPublicKey(RSAPrivateCrtKey privateKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
		KeyFactory kf = KeyFactory.getInstance(Constants.defaultKeyAlgorithm);
		return  kf.generatePublic(
				new RSAPublicKeySpec(privateKey.getModulus(), privateKey.getPublicExponent())
				);
	}
	
	public X500Name getX500NameFromCertificate(X509Certificate certificate) throws CertificateEncodingException {
		return new JcaX509CertificateHolder(certificate).getSubject();
	}
	
	public String getSha3_256(String str) throws NoSuchAlgorithmException {
		MessageDigest digest = MessageDigest.getInstance("SHA3-256");
		byte[] hashbytes = digest.digest(
				str.getBytes(StandardCharsets.UTF_8)
				);
		return Hex.toHexString(hashbytes);
	}
	
	public String getCommonName(X500Name X500name) {
		return X500name.getRDNs(BCStyle.CN)[0].getFirst().getValue().toString();
	}
	
	private void makeCnPath(String commonName) {
		File cnPath = new File(getBasePath()+File.separator+commonName);
		cnPath.mkdirs();
	}
	
	private File getPkFile(String commonName) {
		return new File(getBasePath()+File.separator+commonName+File.separator+commonName+PK_EXTENSION);
	}
	
	private boolean exsistPkCommonNamefiles(String commonName) throws IOException {
		File cnPkFile = getPkFile(commonName);
		boolean ret = cnPkFile.exists();
		if(!ret) {
			makeCnPath(commonName);
			cnPkFile.createNewFile();
		}
		return ret;
	}
	
	private File getCertificateFile(String commonName) {
		return new File(getBasePath()+File.separator+commonName+File.separator+commonName+CERIFICATE_EXTENSION);
	}
	
	private boolean exsistCertificateCommonNamefiles(String commonName) throws IOException {
		File cnCerFile = getCertificateFile(commonName);
		boolean ret = cnCerFile.exists();
		if(!ret) {
			makeCnPath(commonName);
			cnCerFile.createNewFile();
		}
		return ret;
	}
	
	
	public synchronized PrivateKey getOrNewCommonNamePrivateKey(String commonName) throws NoSuchAlgorithmException, FileNotFoundException, IOException, PKCSException, NoSuchProviderException, OperatorCreationException {
		
		String passwd = getSha3_256(commonName);
		
		if(exsistPkCommonNamefiles(commonName)) 
			return getPrivateKeyFromPEMFormat(getPkFile(commonName), passwd);
		
		KeyPair rootKeyPair = getKeyPairGenerator().generateKeyPair();
		PrivateKey pk = rootKeyPair.getPrivate();
		writePrivateKeyToPEMFormat(pk, passwd, getPkFile(commonName));
		return pk;
	}
	
	public PrivateKey getOrNewCommonNamePrivateKey(X500Name rootX500name) throws NoSuchAlgorithmException, FileNotFoundException, IOException, PKCSException, NoSuchProviderException, OperatorCreationException {
		return getOrNewCommonNamePrivateKey(getCommonName(rootX500name));
	}
	

	
	
	public synchronized X509Certificate getOrNewOrRenewRootCertificate(X500Name x500name) throws IOException, CertificateException, NoSuchAlgorithmException, NoSuchProviderException, OperatorCreationException, PKCSException, InvalidKeySpecException {
		
		String commonName = getCommonName(x500name);
		
		if(!exsistCertificateCommonNamefiles(commonName)) 
			return renewRootCertificate(x500name);
		
		X509Certificate ret = getCertificateFromPEMFormat(getCertificateFile(commonName));	
		
		try {
			ret.checkValidity();
		}catch(CertificateExpiredException e) {
			return renewRootCertificate(x500name);
		}
		
		return ret;
	}
	
	private X509Certificate renewRootCertificate(X500Name x500name) throws NoSuchAlgorithmException, FileNotFoundException, NoSuchProviderException, OperatorCreationException, IOException, PKCSException, InvalidKeySpecException, CertificateException {
		
		String commonName = getCommonName(x500name);
		
		File certFile = getCertificateFile(commonName);
		
		PrivateKey rootPrivKey = getOrNewCommonNamePrivateKey(x500name);
		PublicKey rootPublicKey = getPublicKey((RSAPrivateCrtKey) rootPrivKey);
		
        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.DATE, -1);
        Date startDate = calendar.getTime();

        calendar.add(Calendar.YEAR, 1);
        Date endDate = calendar.getTime();
        
        X509Certificate ret = getNewRootCertificate(startDate, endDate, rootPrivKey, rootPublicKey, x500name);
		
        writeToPEMFormat(ret, new FileOutputStream(certFile));
        
		return ret;
	}
	
}
