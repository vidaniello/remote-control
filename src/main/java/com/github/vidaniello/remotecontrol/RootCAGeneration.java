package com.github.vidaniello.remotecontrol;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCSException;

public class RootCAGeneration {
	
	public static String rootCommonName = "Remote control CA";

	public static void main(String[] args) {
			
		try {
			UtilSSL.INSTANCE.getOrNewOrRenewRootCertificate(getRootName(), false);
		} catch (CertificateException | NoSuchAlgorithmException | NoSuchProviderException | OperatorCreationException
				| InvalidKeySpecException | IOException | PKCSException e) {
			e.printStackTrace();
		}

	}
	
	public static X500Name getRootName() {
		X500NameBuilder rootX500nameBuilder = new X500NameBuilder(BCStyle.INSTANCE);
	    rootX500nameBuilder.addRDN(BCStyle.CN, rootCommonName);
	    rootX500nameBuilder.addRDN(BCStyle.OU, "Remote control root CA emitter");
	   
	    return rootX500nameBuilder.build();
	}

}
