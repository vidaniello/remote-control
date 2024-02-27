package com.github.vidaniello.remotecontrol;

import java.io.File;

public class Constants {
	
	public static String appName = "remote-control";
	
	public static String defaultBasePath = System.getProperty("user.home")+File.separatorChar+appName;
	
	public static String defaultSecurityProvider = "BC";
	
	public static String defaultKeyAlgorithm = "RSA";
	
	public static String defaultSignatureAlgorithm = "SHA256withRSA";

}
