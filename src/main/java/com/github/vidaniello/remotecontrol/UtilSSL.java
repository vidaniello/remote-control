package com.github.vidaniello.remotecontrol;

import java.io.File;

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
	
	

}
