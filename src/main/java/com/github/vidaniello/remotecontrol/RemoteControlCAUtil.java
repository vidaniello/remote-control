package com.github.vidaniello.remotecontrol;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

import org.apache.commons.io.IOUtils;

public class RemoteControlCAUtil {

	
	public static byte[] getRemoteControlCA() throws IOException {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		InputStream is = RemoteControlCAUtil.class.getResourceAsStream("Remote control CA.cer");
		
		IOUtils.copy(is, baos);
		
		byte[] ret = baos.toByteArray();
		
		is.close();
		
		return ret;
	}
	
	public static byte[] getRemoteControlPK() throws IOException {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		InputStream is = RemoteControlCAUtil.class.getResourceAsStream("Remote control CA.key");
		
		IOUtils.copy(is, baos);
		
		byte[] ret = baos.toByteArray();
		
		is.close();
		
		return ret;
	}
}
