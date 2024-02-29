package com.github.vidaniello.remotecontrol;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;

public class FileUtil {
	
	
	public static void writeToFile(byte [] content, File file) throws IOException {
		if(!file.exists())
			file.createNewFile();
		
		FileOutputStream fos = new FileOutputStream(file);
		fos.write(content);
		fos.close();
	}
	
	public static void writeToFile(byte [] content, String filename) throws IOException {
		writeToFile(content, new File(filename));
	}

	
	
	public static byte[] readFromFile(File file) throws IOException {
		FileInputStream fis = new FileInputStream(file);
		
		byte[] ret = fis.readAllBytes();
		fis.close();
		return ret;
	}
	
	public static byte[] readFromFile(String filename) throws IOException {
		return readFromFile(new File(filename));
	}
}
