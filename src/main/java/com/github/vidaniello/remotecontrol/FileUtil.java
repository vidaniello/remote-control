package com.github.vidaniello.remotecontrol;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;

public class FileUtil {
	
	
	
	public static void writeToFile(byte [] content, String filename) throws IOException {
		File file = new File(filename);
		if(!file.exists())
			file.createNewFile();
		
		FileOutputStream fos = new FileOutputStream(file);
		fos.write(content);
		fos.close();
	}

	public static byte[] readFromFile(String filename) throws IOException {
		FileInputStream fis = new FileInputStream(filename);
		
		byte[] ret = fis.readAllBytes();
		fis.close();
		return ret;
	}
}
