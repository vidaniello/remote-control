package com.github.vidaniello.remotecontrol;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
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
	
	private String multicastAddress = "230.1.5.5";
	private int receiverPort = 34345;
	
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
