package com.github.vidaniello.remotecontrol;

public class MainStarter {

	public static void main(String[] args) {
		
		HttpServer https = new HttpServer();
		try {
			https.start();
			Runtime.getRuntime().addShutdownHook(new Thread(()->{
				//Call server http stop
				https.onStop(null);
			}));
		} catch (Exception e) {
			System.err.print(e);
		}
	}
	
}
