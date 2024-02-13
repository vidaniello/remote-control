package com.github.vidaniello.remotecontrol;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketException;
import java.util.Date;

import io.vertx.core.Handler;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpServerOptions;
import io.vertx.core.net.SelfSignedCertificate;
import io.vertx.core.net.SocketAddress;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;

public class HttpServer {
	
	public static final int port1 = 34194;
	public static final int port2 = 34294;
	public static final int port3 = 34394;

	private int selectedPort;
	private Vertx vertx;
	
	public HttpServer() {
		
	}
	
	public void start() throws SocketException {
		
		selectedPort = port1;
		
		InetSocketAddress isa = new InetSocketAddress(selectedPort);
		
		//check porta in uso
		try(Socket sk1 = new Socket(isa.getAddress(),selectedPort);){
			
			selectedPort = port2;
			isa = new InetSocketAddress(selectedPort);
			
			try(Socket sk2 = new Socket(isa.getAddress(),selectedPort);){
				
				selectedPort = port3;
				isa = new InetSocketAddress(selectedPort);
				
				try(Socket sk3 = new Socket(isa.getAddress(),selectedPort);){
					throw new SocketException("All port: "+port1+" "+port2+" "+port3+" already in use!");
				}catch(IOException e){}
				
			}catch(IOException e){}
			
			
		}catch(IOException e){}
		
		System.out.println("Selected port: "+selectedPort);
		
		SocketAddress sa = SocketAddress.inetSocketAddress(new InetSocketAddress(selectedPort));
		
		vertx = Vertx.vertx();
		Router router = Router.router(vertx);
		
		router.get("/stop")				.blockingHandler(this::onStop);
		router.get()
		.blockingHandler(ctx->{
			if(ctx.request().path().equals("/"))
				ctx.response().putHeader("content-type", "text/plain").end("ok! "+ new Date());
			else
				ctx.fail(404);
		})
		.failureHandler(ctx->{
			ctx.response().setStatusCode(ctx.statusCode()).putHeader("content-type", "text/plain").end("Error code "+ctx.statusCode());
		});
		/*
		router.get("/status")				.blockingHandler(this::onStatus);
		router.get("/stop")					.blockingHandler(this::onStop);
		router.get("/stopnode")				.blockingHandler(this::onStopnode);
		router.get("/restart")				.blockingHandler(this::onRestart);
		router.get("/help")					.blockingHandler(this::onHelp);
		router.get("/switchclusterstate")	.blockingHandler(this::onSwitchclusterstate);
		router.get("/switchfrombaseline")	.blockingHandler(this::onSwitchFromBaselinee);
		router.get()
		.blockingHandler(ctx->{
			if(ctx.request().path().equals("/"))
				onStatus(ctx);
			else
				ctx.fail(404);
		})
		.failureHandler(ctx->{
			ctx.response().setStatusCode(ctx.statusCode()).putHeader("content-type", "text/plain").end("Error code "+ctx.statusCode());
		});
		*/
		
		SelfSignedCertificate certificate = SelfSignedCertificate.create();
		
		HttpServerOptions hso = new HttpServerOptions();
		hso.setSsl(true)
		   .setKeyCertOptions(certificate.keyCertOptions())
		   .setTrustOptions(certificate.trustOptions());
		
		/*return*/ vertx
				.createHttpServer(hso)
				.requestHandler(router)
				.listen(sa);
	}
	
	public void onStop(RoutingContext ctx) {
		if(ctx!=null) 
			ctx.response().putHeader("content-type", "text/plain").end("Stopping app...\n");
		vertx.close();
	}
	
	
}