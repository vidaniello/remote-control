package com.github.vidaniello.remotecontrol;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketException;

import io.vertx.core.Vertx;
import io.vertx.core.net.SocketAddress;
import io.vertx.ext.web.Router;

public class StartHttpServer {
	
	public static final int port = 34194;

	private Vertx vertx;
	
	public StartHttpServer() {
		
	}
	
	public void start() throws SocketException {
		InetSocketAddress isa = new InetSocketAddress(port);
		
		//check porta in uso
		try(Socket sk = new Socket(isa.getAddress(),port);){
			throw new SocketException("Port "+port+" already in use!");
		}catch(IOException e){}
		
		SocketAddress sa = SocketAddress.inetSocketAddress(new InetSocketAddress(port));
		
		vertx = Vertx.vertx();
		Router router = Router.router(vertx);
		
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
		
		/*return*/ vertx
				.createHttpServer()
				.requestHandler(router)
				.listen(sa);
	}
}
