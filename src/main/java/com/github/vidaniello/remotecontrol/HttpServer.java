package com.github.vidaniello.remotecontrol;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.GeneralName;

import io.netty.handler.codec.http.QueryStringDecoder;
import io.vertx.core.Vertx;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.http.HttpServerOptions;
import io.vertx.core.http.HttpServerRequest;
import io.vertx.core.http.HttpServerResponse;
import io.vertx.core.json.JsonObject;
import io.vertx.core.net.NetClientOptions;
import io.vertx.core.net.PemKeyCertOptions;
import io.vertx.core.net.PemTrustOptions;
import io.vertx.core.net.SelfSignedCertificate;
import io.vertx.core.net.SocketAddress;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;

public class HttpServer {
	
	/*
	public static final int httpPort1 = 34193;
	public static final int httpPort2 = 34293;
	public static final int httpPort3 = 34393;
	*/
	public static final int httpsPort1 = 34194;
	public static final int httpsPort2 = 34294;
	public static final int httpsPort3 = 34394;

	//private int selectedHttpPort;
	private int selectedHttpsPort;
	//private Vertx httpVertx;
	private Vertx httpsVertx;
	
	public HttpServer() {
		
	}
	
	public void start() throws Exception {
		
		/*
		selectedHttpPort = httpPort1;
		
		InetSocketAddress httpIsa = new InetSocketAddress(selectedHttpPort);
		
		//check porta http in uso
		try(Socket sk1 = new Socket(httpIsa.getAddress(),selectedHttpPort);){
			
			selectedHttpPort = httpPort2;
			httpIsa = new InetSocketAddress(selectedHttpPort);
			
			try(Socket sk2 = new Socket(httpIsa.getAddress(),selectedHttpPort);){
				
				selectedHttpPort = httpPort3;
				httpIsa = new InetSocketAddress(selectedHttpPort);
				
				try(Socket sk3 = new Socket(httpIsa.getAddress(),selectedHttpPort);){
					throw new Exception("All port: "+httpPort1+" "+httpPort2+" "+httpPort3+" already in use!");
				}catch(IOException e){}
			}catch(IOException e){}
		}catch(IOException e){}
		
		
		System.out.println("Selected http port: "+selectedHttpPort);
		*/
		
		selectedHttpsPort = httpsPort1;
		
		InetSocketAddress isa = new InetSocketAddress(selectedHttpsPort);
		
		//check porta in uso
		try(Socket sk1 = new Socket(isa.getAddress(),selectedHttpsPort);){
			
			selectedHttpsPort = httpsPort2;
			isa = new InetSocketAddress(selectedHttpsPort);
			
			try(Socket sk2 = new Socket(isa.getAddress(),selectedHttpsPort);){
				
				selectedHttpsPort = httpsPort3;
				isa = new InetSocketAddress(selectedHttpsPort);
				
				try(Socket sk3 = new Socket(isa.getAddress(),selectedHttpsPort);){
					throw new Exception("All port: "+httpsPort1+" "+httpsPort2+" "+httpsPort3+" already in use!");
				}catch(IOException e){}
			}catch(IOException e){}
		}catch(IOException e){}
		
		System.out.println("Selected https port: "+selectedHttpsPort);
		
		
		
		
		//SocketAddress httpSa = SocketAddress.inetSocketAddress(new InetSocketAddress(selectedHttpPort));
		SocketAddress httpsSa = SocketAddress.inetSocketAddress(new InetSocketAddress(selectedHttpsPort));
		
		httpsVertx = Vertx.vertx();
		Router httpsRouter = Router.router(httpsVertx);
		
		//httpVertx = Vertx.vertx();
		//Router httpRouter = Router.router(httpVertx);
		
		//httpsRouter.get("/stop")				.blockingHandler(this::onStop);
		
		httpsRouter.get("/ping")				.blockingHandler(this::onPing);
		httpsRouter.options("/ping")			.blockingHandler(this::onPingOption);
		
		//httpRouter.get("/ping")					.blockingHandler(this::onPing);
	
		httpsRouter.route("/shellcommand")		.handler(this::onShellcommand);
			
		httpsRouter.get()
		.blockingHandler(ctx->{
			if(ctx.request().path().equals("/"))
				ctx.response().putHeader("content-type", "text/html").end(getHomePage());
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
		
		
		/*
		SelfSignedCertificate ssCert = SelfSignedCertificate.create();
		ssCert.keyCertOptions();
		ssCert.trustOptions();
		*/
		
		//TODO get privare root key and certificate over https 
		//from https://remotecontrolclient.netlify.app
		
		PrivateKey privateKey = UtilSSL.INSTANCE.getOrNewCommonNamePrivateKey(getThisIssuerName());
		X509Certificate certificate = 
				UtilSSL.INSTANCE.getOrNewOrRenewCertificate(
						RootCAGeneration.getRootName(), 
						getThisIssuerName(), 
						getThisSubjectAlternativeName(), 
						true);
		
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		UtilSSL.INSTANCE.writeToPEMFormat(privateKey, baos);
		String privateKeyPem =new String(baos.toByteArray());
		
		baos = new ByteArrayOutputStream();
		UtilSSL.INSTANCE.writeToPEMFormat(certificate, baos);
		String certificatePem =new String(baos.toByteArray());
		/*
		Map<String, Object> keyCertMap = new HashMap<>();
		keyCertMap.put("keyValue", privateKeyPem);
		keyCertMap.put("certValues", certificatePem);
		
		JsonObject jsObj = new JsonObject(keyCertMap);
		*/
		
		Buffer privateKeyBuffer = Buffer.buffer(privateKeyPem);
		Buffer certificateBuffer = Buffer.buffer(certificatePem);
		
		//PemKeyCertOptions pkco = new PemKeyCertOptions(jsObj);
		//PemTrustOptions pto = new PemTrustOptions(jsObj);
		
		
		
		PemKeyCertOptions pkco = new PemKeyCertOptions();
		pkco.addKeyValue(privateKeyBuffer);
		pkco.addCertValue(certificateBuffer);
		
		//PemTrustOptions pto = new PemTrustOptions();
		//pto.addCertValue(certificateBuffer);
		
		/*
		KeyStore keystore = KeyStore.getInstance("JKS");
		keystore.load(null);
		keystore.setCertificateEntry("cert-alias", certificate);
		keystore.setKeyEntry("key-alias", privateKey, "changeit".toCharArray(), new Certificate[] {certificate});
			
	    KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
	    kmf.init(keystore, "changeit".toCharArray());
		
		JksOptions jksOptions = new JksOptions();
		*/
		
		
		HttpServerOptions hso = new HttpServerOptions()
		.setSsl(true)
		.setKeyCertOptions(pkco)
		//.setTrustOptions(pto)
		
		
		  //.setKeyCertOptions(ssCert.keyCertOptions())
		 // .setTrustOptions(ssCert.trustOptions());
		;
	
		
		
		/*return*/ httpsVertx
				.createHttpServer(hso)
				.requestHandler(httpsRouter)
				.listen(httpsSa);
		
		/*
		httpVertx
		.createHttpServer()
		.requestHandler(httpRouter)
		.listen(httpSa);
		*/
	}
	
	private X500Name getThisIssuerName() {
		X500NameBuilder rootX500nameBuilder = new X500NameBuilder(BCStyle.INSTANCE);
	    rootX500nameBuilder.addRDN(BCStyle.CN, "Computer A");
	    rootX500nameBuilder.addRDN(BCStyle.OU, "Computer A for test purposes");
	   
	    return rootX500nameBuilder.build();
	}

	private List<GeneralName> getThisSubjectAlternativeName(){
	    List<GeneralName> subjectAlternativeName = new ArrayList<>();
	    //subjectAlternativeName.add(new GeneralName(GeneralName.dNSName, "issuerDomainName.local"));
	    //subjectAlternativeName.add(new GeneralName(GeneralName.dNSName, "localhost"));
	    subjectAlternativeName.add(new GeneralName(GeneralName.iPAddress, "192.168.0.0"));
	   //TODO iterate interfaces to get ip
	    return subjectAlternativeName;
	}
	
	public void onStop(RoutingContext ctx) {
		if(ctx!=null) 
			ctx.response().putHeader("content-type", "text/plain").end("Stopping app...\n");
		httpsVertx.close();
		//httpVertx.close();
	}
	
	private void onPing(RoutingContext ctx) {
		if(ctx!=null) {
			
			String reqType = ctx.request().getHeader("Accept")!=null?ctx.request().getHeader("Accept"):"";
			reqType = ctx.request().getHeader("content-type")!=null?ctx.request().getHeader("content-type"):reqType;
			
			if(reqType.contains("application/json")) {
				addCorsPolicy(ctx.response())
					.putHeader("content-type", "application/json")
				//.putHeader("Access-Control-Allow-Origin", "http://localhost:8080")
				//.putHeader("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept")
				.end("{\"response\": \"pong\"}");
			}else
				ctx.response().putHeader("content-type", "text/plain").end("pong\n");
		}
	}
	
	private void onPingOption(RoutingContext ctx) {
		addCorsPolicy(ctx.response())
		.end();
	}
	
	private void onShellcommand(RoutingContext ctx) {
		

		
		HttpServerRequest req = ctx.request();
		
			
		req.bodyHandler(buff->{
			
			String lastCommand = "";
			String shellResponse = "";
			String errorShellResponse = "";
			
			String contentType = req.headers().get("Content-Type");
			
			if(req.method().equals(HttpMethod.POST))
				 if ("application/x-www-form-urlencoded".equals(contentType)) {
					 
					 QueryStringDecoder qsd = new QueryStringDecoder(buff.toString(), false);
					 Map<String, List<String>> params = qsd.parameters();
					 
					 String command = params.get("command").get(0);
			
					 try {
						 
						Process proc = Runtime.getRuntime().exec(command);
						
						BufferedReader stdInput = new BufferedReader(new 
							 InputStreamReader(proc.getInputStream()));

						BufferedReader stdError = new BufferedReader(new 
						     InputStreamReader(proc.getErrorStream()));
						
						String s = null;
						StringBuilder str = new StringBuilder();
						
						while ((s = stdInput.readLine()) != null) {
							str.append(s+"<br>");
						}
						shellResponse = str.toString();
						
						str = new StringBuilder();
						while ((s = stdError.readLine()) != null) {
							str.append(s+"<br>");
						}
						errorShellResponse = str.toString();
							
						
					} catch (IOException e) {
						errorShellResponse = e.getMessage();
					}
										 
					 lastCommand = command;
				 }
			
			
			
			addCorsPolicy(ctx.response())
			.end(getShellCommandForm(lastCommand, shellResponse, errorShellResponse));
		});
			
		
		
		
		
		
	}
	
	

	
	
	private String getShellCommandForm(String lastCommand, String shellResponse, String errorShellResponse) {
		String form = ""
				+ "<h1>Shell Command Form</h1>"
				+ "<form action=\"/shellcommand\" method=\"post\">"
				+ "<label for=\"command\">cmd:</label><br>"
				+ "<input type=\"text\" id=\"command\" name=\"command\" value=\""+lastCommand+"\"><br>"
				+ "<input type=\"submit\" value=\"Invia\">"
				+ "</form>"
				+ "<div>"
				+ shellResponse
				+ "</div>"
				+ "<div style=\"color: red;\">"
				+ errorShellResponse
				+ "</div>";;
		
		
		return getEmptyBody("Shell Command Form",form);
	}
	
	
	private String getEmptyBody(String title, String bodyContent) {
		return "<!DOCTYPE html>"
				+ "<html>"
				+ "<head>"
				+ "<meta name=\"viewport\" content=\"width=device-width, height=device-height, initial-scale=1.0, minimum-scale=1.0\">"
				+ "<title>"+title+"</title>"
				+ "</head>"
				+ "<body>"
				+ bodyContent
				+ "</body"
				+ "</html>";
	}
	
	
	
	private String getHomePage() {
		String bodyContent = ""
				+ "<h1>Home page</h1>"
				+ "<div><a href=\"/shellcommand\">shellcommand</a></div>"
				+ ""
				+ ""
				+ "";
		return getEmptyBody("HomePage", bodyContent);
	}
	
	
	private HttpServerResponse addCorsPolicy(HttpServerResponse resp) {
		resp
		//.putHeader("Access-Control-Allow-Origin", "http://localhost:8080")
		.putHeader("Access-Control-Allow-Origin", "https://remotecontrolclient.netlify.app")
		.putHeader("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
		return resp;
	}
}
