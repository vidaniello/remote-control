package com.github.vidaniello.remotecontrol;
/*
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketException;
import java.net.UnknownHostException;

import sun.net.util.IPAddressUtil;

public class JsMain {
	
	private static String multicastAddress = "230.1.5.5";
	private static int receiverPort = 34345;

	public static void main(String[] args) {
		
		System.out.println("Hello World!");
		

		//try {
			
			//byte [] ipstr = IPAddressUtil.validateNumericFormatV4(multicastAddress);
			//InetAddress ia = new Inet4Address(null, ipstr);
			
			String message = "Message from java";
			
			byte[] buf = message.getBytes();
			//InetSocketAddress address = new InetSocketAddress(multicastAddress, receiverPort);
			
			//InetAddress ia = InetAddress.getByName(multicastAddress);
			//DatagramSocket socket = new DatagramSocket();
			//DatagramPacket packet = new DatagramPacket(buf,buf.length, ia, receiverPort);
			//socket.send(packet);
			
			//socket.close();
			/*
		} catch (SocketException e) {
			e.printStackTrace();
		} catch (UnknownHostException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
		*/
/*
		System.out.println("Hello World!");
	}

}
*/