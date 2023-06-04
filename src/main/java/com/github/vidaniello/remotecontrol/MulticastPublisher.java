package com.github.vidaniello.remotecontrol;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;

public class MulticastPublisher extends MulticastCommunication{
	
	
	public MulticastPublisher(int port, String multicastAddress) {
		super(port, multicastAddress);
	}
	
	public synchronized void pubblish(String message) throws IOException{
		
		setSocket(new DatagramSocket());
		setGroup(InetAddress.getByName(getMulticastAddress()));
		
		setBuf(message.getBytes());
		
		DatagramPacket packet = new DatagramPacket(getBuf(), getBuf().length, getGroup(), getPort());
		
		getSocket().send(packet);
		
		getSocket().close();
	}

}
