package com.github.vidaniello.remotecontrol;

import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.MulticastSocket;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class MulticastCommunication {

	private static int defaultBufferSize = 256;
	
	private Logger log = LogManager.getLogger();

	private DatagramSocket socket;
	private InetAddress group;
	private byte[] buf;

	private int port;
	private String multicastAddress;

	private volatile boolean stopRequest;

	public MulticastCommunication() {

	}

	public MulticastCommunication(int port, String multicastAddress, int bufferSize) {
		this.port = port;
		this.multicastAddress = multicastAddress;
		buf = new byte[bufferSize];
	}
	
	public MulticastCommunication(int port, String multicastAddress) {
		this(port, multicastAddress, defaultBufferSize);
	}

	protected DatagramSocket getSocket() {
		return socket;
	}
	
	protected void setSocket(DatagramSocket socket) {
		this.socket = socket;
	}
	
	protected MulticastSocket getMulticastSocket() {
		return (MulticastSocket) socket;
	}

	protected void setMulticastSocket(MulticastSocket mSoc) {
		this.socket = mSoc;
	}

	protected byte[] getBuf() {
		return buf;
	}

	protected void setBuf(byte[] buf) {
		this.buf = buf;
	}

	public InetAddress getGroup() {
		return group;
	}

	protected void setGroup(InetAddress group) {
		this.group = group;
	}

	public Logger getLog() {
		return log;
	}

	public String getMulticastAddress() {
		return multicastAddress;
	}

	public int getPort() {
		return port;
	}
	
	public boolean isStopRequest() {
		return stopRequest;
	}
	
	protected void setStopRequest(boolean stopRequest) {
		this.stopRequest = stopRequest;
	}
}
