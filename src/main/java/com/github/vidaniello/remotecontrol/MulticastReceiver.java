package com.github.vidaniello.remotecontrol;

import java.net.DatagramPacket;
import java.net.InetAddress;
import java.net.MulticastSocket;
import java.net.SocketException;
import java.util.concurrent.Callable;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class MulticastReceiver extends MulticastCommunication implements Callable<Void> {


	
	public MulticastReceiver(int port, String multicastAddress) {
		super(port, multicastAddress);
	}
	
	public MulticastReceiver(int port, String multicastAddress, int bufferSize) {
		super(port, multicastAddress, bufferSize);
	}
	
	@Override
	public Void call() throws Exception {
		
		setStopRequest(false);
		
		setGroup(InetAddress.getByName(getMulticastAddress()));
		
		try {
			
			setMulticastSocket(new MulticastSocket(getPort()));
			
			getMulticastSocket().joinGroup(getGroup());
						
			while(true) {
				
				DatagramPacket packet = new DatagramPacket(getBuf(), getBuf().length);
				getMulticastSocket().receive(packet);
				
				String receive = new String(packet.getData(), 0 ,packet.getLength());
					
				getLog().debug(packet.getAddress().getHostAddress()+":"+packet.getPort()+": "+receive);
				
				if(receive.equals("end")) {
					setStopRequest(true);
					break;
				}
			}
			
			
		} catch (SocketException e) {
			if(!isStopRequest())
				getLog().error(e.getMessage(), e);
		} catch (Exception e) {
			getLog().error(e.getMessage(), e);
		} finally {
			_close();
		}

		return null;
	}

	public void close() {
		_close();
	}
	
	private void _close() {
		
		if(!isStopRequest())
			try {
				
				setStopRequest(true);
				
				if(getMulticastSocket()!=null) {
					
					if(getGroup()!=null)
						getMulticastSocket().leaveGroup(getGroup());
					
					getMulticastSocket().close();
				}
			} catch (Exception e) {
				
			}
	}
}
