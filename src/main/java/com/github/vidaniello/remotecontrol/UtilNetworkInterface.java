package com.github.vidaniello.remotecontrol;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;

public class UtilNetworkInterface {
	
	public static Set<String> allIpv4Ip() throws SocketException{
		Set<String> ret = new HashSet<>();
		
		Enumeration<NetworkInterface> e = NetworkInterface.getNetworkInterfaces();
		while(e.hasMoreElements())
		{
		    NetworkInterface n = (NetworkInterface) e.nextElement();
		    
		    if(n.isLoopback())continue;
		    if(n.isLoopback())continue;
		    
		    Enumeration<InetAddress> ee = n.getInetAddresses();
		    while (ee.hasMoreElements())
		    {
		        InetAddress i = (InetAddress) ee.nextElement();
		        if(i instanceof Inet4Address) {
		        	System.out.println(i.getHostAddress());
		        	ret.add(i.getHostAddress());
		        }
		    }
		}
		
		return ret;
	}

}
