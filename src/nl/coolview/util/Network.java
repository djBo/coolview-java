package nl.coolview.util;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.URL;
import java.net.UnknownHostException;
import java.util.Collections;
import java.util.Enumeration;
import java.util.Map;

import javax.net.ssl.HttpsURLConnection;


public class Network {

	public static String getHostName() {
		try {
			return InetAddress.getLocalHost().getHostName();
		} catch (UnknownHostException e) {
			e.printStackTrace();
		}
		return null;
	}

	public static String getMacAddress() {
		try {
			Enumeration<NetworkInterface> nics = NetworkInterface.getNetworkInterfaces();
			for (NetworkInterface nic : Collections.list(nics)) {
				if (nic.isLoopback()) continue;
				if (!nic.isUp()) continue;
				byte[] mac = nic.getHardwareAddress();
				StringBuilder sb = new StringBuilder();
				for (int i = 0; i < mac.length; i++) {
					sb.append(String.format("%02X%s", mac[i], (i < mac.length - 1) ? "-" : ""));		
				}
				return sb.toString();
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	public static String doGet(URL url, Map<String, String> params) throws IOException {
		return doGet(url, params, "text/plain");
	}
	
	public static String doGet(URL url, Map<String, String> params, String type) throws IOException {
		StringBuffer responseData = new StringBuffer();
		HttpURLConnection urlConnection = null;
		try {
		    urlConnection = (HttpURLConnection) url.openConnection();
		    if (urlConnection instanceof HttpsURLConnection) {
		        ((HttpsURLConnection) urlConnection).setHostnameVerifier(CertUtils.DO_NOT_VERIFY);
		    }
		    urlConnection.setRequestMethod("GET");
		    urlConnection.setRequestProperty("Content-Type", type);
		    urlConnection.setConnectTimeout(2000);
		    
			BufferedReader in = new BufferedReader(new InputStreamReader(urlConnection.getInputStream()));
			try {
				String line;
				while ((line = in.readLine()) != null) {
					responseData.append(line);
				}
			} finally {
				in.close();
			}
			
		} finally {
		    if (urlConnection != null) {
		        urlConnection.disconnect();
		    }
		}		
		return responseData.toString();
	}

	public static String doPost(URL url, String body) throws IOException {
		return doPost(url, body, "application/x-www-form-urlencoded");
	}

	public static String doPost(URL url, String body, String type) throws IOException {
		StringBuffer responseData = new StringBuffer();
		HttpURLConnection urlConnection = null;
		try {
		    urlConnection = (HttpURLConnection) url.openConnection();
		    if (urlConnection instanceof HttpsURLConnection) {
		        ((HttpsURLConnection) urlConnection).setHostnameVerifier(CertUtils.DO_NOT_VERIFY);
		    }
		    urlConnection.setRequestMethod("POST");
		    urlConnection.setRequestProperty("Content-Type", type);
		    urlConnection.setConnectTimeout(2000);
		    
		    urlConnection.setDoOutput(true);
			DataOutputStream wr = new DataOutputStream(urlConnection.getOutputStream());
			try {
				wr.writeBytes(body);
				wr.flush();
			} finally {
				wr.close();
			}
			
			BufferedReader in = new BufferedReader(new InputStreamReader(urlConnection.getInputStream()));
			try {
				String line;
				while ((line = in.readLine()) != null) {
					responseData.append(line);
				}
			} finally {
				in.close();
			}
			
		} finally {
		    if (urlConnection != null) {
		        urlConnection.disconnect();
		    }
		}		
		return responseData.toString();				
	}

}
