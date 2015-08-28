package nl.coolview.util;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyManagementException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;

import javax.crypto.NoSuchPaddingException;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManagerFactory;

import nl.coolview.crypto.Crypto;

import org.apache.log4j.Logger;

public class CertUtils {
	private static Logger logger = Logger.getLogger(CertUtils.class);

	public static final HostnameVerifier DO_NOT_VERIFY = new HostnameVerifier() {
		@Override
		public boolean verify(String hostname, SSLSession session) {
			return true;
		}
	};

	public static void generateCerts(KeyStore keystore, char[] password, Integer size, String DN, String alias, String root) {
		try {
			logger.debug("Generating key pair...");
			KeyPair kp = Crypto.genkeypair(size);
			logger.debug("Generating self-signed certificate...");
			X509Certificate cert = Crypto.genca(kp, DN, new Date(), 365);

			//TODO: FIX THIS!
			if (root != null) {
				logger.debug("Loading ca certificate...");
				X509Certificate caCert = null;
				try (InputStream is = new FileInputStream(root)) {
					CertificateFactory cf = CertificateFactory.getInstance("X.509");
					caCert = (X509Certificate)cf.generateCertificate(is);
				}
				keystore.setCertificateEntry("ca", caCert);
			}

			keystore.setKeyEntry(alias, kp.getPrivate(), password, new Certificate[] {cert});

		} catch (Exception e) {
			logger.fatal("Unable to generate local self-signed certificate", e);
		}
	}

	public static void setupTrustManager(KeyStore keystore, char[] password) throws NoSuchAlgorithmException, KeyStoreException, KeyManagementException, UnrecoverableKeyException {
		// Create a TrustManager that trusts the CAs in our KeyStore
		TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
		tmf.init(keystore);

		// Create a KeyManager that delivers the client certificate from our KeyStore
		KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
		kmf.init(keystore, password);

		// Create an SSLContext that uses our TrustManager
		SSLContext context = SSLContext.getInstance("TLS");
		context.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);

		HttpsURLConnection.setDefaultSSLSocketFactory(context.getSocketFactory());
		HttpsURLConnection.setDefaultHostnameVerifier(DO_NOT_VERIFY);
	}

	public static KeyStore loadKeyStore(File file, char[] password) throws Exception {
		KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
		if (file.exists()) {
			try (InputStream is = new FileInputStream(file);) {
				keyStore.load(is, password);
			}
		} else {
			keyStore.load(null, password);
		}
		return keyStore;
	}

	public static void saveKeystore(KeyStore keystore, File file, char[] password) throws Exception {
		if (keystore == null) throw new Exception("Keystore not initialized");
		OutputStream os = new FileOutputStream(file);
		try {
			keystore.store(os, password);
		} finally {
			os.close();
		}
	}

	private static void writeLn(BufferedWriter bw, String s) throws IOException {
		bw.write(s);
		bw.newLine();
	}

	public static void encodePrivateKey(PrivateKey k, String p, String f) throws NoSuchAlgorithmException, NoSuchPaddingException, IOException {
		byte[] pw = p.getBytes();
		byte[] iv = new byte[16];
		Crypto.rng(iv);
		byte[] sk = Arrays.copyOf(Crypto.derive(pw, Arrays.copyOf(iv, 8), 1, 3, "MD5"), 32);

        BufferedWriter bw = new BufferedWriter(new FileWriter(new File(f), true));
		try {
			writeLn(bw, "-----BEGIN RSA PRIVATE KEY-----");
            writeLn(bw, "Proc-Type: 4,ENCRYPTED");
            writeLn(bw, "DEK-Info: AES-256-CBC," + Crypto.hex(iv).toUpperCase());
            writeLn(bw, "");
            for (String s : Crypto.split(Crypto.e64(Crypto.enc(k.getEncoded(), sk, iv)), 64))
            	writeLn(bw, s);
            writeLn(bw, "-----END RSA PRIVATE KEY-----");
		} finally {
			bw.close();
		}
	}

	public static void encodeCertificate(X509Certificate cert, String f) throws CertificateEncodingException, IOException {
		BufferedWriter bw = new BufferedWriter(new FileWriter(new File(f), true));
		try {
			writeLn(bw, "-----BEGIN CERTIFICATE-----");
			for (String s : Crypto.split(Crypto.e64(cert.getEncoded()), 64))
				writeLn(bw, s);
			writeLn(bw, "-----END CERTIFICATE-----");
		} finally {
			bw.close();
		}
	}

}
