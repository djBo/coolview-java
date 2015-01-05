package nl.coolview.crypto;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Random;
import java.util.Vector;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import sun.security.pkcs.PKCS10;
import sun.security.util.ObjectIdentifier;
import sun.security.x509.AlgorithmId;
import sun.security.x509.AuthorityKeyIdentifierExtension;
import sun.security.x509.BasicConstraintsExtension;
import sun.security.x509.CertificateAlgorithmId;
import sun.security.x509.CertificateExtensions;
import sun.security.x509.CertificateIssuerName;
import sun.security.x509.CertificateSerialNumber;
import sun.security.x509.CertificateSubjectName;
import sun.security.x509.CertificateValidity;
import sun.security.x509.CertificateVersion;
import sun.security.x509.CertificateX509Key;
import sun.security.x509.ExtendedKeyUsageExtension;
import sun.security.x509.KeyIdentifier;
import sun.security.x509.KeyUsageExtension;
import sun.security.x509.NetscapeCertTypeExtension;
import sun.security.x509.SubjectKeyIdentifierExtension;
import sun.security.x509.X500Name;
import sun.security.x509.X509CertImpl;
import sun.security.x509.X509CertInfo;

/**
 * Crypto Class
 * 
 * <p>This class contains the most commonly used crypto functions in a single abstract class.
 * <p>Copyright (c) Rory Slegtenhorst
 * <p>Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * <p>The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * <p>THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 * 
 * @author Rory Slegtenhorst <rory.slegtenhorst@gmail.com>
 */
public abstract class Crypto {

	private static final String MAC = "HmacSHA1";
	private static final String MD = "SHA-1";
	private static final String RNG = "SHA1PRNG";
	private static final String CipherName = "AES";
	private static final String CipherInstance = "AES/CBC/PKCS5Padding";
	private static final String PubAlgo = "RSA";
	private static final String SigAlgo = "SHA1WithRSA";
	
	private final static char[] ALPHABET_BASE64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".toCharArray();
	private static int[] CHARACTER_BASE64 = new int[128];

	private static final String ALPHABET_HEX = "0123456789abcdef";
	private static final char[] CHARACTER_HEX = ALPHABET_HEX.toCharArray();
	
	private static final String ALPHABET_MODHEX = "cbdefghijklnrtuv";
	private static final char[] CHARACTERS_MODHEX = ALPHABET_MODHEX.toCharArray();
	
	private static final String CHARSET_UTF8 = "UTF-8";
	
	public static final String OBFUSCATE = "OBF:";
	
	static {
		for (int i = 0; i < ALPHABET_BASE64.length; i++) {
			CHARACTER_BASE64[ALPHABET_BASE64[i]] = i;
		}
	}
	
	/**
	 * Compare two byte arrays
	 * @param byte[] first
	 * @param byte[] second
	 * @return true if both arrays are null or if the arrays have the same length and the elements at each index in the two arrays are equal, false otherwise.
	 */
	public static boolean compare(byte[] first, byte[] second) {
		return java.util.Arrays.equals(first, second);
	}
		
	/**
	 * Concatenates two byte arrays
	 * @param byte[] first
	 * @param byte[] second
	 * @return The concatenated byte array
	 */
	public static byte[] concat(byte[] first, byte[] second) {
		byte[] result = new byte[first.length + second.length];
		System.arraycopy(first, 0, result, 0, first.length);
		System.arraycopy(second, 0, result, first.length, second.length);
		return result;
	}

	/**
	 * Decode Base64 data
	 * @param String data
	 * @return byte[] containing the decoded bytes
	 */
	public static byte[] d64(String data) {
		int delta = data.endsWith("==") ? 2 : data.endsWith("=") ? 1 : 0;
		byte[] buffer = new byte[data.length() * 3 / 4 - delta];
		int mask = 0xFF;
		int index = 0;
		for (int i = 0; i < data.length(); i += 4) {
			int c0 = CHARACTER_BASE64[data.charAt(i)];
			int c1 = CHARACTER_BASE64[data.charAt(i + 1)];
			buffer[index++] = (byte) (((c0 << 2) | (c1 >> 4)) & mask);
			if (index >= buffer.length) {
				return buffer;
			}
			int c2 = CHARACTER_BASE64[data.charAt(i + 2)];
			buffer[index++] = (byte) (((c1 << 4) | (c2 >> 2)) & mask);
			if (index >= buffer.length) {
				return buffer;
			}
			int c3 = CHARACTER_BASE64[data.charAt(i + 3)];
			buffer[index++] = (byte) (((c2 << 6) | c3) & mask);
		}
		return buffer;
	}

	/**
	 * Synchronous decryption of data, defaulting to AES
	 * @param byte[] data
	 * @param byte[] keyData
	 * @param [] ivData
	 * @return Decoded bytes
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 */
	public static synchronized byte[] dec(byte[] data, byte[] keyData, byte[] ivData) throws NoSuchAlgorithmException, NoSuchPaddingException {
		try {
			final Cipher mCipher = Cipher.getInstance(CipherInstance);
			final IvParameterSpec iv = new IvParameterSpec(ivData);
			final SecretKey key = new SecretKeySpec(keyData, CipherName);
			mCipher.init(Cipher.DECRYPT_MODE, key, iv);
			return mCipher.doFinal(data);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}
	
	/**
	 * Decodes a HEX string
	 * @param String data
	 * @return byte[] decoded
	 */
	public static byte[] dehex(String data) {
		byte[] res = new byte[data.length() / 2];
		for (int i = 0; i < res.length; i++) {
			res[i] = (byte) Integer.parseInt(data.substring(2*i, 2*i+2), 16);
		}
		return res;
	}

	/**
	 * De-Obfuscate input string
	 * @param String s
	 * @return de-obfuscated string
	 */
	public static String deobf(String s) {
        if (s.startsWith(OBFUSCATE)) s = s.substring(4);

        byte[] b = new byte[s.length() / 2];
        int l = 0;
        for (int i = 0; i < s.length(); i += 4)
        {
            if (s.charAt(i)=='U')
            {
                i++;
                String x = s.substring(i, i + 4);
                int i0 = Integer.parseInt(x, 36);
                byte bx = (byte)(i0>>8);
                b[l++] = bx;
            }
            else
            {
                String x = s.substring(i, i + 4);
                int i0 = Integer.parseInt(x, 36);
                int i1 = (i0 / 256);
                int i2 = (i0 % 256);
                byte bx = (byte) ((i1 + i2 - 254) / 2);
                b[l++] = bx;
            }
        }

        try {
			return new String(b, 0, l, CHARSET_UTF8);
		} catch (UnsupportedEncodingException e) {
			throw new RuntimeException(e);
		}
    }
	
	/**
	 * Password Based Key Derivation Function
	 * @param byte[] password
	 * @param byte[] salt
	 * @param Integer count
	 * @param Integer iterations
	 * @param String messageDigest
	 * @return
	 */
	public static byte[] derive(byte[] password, byte[] salt, Integer count, Integer iterations, String messageDigest) {
		MessageDigest md = null;
		try {
			md = MessageDigest.getInstance(messageDigest);
			byte[] keyMaterial = new byte[md.getDigestLength() * iterations];
			
			byte[] data00 = concat(password, salt); 

			byte[] result = null;
			byte[] hashtarget = new byte[md.getDigestLength() + data00.length];
			
			for (int j = 0; j < iterations; j++) {
				if (j == 0) {
					result = data00;
				} else {
					hashtarget = concat(result, data00);
					result = hashtarget;
				}
				for(int i = 0; i < count; i++)
					result = md.digest(result);
				System.arraycopy(result, 0, keyMaterial, j * md.getDigestLength(), result.length);
			}
			return keyMaterial;
			
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			return null;
		}
	}

	/**
	 * Password Based Key Derivation Function, defaulting to SHA-1
	 * @see derive
	 */
	public static byte[] derive(byte[] password, byte[] salt, Integer count, Integer iterations) {
		return derive(password, salt, count, iterations, MD);
	}

	/**
	 * Password Based Key Derivation Function, defaulting to SHA-1, using the standard settings for most use cases.
	 * @param input
	 * @param salt
	 * @return
	 */
	public static byte[] derive(byte[] input, byte[] salt) {
		return derive(input, salt, 1, 3);
	}

	/**
	 * Base64 encode data
	 * @param byte[] data
	 * @return Base64 encoded data
	 */
	public static String e64(byte[] data) {
		int size = data.length;
		char[] ar = new char[((size + 2) / 3) * 4];
		int a = 0;
		int i = 0;
		while (i < size) {
			byte b0 = data[i++];
			byte b1 = (i < size) ? data[i++] : 0;
			byte b2 = (i < size) ? data[i++] : 0;

			int mask = 0x3F;
			ar[a++] = ALPHABET_BASE64[(b0 >> 2) & mask];
			ar[a++] = ALPHABET_BASE64[((b0 << 4) | ((b1 & 0xFF) >> 4)) & mask];
			ar[a++] = ALPHABET_BASE64[((b1 << 2) | ((b2 & 0xFF) >> 6)) & mask];
			ar[a++] = ALPHABET_BASE64[b2 & mask];
		}
		switch (size % 3) {
		case 1:
			ar[--a] = '=';
		case 2:
			ar[--a] = '=';
		}
		return new String(ar);
	}

	/**
	 * Synchronous Encryption of data
	 * @param data
	 * @param keyData
	 * @param ivData
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 */
	public static synchronized byte[] enc(byte[] data, byte[]keyData, byte[]ivData) throws NoSuchAlgorithmException, NoSuchPaddingException {
		return enc(data, keyData, ivData, CipherInstance, CipherName);
	}
	
	public static synchronized byte[] enc(byte[] data, byte[]keyData, byte[]ivData, String cipherInstance) throws NoSuchAlgorithmException, NoSuchPaddingException {
		return enc(data, keyData, ivData, cipherInstance, CipherName);
	}
	
	public static synchronized byte[] enc(byte[] data, byte[]keyData, byte[]ivData, String cipherInstance, String cipherName) throws NoSuchAlgorithmException, NoSuchPaddingException {
		try {
			final Cipher mCipher = Cipher.getInstance(cipherInstance);
			final IvParameterSpec iv = new IvParameterSpec(ivData);
			final SecretKey key = new SecretKeySpec(keyData, cipherName);
			mCipher.init(Cipher.ENCRYPT_MODE, key, iv);
			return mCipher.doFinal(data);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	/**
	 * Returns HEX encoded string of data
	 * @param byte[] data
	 * @return HEX encoded string
	 */
	public static String hex(byte[] data) {
		char[] res = new char[2 * data.length];
		for (int i = 0; i < data.length; ++i)
		{
			res[2 * i] = CHARACTER_HEX[(data[i] & 0xF0) >>> 4];
			res[2 * i + 1] = CHARACTER_HEX[data[i] & 0x0F];
		}
		return new String(res);//.toUpperCase();

	}

	/**
	 * Generate self-signed CA certificate
	 * @param keyPair
	 * @param DN
	 * @param first
	 * @param days
	 * @return
	 * @throws Exception
	 */
	public static X509Certificate genca(KeyPair keyPair, String DN, Date first, long days) throws Exception {

		Date last = new Date(first.getTime() + (days * 24 * 60 * 60 * 1000));
		CertificateValidity period = new CertificateValidity(first, last);
		
		BigInteger serial = new BigInteger(64, SecureRandom.getInstance(RNG));
		AlgorithmId algo = new AlgorithmId(AlgorithmId.sha1WithRSAEncryption_oid);
		
		X500Name owner = new X500Name(DN);
		
		X509CertInfo info = new X509CertInfo();
		info.set(X509CertInfo.VERSION, new CertificateVersion(CertificateVersion.V3));
		info.set(X509CertInfo.SERIAL_NUMBER, new CertificateSerialNumber(serial));
		info.set(X509CertInfo.ALGORITHM_ID, new CertificateAlgorithmId(algo));
		info.set(X509CertInfo.SUBJECT, new CertificateSubjectName(owner));
		info.set(X509CertInfo.KEY, new CertificateX509Key(keyPair.getPublic()));
		info.set(X509CertInfo.VALIDITY, period);
		info.set(X509CertInfo.ISSUER, new CertificateIssuerName(owner));

		// Add extensions
		CertificateExtensions ext = new CertificateExtensions();
		ext.set(BasicConstraintsExtension.NAME, new BasicConstraintsExtension(/* isCritical */true, /* isCA */true, -1));
		info.set(X509CertInfo.EXTENSIONS, ext);

		// Sign the cert to identify the algorithm that's used.
		X509CertImpl cert = new X509CertImpl(info);
		cert.sign(keyPair.getPrivate(), SigAlgo);

		 // Update the algorith, and resign.
		algo = (AlgorithmId)cert.get(X509CertImpl.SIG_ALG);
		info.set(CertificateAlgorithmId.NAME + "." + CertificateAlgorithmId.ALGORITHM, algo);
		cert = new X509CertImpl(info);
		cert.sign(keyPair.getPrivate(), SigAlgo);
		  
		return cert;
	}
	
	/**
	 * Generate a certificate sign request
	 * @param DN
	 * @param keyPair
	 * @return
	 * @throws Exception
	 */
	public static PKCS10 gencsr(String DN, KeyPair keyPair) throws Exception {
		PKCS10 csr = new PKCS10 (keyPair.getPublic());
		X500Name owner = new X500Name(DN);
		Signature sig = Signature.getInstance(SigAlgo);
        sig.initSign (keyPair.getPrivate());
        csr.encodeAndSign(owner, sig);
        return csr;
	}

	public static X509Certificate signcsr(PKCS10 csr, Certificate signCert, PrivateKey signKey, Date first, long days) throws Exception {
		return signcsr(csr, signCert, signKey, first, days, false, 0);
	}
	
	/**
	 * Sign a CSR, returning the signed certificate
	 * @param csr
	 * @param signCert
	 * @param signKey
	 * @param first
	 * @param days
	 * @param isCA
	 * @param depth
	 * @return
	 * @throws Exception
	 */
	public static X509Certificate signcsr(PKCS10 csr, Certificate signCert, PrivateKey signKey, Date first, long days, boolean isCA, int depth) throws Exception {
		Date last = new Date(first.getTime() + (days * 24 * 60 * 60 * 1000));
		CertificateValidity period = new CertificateValidity(first, last);
		
		BigInteger serial = new BigInteger(64, SecureRandom.getInstance(RNG));
		AlgorithmId algo = new AlgorithmId(AlgorithmId.sha1WithRSAEncryption_oid);

		X509CertImpl signCertImpl = new X509CertImpl(signCert.getEncoded());
		X509CertInfo signCertInfo = (X509CertInfo)signCertImpl.get(X509CertImpl.NAME + "." + X509CertImpl.INFO);
		X500Name signer = (X500Name) signCertInfo.get(X509CertInfo.SUBJECT + "." + CertificateSubjectName.DN_NAME);

		X509CertInfo info = new X509CertInfo();
		info.set(X509CertInfo.VERSION, new CertificateVersion(CertificateVersion.V3));
		info.set(X509CertInfo.SERIAL_NUMBER, new CertificateSerialNumber(serial));
		info.set(X509CertInfo.ALGORITHM_ID, new CertificateAlgorithmId(algo));
		info.set(X509CertInfo.SUBJECT, new CertificateSubjectName(csr.getSubjectName()));
		info.set(X509CertInfo.KEY, new CertificateX509Key(csr.getSubjectPublicKeyInfo()));
		info.set(X509CertInfo.VALIDITY, period);
		info.set(X509CertInfo.ISSUER, new CertificateIssuerName(signer));		
		
		// Add extensions
		CertificateExtensions ext = new CertificateExtensions();
		
		ext.set(SubjectKeyIdentifierExtension.NAME, new SubjectKeyIdentifierExtension(new KeyIdentifier(csr.getSubjectPublicKeyInfo()).getIdentifier()));
		ext.set(AuthorityKeyIdentifierExtension.NAME, new AuthorityKeyIdentifierExtension(new KeyIdentifier(signCert.getPublicKey()), null, null));

		// Basic Constraints
		ext.set(BasicConstraintsExtension.NAME, new BasicConstraintsExtension(/* isCritical */true, /* isCA */isCA, /* pathLen */depth));

		// Netscape Cert Type Extension
		boolean[] ncteOk = new boolean[8];
		ncteOk[0] = true; // SSL_CLIENT
		ncteOk[1] = true; // SSL_SERVER
		// "client" = 0
		// "server" = 1
		// "email" = 2
		// "objsign" = 3
		// "reserved" = 4
		// "sslCA" = 5
		// "emailCA" = 6
		// "objCA" = 7
		NetscapeCertTypeExtension ncte = new NetscapeCertTypeExtension(ncteOk);
		ncte = new NetscapeCertTypeExtension(false, ncte.getExtensionValue());
		ext.set(NetscapeCertTypeExtension.NAME, ncte);

		// Key Usage Extension
		boolean[] kueOk = new boolean[9];
		kueOk[0] = true;
		kueOk[2] = true;
		kueOk[5] = isCA;
		// "digitalSignature", // (0),
		// "nonRepudiation", // (1)
		// "keyEncipherment", // (2),
		// "dataEncipherment", // (3),
		// "keyAgreement", // (4),
		// "keyCertSign", // (5),
		// "cRLSign", // (6),
		// "encipherOnly", // (7),
		// "decipherOnly", // (8)
		// "contentCommitment" // also (1)
		KeyUsageExtension kue = new KeyUsageExtension(kueOk);
		ext.set(KeyUsageExtension.NAME, kue);

		// Extended Key Usage Extension
		int[] serverAuthOidData = { 1, 3, 6, 1, 5, 5, 7, 3, 1 };
		ObjectIdentifier serverAuthOid = new ObjectIdentifier(serverAuthOidData);
		int[] clientAuthOidData = { 1, 3, 6, 1, 5, 5, 7, 3, 2 };
		ObjectIdentifier clientAuthOid = new ObjectIdentifier(clientAuthOidData);
		Vector<ObjectIdentifier> v = new Vector<ObjectIdentifier>();
		v.add(serverAuthOid);
		v.add(clientAuthOid);
		ExtendedKeyUsageExtension ekue = new ExtendedKeyUsageExtension(false, v);
		ext.set(ExtendedKeyUsageExtension.NAME, ekue);
		info.set(X509CertInfo.EXTENSIONS, ext);

		// Sign the cert to identify the algorithm that's used.
		X509CertImpl cert = new X509CertImpl(info);
		cert.sign(signKey, SigAlgo);

		 // Update the algorith, and resign.
		algo = (AlgorithmId)cert.get(X509CertImpl.SIG_ALG);
		info.set(CertificateAlgorithmId.NAME + "." + CertificateAlgorithmId.ALGORITHM, algo);
		info.set(X509CertInfo.EXTENSIONS, ext);
		cert = new X509CertImpl(info);
		cert.sign(signKey, SigAlgo);

		return cert;
	}

	/**
	 * Generate a keypair with a given bit-length. Please note that this method can be pretty slow.
	 * @param keysize
	 * @return
	 * @throws NoSuchAlgorithmException
	 */
	public static KeyPair genkeypair(int keysize) throws NoSuchAlgorithmException {
		final KeyPairGenerator keyGen = KeyPairGenerator.getInstance(PubAlgo);
        keyGen.initialize(keysize, SecureRandom.getInstance(RNG));
        return keyGen.generateKeyPair();
	}
	
	/**
	 * Increment a byte array counter by 1
	 * @param counter
	 */
	public static void inc(byte[] counter) {
        for (int i = counter.length - 1; i >= 0; i--) {
            ++counter[i];
            if (counter[i] != 0) break; // Check whether we need to loop again to carry the one.
        }
    }
	
	/**
	 * Generate HMAC of data using input key, defaults to HmacSHA1
	 * @param key
	 * @param data
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 */
	public static byte[] mac(byte[] key, byte[] data) throws NoSuchAlgorithmException, InvalidKeyException {
		Mac mac = Mac.getInstance(MAC);
		mac.init(new SecretKeySpec(key, "RAW"));
		return mac.doFinal(data);
	}
		
	/**
	 * Generate message digest of data, defaults to SHA-1
	 * @param data
	 * @return
	 * @throws NoSuchAlgorithmException
	 */
	public static byte[] md(byte[] data) throws NoSuchAlgorithmException {
		MessageDigest md = MessageDigest.getInstance(MD);
		return md.digest(data);
	}

	/**
	 * ModHEX decode string 
	 * @param data
	 * @return
	 * @throws IOException
	 */
	public static byte[] modhex(String data) throws IOException {
		ByteArrayOutputStream baos = null;
		try {
			baos = new ByteArrayOutputStream();
			int len = data.length();

			boolean toggle = false;
			int keep = 0;

			for (int i = 0; i < len; i++) {
				char ch = data.charAt(i);
				int n = ALPHABET_MODHEX.indexOf(Character.toLowerCase(ch));
				if (n == -1) {
					throw new 
					IllegalArgumentException(data + " is not properly encoded");
				}

				toggle = !toggle;

				if (toggle) {
					keep = n;
				} else {
					baos.write((keep << 4) | n);
				}
			}
			return baos.toByteArray();
		} finally {
			if (baos != null) baos.close();
		}
	}

	/**
	 * ModHEX encode data
	 * @param data
	 * @return
	 */
	public static String modhex(byte[] data) {
		StringBuffer result = new StringBuffer();
		for (int i = 0; i < data.length; i++) {
			result.append(CHARACTERS_MODHEX[(data[i] >> 4) & 0xf]);
			result.append(CHARACTERS_MODHEX[data[i] & 0xf]);
		}
		return result.toString();

	}

	/**
	 * Obfuscate input string
	 * @param s
	 * @return
	 */
	public static String obf(String s) {
        StringBuilder buf = new StringBuilder();

        byte[] b;
		try {
			b = s.getBytes(CHARSET_UTF8);
		} catch (UnsupportedEncodingException e) {
			throw new RuntimeException(e);
		}

        buf.append(OBFUSCATE);
        for (int i = 0; i < b.length; i++)
        {
            byte b1 = b[i];
            byte b2 = b[b.length - (i + 1)];
            if (b1<0 || b2<0)
            {
                int i0 = (0xff&b1)*256 + (0xff&b2); 
                String x = Integer.toString(i0, 36).toLowerCase();
                buf.append("U0000",0,5-x.length());
                buf.append(x);
            }
            else
            {
                int i1 = 127 + b1 + b2;
                int i2 = 127 + b1 - b2;
                int i0 = i1 * 256 + i2;
                String x = Integer.toString(i0, 36).toLowerCase();

                int j0 = Integer.parseInt(x, 36);
                int j1 = (i0 / 256);
                int j2 = (i0 % 256);
                byte bx = (byte) ((j1 + j2 - 254) / 2);
                
                buf.append("000",0,4-x.length());
                buf.append(x);
            }

        }
        return buf.toString();

    }
	
	/**
	 * Generate random bytes into input array
	 * @param bytes
	 * @throws NoSuchAlgorithmException
	 */
	public static void rng(byte[] bytes) throws NoSuchAlgorithmException {
		SecureRandom sr = SecureRandom.getInstance(RNG);
		sr.nextBytes(bytes);
	}

	/**
	 * Generate random int between min and max, inclusive
	 * @param min
	 * @param max
	 * @return
	 */
	public static int random(int min, int max) {
		Random r = new Random();
		return r.nextInt((max - min) + 1) + min;
	}

	/**
	 * Split a string into lines of a given length
	 * @param in
	 * @param max
	 * @return
	 */
	public static String[] split(String in, Integer max) {
		return in.split("(?<=\\G.{" + max + "})");
	}

}
