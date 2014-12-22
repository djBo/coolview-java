package nl.coolview.crypto;

/**
 * <p>Copyright (c) Rory Slegtenhorst</p>
 * <p>Permission is hereby granted, free of charge, to any person obtaining a copy<br>
 * of this software and associated documentation files (the "Software"), to deal<br>
 * in the Software without restriction, including without limitation the rights<br>
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell<br>
 * copies of the Software, and to permit persons to whom the Software is<br>
 * furnished to do so, subject to the following conditions:<br>
 * <p>The above copyright notice and this permission notice shall be included in all<br>
 * copies or substantial portions of the Software.</p>
 * <p>THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR<br>
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,<br>
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE<br>
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER<br>
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,<br>
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE<br>
 * SOFTWARE.</p>
 * 
 * @author Rory Slegtenhorst <rory.slegtenhorst@gmail.com>
 */
public class Bob extends Crypto {

	byte[] counter = new byte[16]; // 128-bit counter.

	byte[] randomC = new byte[20];
	byte[] randomD = new byte[20];
	byte[] randomY = new byte[20];

	byte[] key = new byte[20]; // Encrypted Master Key
	byte[] salt = new byte[20];
	byte[] sequence = new byte[20]; // Sequence Key
	byte[] token;
	
	// TEMPORARY
	String password;
	byte[] otp = new byte[20];
	byte[] master = new byte[20];
	byte[] hmac;
	byte[] dkey;
	byte[] K = new byte[16];
	byte[] iv = new byte[16];
	byte[] alice = new byte[20];
	byte[] T;

	public Bob() {
		this("");
	}
	public Bob(String data) {
		super();
		fromString(data);
	}

	public void clear() {
		password = null;
		counter = new byte[16];
		randomC = null;
		randomD = null;
		randomY = null;
		otp = null;
		master = null;
		hmac = null;
		dkey = null;
		K = new byte[16];
		iv = new byte[16];
		alice = null;
		T = null;
	}

	public void fromString(String data) {
		String[] parts = data.split("\\|");
		if (parts.length == 5) {
			counter = dehex(parts[0]);
			key = dehex(parts[1]);
			salt = dehex(parts[2]);
			sequence = dehex(parts[3]);
			token = dehex(parts[4]);
			
			randomC = null;
			randomD = null;
			randomY = null;
			password = null;
			otp = new byte[20];
			master = new byte[20];
			hmac = null;
			dkey = null;
			K = new byte[16];
			iv = new byte[16];
			alice = new byte[20];
			T = null;
		}
	}
	
	@Override
	public String toString() {
		return hex(counter) + "|" + hex(key) + "|" + hex(salt) + "|" + hex(sequence) + "|" + hex(token);
	}
	
	
}
