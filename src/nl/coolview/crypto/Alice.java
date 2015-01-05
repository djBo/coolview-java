package nl.coolview.crypto;

/**
 * Alice Class
 * 
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
public class Alice extends Crypto {

	String password;

	byte[] counter = new byte[16]; // 128-bit counter.
	
	byte[] randomA = new byte[20];
	byte[] randomB = new byte[20];
	byte[] randomX = new byte[20];
	
	byte[] key = new byte[20]; // Static Key
	byte[] salt = new byte[20];
	byte[] sequence = new byte[20];
	
	//TEMPORARY
	byte[] otp = new byte[20];
	
	public Alice() {
		this("");
	}
	public Alice(String data) {
		super();
		fromString(data);
	}
	
	public void clear() {
		counter = new byte[16];
		randomA = null;
		randomB = null;
		randomX = null;
		otp = null;
	}

	public void fromString(String data) {
		String[] parts = data.split("\\|");
		if (parts.length == 5) {
			counter = dehex(parts[0]);
			key = dehex(parts[1]);
			salt = dehex(parts[2]);
			sequence = dehex(parts[3]);
			password = parts[4];
			randomA = null;
			randomB = null;
			randomX = null;
			otp = new byte[20];
		}
	}

	@Override
	public String toString() {
		return hex(counter) + "|" + hex(key) + "|" + hex(salt) + "|" + hex(sequence) + "|" + password;
	}
	
}