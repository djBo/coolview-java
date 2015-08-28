package nl.coolview.util;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Properties;

import org.apache.log4j.Logger;

/**
 * PropertyReader Class
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
public class PropertyReader {
	private static Logger logger = Logger.getLogger(PropertyReader.class);

	private String mFilename;

	private Properties props;

	public PropertyReader(String filename) {
		mFilename = filename;
		props = new Properties();
	}

	public void load() throws FileNotFoundException, IOException {
		File mFile = new File(mFilename);
		logger.debug("Loading: " + mFile.getAbsolutePath());
		props.load(new FileInputStream(mFile));
	}

	public void save() throws FileNotFoundException, IOException {
		File mFile = new File(mFilename);
		props.store(new FileOutputStream(mFile), null);
	}

	public Boolean containsKey(String key) {
		return props.containsKey(key);
	}

	public String getProperty(String key) {
		return props.getProperty(key);
	}

	public String getProperty(String key, boolean required) throws IOException {
		if (!containsKey(key) && required) {
			throw new IOException("Property " + key + " not found");
		}
		String value = getProperty(key);
		if (value == null || value.equals("")) {
			throw new NullPointerException("Property " + key + " is empty");
		}
		return value;
	}

	public String getProperty(String key, String defaultValue) {
		String value = getProperty(key);
		if (value == null || value.equals("")) {
			return defaultValue;
		} else {
			return value;
		}
	}

	public void setProperty(String key, String value) {
		props.setProperty(key, value);
	}
}
