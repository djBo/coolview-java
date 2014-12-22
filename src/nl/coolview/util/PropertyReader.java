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

	public String getProperty(String key, Boolean required) throws IOException {
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
