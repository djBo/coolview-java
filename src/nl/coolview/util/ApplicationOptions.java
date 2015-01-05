package nl.coolview.util;

import java.io.FileNotFoundException;
import java.io.IOException;

import org.apache.log4j.Logger;

/**
 * ApplicationOptions Interface
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
public interface ApplicationOptions {

	public String getConfigurationFile();
	public void load() throws FileNotFoundException, IOException;
	public void save() throws FileNotFoundException, IOException;

	public abstract class AbstractApplicationOptions implements ApplicationOptions {
		private static Logger logger = Logger.getLogger(AbstractApplicationOptions.class);

		protected final PropertyReader props;

		public AbstractApplicationOptions() {
			props = new PropertyReader(getConfigurationFile());
		}

		@Override
		public void load() throws FileNotFoundException, IOException {
			try {
				props.load();
			} catch (FileNotFoundException e) {
				logger.error(e);
				throw e;
			} catch (IOException e) {
				logger.error(e);
				throw e;
			}
		}
		
		@Override
		public void save() throws FileNotFoundException, IOException {
			try {
				props.save();
			} catch (FileNotFoundException e) {
				logger.error(e);
				throw e;
			} catch (IOException e) {
				logger.error(e);
				throw e;
			}
		}
	}
}
