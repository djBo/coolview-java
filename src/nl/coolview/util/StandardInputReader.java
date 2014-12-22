package nl.coolview.util;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import org.apache.log4j.Logger;

/**
 * StandardInputReader Class
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
public class StandardInputReader {

	private ExecutorService mExecutor;
	public StandardInputReader() {
		mExecutor = Executors.newSingleThreadExecutor();
	}

	public String readLine() throws InterruptedException {
		String result = null;
		try {
			try {
				result = mExecutor.submit(new StandardInputReadTask()).get();
			} catch (ExecutionException e) {
				e.getCause().printStackTrace();
			}
		} finally {
			//mExecutor.shutdownNow();
		}
		return result;
	}

	private static class StandardInputReadTask implements Callable<String> {
		private final static Logger logger = Logger.getLogger(StandardInputReadTask.class);

		@Override
		public String call() throws IOException {
			BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
			logger.debug("StandardInputReadTask run() called");
			String result;
			do {
				try {
					// wait until we have data to complete a readLine()
					while (!br.ready()) {
						Thread.sleep(1);
					}
					result = br.readLine();
				} catch (InterruptedException e) {
					logger.debug("StandardInputReadTask interrupted");
					return null;
				}
			} while ("".equals(result));
			logger.debug("StandardInputReadTask finished");
			return result;
		}
	}
}
