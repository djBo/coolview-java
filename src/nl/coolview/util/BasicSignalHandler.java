package nl.coolview.util;

import org.apache.log4j.Logger;

import sun.misc.Signal;
import sun.misc.SignalHandler;

/**
 * BasicSignalHandler Class
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
public class BasicSignalHandler implements SignalHandler {
	private static Logger logger = Logger.getLogger(BasicSignalHandler.class);

	private SignalHandler oldHandler;

	// Static method to install the signal handler
	public static BasicSignalHandler install(String signalName) {
		Signal diagSignal = new Signal(signalName);
		BasicSignalHandler diagHandler = new BasicSignalHandler();
		diagHandler.oldHandler = Signal.handle(diagSignal, diagHandler);
		logger.debug("Installed signal handler for " + signalName);
		return diagHandler;
	}

	@Override
	public void handle(Signal sig) {
		logger.debug("Handler called for: " + sig);
		try {
			// Output information for each thread
			Thread[] threadArray = new Thread[Thread.activeCount()];
			int numThreads = Thread.enumerate(threadArray);
			logger.debug("Current threads:");
			for (int i = 0; i < numThreads; i++) {
				logger.debug("\t" + threadArray[i]);
			}

			// Chain back to previous handler, if one exists
			if ( oldHandler != SIG_DFL && oldHandler != SIG_IGN ) {
				oldHandler.handle(sig);
			}

		} catch (Exception e) {
			logger.error("Handler exception:", e);
		}
	}

}
