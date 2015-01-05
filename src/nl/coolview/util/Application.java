package nl.coolview.util;

import java.io.File;
import java.io.RandomAccessFile;
import java.lang.management.ManagementFactory;
import java.lang.management.RuntimeMXBean;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.nio.channels.FileLock;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogManager;

import org.apache.log4j.Logger;
import org.yajul.log.JuliToLog4jHandler;

import sun.management.VMManagement;

/**
 * Application Class
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
public class Application {
	private static Logger logger = Logger.getLogger(Application.class);

	public static Integer getProcessId() {
		Integer processId = null;
		try {
			RuntimeMXBean runtimeMXBean = ManagementFactory.getRuntimeMXBean();
			Field jvmField = runtimeMXBean.getClass().getDeclaredField("jvm");
			jvmField.setAccessible(true);
			VMManagement vmManagement = (VMManagement) jvmField.get(runtimeMXBean);
			Method getProcessIdMethod = vmManagement.getClass().getDeclaredMethod("getProcessId");
			getProcessIdMethod.setAccessible(true);
			processId = (Integer) getProcessIdMethod.invoke(vmManagement);
			logger.debug("Process ID: " + processId);
		} catch (Exception e) {
			logger.error("Unable to retrieve pid", e);
		}
		return processId;
	}

	public static final void initLogging() {
		java.util.logging.Logger rootLogger = LogManager.getLogManager().getLogger("");
		// remove old handlers
		for (Handler handler : rootLogger.getHandlers()) {
			rootLogger.removeHandler(handler);
		}
		// add our own
		Handler activeHandler = new JuliToLog4jHandler();
		activeHandler.setLevel(Level.OFF);
		rootLogger.addHandler(activeHandler);
		rootLogger.setLevel(Level.OFF);
	}

	public static boolean lockInstance(final String lockFile) {
		final File file = new File(lockFile);
		try {
			final RandomAccessFile randomAccessFile = new RandomAccessFile(file, "rw");
			final FileLock fileLock = randomAccessFile.getChannel().tryLock();
			if (fileLock != null) {
				Runtime.getRuntime().addShutdownHook(new Thread() {
					public void run() {
						try {
							fileLock.release();
							randomAccessFile.close();
							file.delete();
						} catch (Exception e) {
							logger.error("Unable to remove lock file: " + lockFile, e);
						}
					}
				});
				logger.debug("Lock acquired");
				return true;
			}
		} catch (Exception e) {
			if (file != null) {
				logger.fatal("Unable to create and/or lock file: " + file.getAbsolutePath(), e);
			} else {
				logger.fatal("Unable to create and/or lock file: " + lockFile, e);
			}
		}
		return false;
	}
}
