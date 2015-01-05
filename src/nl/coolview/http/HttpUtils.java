package nl.coolview.http;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletResponse;

/**
 * HttpUtils Class
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
public class HttpUtils {
	//private static Logger logger = Logger.getLogger(HttpUtils.class);

	private HttpUtils(){}

	public static Map<String, String> parseQueryParameters(String uri) {
		Map<String, String> result = new HashMap<String, String>();

		if (uri == null || uri.equals("")) return result;
		
		// Fetch all query parameters from the uri
		String queryString = uri.substring(uri.indexOf('?') + 1);
		//logger.debug("Parameters: " + queryString);

		// Split each item using '&' as delimiter
		String[] params = queryString.split("&");
		for (String param : params) {
			//logger.debug("Parameter: " + param);
			String key = param.substring(0, param.indexOf("="));
			String val = param.substring(param.indexOf("=") + 1);
			//logger.debug("Key: " + key + ", Val: " + val);
			result.put(key, val);
		}
		return result;
	}

	public static String htmlException(Exception e) {
		StringBuffer sb = new StringBuffer();
		sb.append("<pre>" + e.getClass().getName() + ": ");
		sb.append(e.toString() + "\r\n");
		for (StackTraceElement element : e.getStackTrace()) {
			sb.append("\tat " + element.toString() + "\r\n");
		}
		sb.append("</pre>");
		return sb.toString();
	}

	public static void respondWith400(HttpServletResponse response) throws IOException {
		response.setContentType("text/html");
		response.setCharacterEncoding("UTF-8");
		response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
		response.getWriter().write("<html><body><h1>400 Bad Request</h1></body></html>");
	}

	/*
	public static void respondWith403(HttpResponse response) {
		response.setStatusCode(HttpStatus.SC_FORBIDDEN);
		StringEntity entity = new StringEntity("<html><body><h1>403 Forbidden</h1></body></html>", ContentType.create("text/html", "UTF-8"));
		response.setEntity(entity);
	}

	public static void respondWith404(HttpResponse response) {
		response.setStatusCode(HttpStatus.SC_NOT_FOUND);
		StringEntity entity = new StringEntity("<html><body><h1>404 Not Found</h1></body></html>", ContentType.create("text/html", "UTF-8"));
		response.setEntity(entity);
	}

	public static void respondWith405(HttpResponse response) {
		response.setStatusCode(HttpStatus.SC_METHOD_NOT_ALLOWED);
		StringEntity entity = new StringEntity("<html><body><h1>405 Method Not Allowed</h1></body></html>", ContentType.create("text/html", "UTF-8"));
		response.setEntity(entity);
	}

	public static void respondWith500(HttpResponse response) {
		respondWith500(response, null);
	}

	public static void respondWith500(HttpResponse response, String message) {
		response.setStatusCode(HttpStatus.SC_INTERNAL_SERVER_ERROR);
		StringEntity entity = new StringEntity("<html><body><h1>500 Internal Server Error</h1>" + (message != null && !message.equals("") ? "<pre>" + message + "</pre>" : "") + "</body></html>", ContentType.create("text/html", "UTF-8"));
		response.setEntity(entity);
	}
	 */
}
