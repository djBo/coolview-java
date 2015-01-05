package nl.coolview.servlet;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import nl.coolview.http.HttpUtils;

/**
 * AbstractServlet Class
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
public class AbstractServlet extends HttpServlet {
	private static final long serialVersionUID = 1L;

	private String mEncoding;
	private byte[] mContent;
	private String mContentType;
	private Map<String, String> mParams;

	public String getContent() {
		if (mEncoding == null || mEncoding.equals("")) mEncoding = "UTF-8";
		Charset cs = Charset.isSupported(mEncoding) ? Charset.forName(mEncoding) : Charset.defaultCharset();
		return new String(mContent, cs);
	}

	public String getContentType() {
		return mContentType;
	}
	
	public String getParameter(String name) {
		return mParams.get(name);
	}

	/**
	 * This method gets called first, and is responsible for retrieving the body of the request
	 */
	@Override
	public void service(ServletRequest request, ServletResponse response) throws ServletException, IOException {
		Integer l = request.getContentLength();
		if (l < 0) l = 0;
	    byte[] data = new byte[l];
	    int c = 0, t = 0;
	    try ( InputStream is = request.getInputStream(); ) {
	    	while (t < data.length) {
	    		t += (c = is.read(data, t, data.length - t));
	    		if (c < 1)
	    			throw new IOException("Cannot read more than " + t + (t == 1 ? " byte!" : " bytes!"));
	    	}
	    }
	    mContent = data;
	    mEncoding = request.getCharacterEncoding();
		super.service(request, response);
	}

	/**
	 * This method gets called after the former, and is responsible for retrieving the query parameters
	 */
	@Override
	protected void service(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		String s = request.getQueryString();
		if (s == null) s = "";
		mParams = HttpUtils.parseQueryParameters(s);
		
		mContentType = request.getContentType();
		if (mContentType == null) mContentType = "";
		if (mContentType.startsWith("application/x-www-form-urlencoded")) {
			mParams.putAll(HttpUtils.parseQueryParameters(getContent()));
		}
		super.service(request, response);
	}

	

}