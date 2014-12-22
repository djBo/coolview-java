package org.eclipse.jetty.http;

import java.io.IOException;
import java.lang.reflect.Field;
import java.net.Socket;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.eclipse.jetty.io.EndPoint;
import org.eclipse.jetty.server.AbstractHttpConnection;
import org.eclipse.jetty.server.AsyncContinuation;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.Response;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.util.URIUtil;
import org.eclipse.jetty.util.log.Log;
import org.eclipse.jetty.util.log.Logger;

public class HttpServer extends Server {

	private static final Logger LOG = Log.getLogger(HttpServer.class);

	private Socket getCurrentSocket(EndPoint p) {
		Socket result = null;
		try {
			Field f = getDeclaredField(p.getClass(), "_socket");
			f.setAccessible(true);
			result = (Socket) f.get(p);
		} catch (Exception e) {
			LOG.warn("Unable to get handle for current socket");
		}
		return result;
	}

	private Field getDeclaredField(Class<?> c, String name) {
		Field result = null;
		try {
			result = c.getDeclaredField(name);
		} catch (NoSuchFieldException e) {
			if (c.getSuperclass() != null) {
				return getDeclaredField(c.getSuperclass(), name);
			}
		}
		return result;
	}

	@Override
	public void handle(AbstractHttpConnection connection) throws IOException, ServletException {
		final String target = connection.getRequest().getPathInfo();
		final Request request = connection.getRequest();
		final Response response = connection.getResponse();

		Socket socket = getCurrentSocket(connection.getEndPoint());
		if (socket != null) request.setAttribute("socket", socket);

		if (LOG.isDebugEnabled()) {
			LOG.debug("REQUEST " + target + " on " + connection);
			handle(target, request, request, response);
			LOG.debug("RESPONSE " + target + "  " + connection.getResponse().getStatus()+ " handled=" + request.isHandled());
		} else
			handle(target, request, request, response);
	}

	@Override
	public void handleAsync(AbstractHttpConnection connection) throws IOException, ServletException {
		final AsyncContinuation async = connection.getRequest().getAsyncContinuation();
		final AsyncContinuation.AsyncEventState state = async.getAsyncEventState();

		final Request baseRequest = connection.getRequest();
		final String path = state.getPath();

		if (path != null) {
			// this is a dispatch with a path
			final String contextPath = state.getServletContext().getContextPath();
			HttpURI uri = new HttpURI(URIUtil.addPaths(contextPath,path));
			baseRequest.setUri(uri);
			baseRequest.setRequestURI(null);
			baseRequest.setPathInfo(baseRequest.getRequestURI());
			if (uri.getQuery() != null)
				baseRequest.mergeQueryString(uri.getQuery()); //we have to assume dispatch path and query are UTF8
		}

		final String target = baseRequest.getPathInfo();
		final HttpServletRequest request = (HttpServletRequest) async.getRequest();
		final HttpServletResponse response = (HttpServletResponse) async.getResponse();

		Socket socket = getCurrentSocket(connection.getEndPoint());
		if (socket != null) request.setAttribute("socket", socket);

		if (LOG.isDebugEnabled()) {
			LOG.debug("REQUEST " + target + " on " + connection);
			handle(target, baseRequest, request, response);
			LOG.debug("RESPONSE " + target + "  " + connection.getResponse().getStatus());
		} else
			handle(target, baseRequest, request, response);
	}

}
