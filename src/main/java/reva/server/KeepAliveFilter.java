/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package reva.server;

import java.io.IOException;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * HTTP keep-alive filter to prevent premature connection termination.
 * 
 * This filter explicitly sets HTTP keep-alive headers to ensure long-lived
 * MCP sessions don't get terminated due to connection timeouts. It prevents
 * the "Session terminated" error that occurs when the server closes connections
 * before the client finishes processing.
 */
public class KeepAliveFilter implements Filter {

    /**
     * Initialize the filter (no-op)
     */
    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        // No initialization needed
    }

    /**
     * Add keep-alive headers to HTTP responses
     */
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        // Only process HTTP requests
        if (!(request instanceof HttpServletRequest) || !(response instanceof HttpServletResponse)) {
            chain.doFilter(request, response);
            return;
        }

        HttpServletResponse httpResponse = (HttpServletResponse) response;

        // Explicitly set keep-alive headers to prevent connection termination
        // Connection: keep-alive tells the client to keep the connection open
        httpResponse.setHeader("Connection", "keep-alive");
        
        // Keep-Alive header specifies timeout and max requests
        // timeout=300: keep connection alive for 5 minutes of inactivity
        // max=1000: allow up to 1000 requests on the same connection
        httpResponse.setHeader("Keep-Alive", "timeout=300, max=1000");

        // Continue with the filter chain
        chain.doFilter(request, response);
    }

    /**
     * Cleanup (no-op)
     */
    @Override
    public void destroy() {
        // No cleanup needed
    }
}
