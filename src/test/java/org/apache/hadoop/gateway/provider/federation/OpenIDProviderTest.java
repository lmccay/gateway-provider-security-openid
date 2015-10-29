/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.hadoop.gateway.provider.federation;

import org.apache.hadoop.gateway.openid.filter.OIDCFilter;
import org.easymock.EasyMock;
import org.easymock.IMocksControl;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.security.AccessController;
import java.security.Principal;
import javax.security.auth.Subject;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import junit.framework.TestCase;

/**
 * Tests for PseudoAuth Federation Provider.
 */
public class OpenIDProviderTest extends TestCase {

  private IMocksControl control;
  private HttpServletRequest request;
  private HttpServletResponse response;
  private HttpSession session;
  private FilterChain chain;
  private FilterConfig config;
  private OIDCFilter filter;

  @Before
  public void setUp() throws Exception {
    control = EasyMock.createNiceControl();
    request = EasyMock.createNiceMock(HttpServletRequest.class);
    response = control.createMock(HttpServletResponse.class);
    session = control.createMock(HttpSession.class);
    chain = new MockFilterChain();
    config = control.createMock(FilterConfig.class);
    filter = new OIDCFilter();
    
    EasyMock.expect(config.getInitParameter("ClientId")).andReturn("OPENID-TEST");
    EasyMock.expect(config.getInitParameter("ClientSecret")).andReturn("kjsdhfjkhdsfhjk");
    EasyMock.expect(config.getInitParameter("AuthorizeEndpoint")).andReturn("http://localhost");
    EasyMock.expect(config.getInitParameter("TokenEndpoint")).andReturn("http://localhost");
    
    EasyMock.expect(request.getRequestURL()).andReturn(new StringBuffer("http://localhost")).anyTimes();
    EasyMock.expect(request.getSession()).andReturn(session);
    EasyMock.expect(request.getQueryString()).andReturn("").anyTimes();
    // /* expect */ request.setAttribute(EasyMock.eq("oidcState"), EasyMock.captureString());
    // EasyMock.expectLastCall();
    // EasyMock.replay(request);
    chain.doFilter(request, response);
  }

  @Test
  public void testFederatedIdentity() throws Exception {
    control.replay();

    filter.init(config);
    filter.doFilter(request, response, chain);
    control.verify();
  }

  private class MockFilterChain implements FilterChain {
    /* (non-Javadoc)
     * @see javax.servlet.FilterChain#doFilter(javax.servlet.ServletRequest, javax.servlet.ServletResponse)
     */
    @Override
    public void doFilter(ServletRequest request, ServletResponse response)
        throws IOException, ServletException {
      Subject subject = Subject.getSubject(AccessController.getContext());
      if (subject != null) {
        System.out.println("non-null subject");
        assertTrue(subject.getPrincipals().size() == 1);
        assertTrue("Expected subject not found.", 
          ((Principal) subject.getPrincipals().toArray()[0]).getName().equals("guest"));
      }
      else {
        System.out.println("null subject");
      }
    }
  }
  
}
