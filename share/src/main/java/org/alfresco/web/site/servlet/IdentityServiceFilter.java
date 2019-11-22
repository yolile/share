/*
 * #%L
 * Alfresco Share WAR
 * %%
 * Copyright (C) 2005 - 2019 Alfresco Software Limited
 * %%
 * This file is part of the Alfresco software.
 * If the software was purchased under a paid Alfresco license, the terms of
 * the paid license agreement will prevail.  Otherwise, the software is
 * provided under the following open source license terms:
 *
 * Alfresco is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Alfresco is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with Alfresco. If not, see <http://www.gnu.org/licenses/>.
 * #L%
 */
package org.alfresco.web.site.servlet;

import org.alfresco.error.AlfrescoRuntimeException;
import org.alfresco.web.site.IdentityServiceFilterConfigUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpEntity;
import org.apache.http.StatusLine;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.json.JSONObject;
import org.keycloak.KeycloakSecurityContext;
import org.keycloak.adapters.servlet.KeycloakOIDCFilter;
import org.springframework.context.ApplicationContext;
import org.springframework.extensions.surf.FrameworkUtil;
import org.springframework.extensions.surf.RequestContextUtil;
import org.springframework.extensions.surf.UserFactory;
import org.springframework.extensions.surf.exception.ConnectorServiceException;
import org.springframework.extensions.surf.site.AuthenticationUtil;
import org.springframework.extensions.surf.support.AlfrescoUserFactory;
import org.springframework.extensions.webscripts.connector.*;
import org.springframework.web.context.support.WebApplicationContextUtils;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

public class IdentityServiceFilter extends KeycloakOIDCFilter
{
    private static Log logger = LogFactory.getLog(IdentityServiceFilter.class);

    private ServletContext servletContext;
    private boolean enabled;

    private Connector cachedAlfSessionConnector;
    private SlingshotLoginController loginController;

    @Override
    public void init(FilterConfig filterConfig) throws ServletException
    {
        super.init(filterConfig);

        this.servletContext = filterConfig.getServletContext();

        ApplicationContext context = this.getApplicationContext();
        IdentityServiceFilterConfigUtils identityServiceFilterConfigUtils =
            (IdentityServiceFilterConfigUtils) context.getBean("identityServiceFilterConfigUtils");

        this.enabled = identityServiceFilterConfigUtils.isIdentityServiceEnabled();
        this.loginController = (SlingshotLoginController) context.getBean("loginController");
    }

    @Override
    public void doFilter(ServletRequest sreq, ServletResponse sres, FilterChain chain) throws IOException, ServletException
    {
        HttpServletRequest req = (HttpServletRequest) sreq;
        HttpServletResponse res = (HttpServletResponse) sres;

        if (this.enabled && (!AuthenticationUtil.isAuthenticated(req) ||
            cachedAlfSessionConnector == null ||
            cachedAlfSessionConnector.getConnectorSession() == null ||
            cachedAlfSessionConnector.getConnectorSession().getParameter(AlfrescoAuthenticator.CS_PARAM_ALF_TICKET) == null))
        {
            super.doFilter(sreq, sres, chain);

            KeycloakSecurityContext context = (KeycloakSecurityContext) req.getAttribute(KeycloakSecurityContext.class.getName());

            if (context != null && !AuthenticationUtil.isAuthenticated(req))
            {
                String username = context.getToken().getPreferredUsername();
                String accessToken = context.getTokenString();

                storeToken(req, res, username, accessToken);
                exchangeTokenForAlfTicket(req, username, accessToken);
            }
        }

        chain.doFilter(sreq, sres);
    }

    private void storeToken(HttpServletRequest req, HttpServletResponse res, String username, String accessToken)
    {
        AuthenticationUtil.login(req, res, username);

        HttpSession session = req.getSession();
        session.setAttribute(UserFactory.SESSION_ATTRIBUTE_KEY_USER_ID, username);
        session.setAttribute(UserFactory.SESSION_ATTRIBUTE_EXTERNAL_AUTH, Boolean.TRUE);

        try
        {
            RequestContextUtil.initRequestContext(this.getApplicationContext(), req, true);
            this.loginController.beforeSuccess(req, res);

            CredentialVault vault = FrameworkUtil.getCredentialVault(session, username);
            Credentials credentials = vault.newCredentials(AlfrescoUserFactory.ALFRESCO_ENDPOINT_ID);
            credentials.setProperty(Credentials.CREDENTIAL_USERNAME, username);
            credentials.setProperty(Credentials.CREDENTIAL_ACCESS_TOKEN, accessToken);
            vault.store(credentials);
        }
        catch (Exception e)
        {
            if (logger.isErrorEnabled())
            {
                logger.error(e);
            }
        }
    }

    private void exchangeTokenForAlfTicket(HttpServletRequest req, String username, String accessToken)
    {
        if (cachedAlfSessionConnector == null)
        {
            try
            {
                cachedAlfSessionConnector = FrameworkUtil.getConnector(req.getSession(), username, "alfresco");
            }
            catch (ConnectorServiceException cse)
            {
                if (logger.isErrorEnabled())
                {
                    logger.error(cse);
                }
            }

            return;
        }

        String endpoint = StringUtils.removeEnd(StringUtils.removeEnd(cachedAlfSessionConnector.getEndpoint(), "/s"), "s/");
        String url = endpoint + (endpoint.endsWith("/") ? "" : "/") + "api/-default-/public/authentication/versions/1/tickets/-me-";
        HttpGet httpGet = new HttpGet(url);
        httpGet.setHeader("Authorization", "Bearer " + accessToken);

        try
        {
            try (CloseableHttpClient httpclient = HttpClients.createDefault())
            {
                try (CloseableHttpResponse response = httpclient.execute(httpGet))
                {
                    StatusLine statusLine = response.getStatusLine();

                    if (statusLine == null)
                    {
                        if (logger.isErrorEnabled())
                        {
                            logger.error("Request method " + httpGet.getMethod() + " on URL " + url + " returned no status.");
                        }

                        return;
                    }

                    HttpEntity resEntity = response.getEntity();

                    if (resEntity != null)
                    {
                        int statusCode = statusLine.getStatusCode();

                        if (statusCode == 200)
                        {
                            try
                            {
                                String content = EntityUtils.toString(resEntity);
                                JSONObject json = new JSONObject(content);
                                String alfTicket = json.getJSONObject("entry").getString("id");

                                cachedAlfSessionConnector.getConnectorSession().setParameter(AlfrescoAuthenticator.CS_PARAM_ALF_TICKET, alfTicket);

                                EntityUtils.consume(resEntity);
                            }
                            catch (IOException e)
                            {
                                if (logger.isErrorEnabled())
                                {
                                    logger.error("Failed to read the returned content from "+ resEntity + " on " + url, e);
                                }
                            }
                        }
                        else
                        {
                            if (logger.isErrorEnabled())
                            {
                                logger.error("Request method " + httpGet.getMethod() + " on URL " + url + " returned status " + statusCode);
                            }
                        }
                    }
                    else
                    {
                        if (logger.isErrorEnabled())
                        {
                            logger.error("Request method " + httpGet.getMethod() + " on URL " + url + " din not return an entity.");
                        }
                    }
                }
                catch (IOException e)
                {
                    if (logger.isErrorEnabled())
                    {
                        logger.error("Failed to connect or to read the response from " + url + " using method " + httpGet.getMethod() , e);
                    }
                }
            }
            catch (IOException e)
            {
                if (logger.isErrorEnabled())
                {
                    logger.error("Failed to create an HttpClient for " + url + " using method " + httpGet.getMethod(), e);
                }
            }
        }
        catch (AlfrescoRuntimeException e)
        {
            if (logger.isErrorEnabled())
            {
                logger.error(e);
            }
        }
    }

    private ApplicationContext getApplicationContext()
    {
        return WebApplicationContextUtils.getRequiredWebApplicationContext(this.servletContext);
    }
}
