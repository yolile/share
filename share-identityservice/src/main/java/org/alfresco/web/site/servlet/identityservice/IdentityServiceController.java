package org.alfresco.web.site.servlet.identityservice;

import org.alfresco.web.site.servlet.SlingshotLoginController;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/*import org.keycloak.KeycloakSecurityContext;*/


public class IdentityServiceController extends SlingshotLoginController {

    @Override
    public ModelAndView handleRequestInternal(HttpServletRequest request, HttpServletResponse response) throws Exception {
        return super.handleRequestInternal(request, response);
    }

    @Override
    public ModelAndView handleRequest(HttpServletRequest request, HttpServletResponse response) throws Exception {

/*        KeycloakSecurityContext context = (KeycloakSecurityContext) request.getAttribute(KeycloakSecurityContext.class.getName());
        if (context != null)
        {
            String username = context.getToken().getPreferredUsername();
            String accessToken = context.getTokenString();
        }*/

        return super.handleRequest(request, response);
    }
}
