package org.alfresco.components.identityservice.guest;

import java.util.HashMap;

import org.alfresco.web.site.servlet.identityservice.config.IdentityServicePropertiesService;
import org.springframework.extensions.config.ConfigService;
import org.springframework.extensions.webscripts.Cache;
import org.springframework.extensions.webscripts.DeclarativeWebScript;
import org.springframework.extensions.webscripts.Status;
import org.springframework.extensions.webscripts.WebScriptRequest;

import java.util.Map;

public class LoginUrlGet extends DeclarativeWebScript {

    protected IdentityServicePropertiesService identityServicePropertiesService;

    public void setIdentityServicePropertiesService(IdentityServicePropertiesService identityServicePropertiesService) {
        this.identityServicePropertiesService = identityServicePropertiesService;
    }

    @Override
    protected Map<String, Object> executeImpl(WebScriptRequest req, Status status, Cache cache) {
        Map<String, Object> model = new HashMap<String, Object>();

        String url = identityServicePropertiesService.getAuthServerUrl();

        /*String url = "http://localhost:8082/auth/" +
                "realms/alfresco/protocol/openid-connect/auth?" +
                "response_type=code&" +
                "client_id=alfresco&" +
                "login=true&" +
                "scope=openid";*/

        model.put("loginUrl", url);

        return model;
    }
}
