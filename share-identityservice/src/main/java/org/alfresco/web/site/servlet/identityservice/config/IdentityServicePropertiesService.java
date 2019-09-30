package org.alfresco.web.site.servlet.identityservice.config;

/**
 *
 */
public class IdentityServicePropertiesService {
    /*private boolean enabled;*/
    private String realm;
    private String authServerUrl;

/*    public boolean isEnabled() {
        return enabled;
    }*/

    public String getRealm() {
        return realm;
    }

    public String getAuthServerUrl() {
        return authServerUrl;
    }

    /*public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }*/

    public void setRealm(String realm) {
        this.realm = realm;
    }

    public void setAuthServerUrl(String authServerUrl) {
        this.authServerUrl = authServerUrl;
    }
}
