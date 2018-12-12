package org.wso2.carbon.identity.application.authenticator.assoc.account.internal;

import org.wso2.carbon.identity.application.authenticator.assoc.account.AssociateAccountAuthenticator;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.wso2.carbon.identity.application.authentication.framework.ApplicationAuthenticator;
import org.wso2.carbon.user.core.service.RealmService;

import java.util.Hashtable;

/**
 * @scr.component name="org.wso2.carbon.identity.application.authenticator.assoc.account.component" immediate="true"
 * @scr.reference name="realm.service"
 * interface="org.wso2.carbon.user.core.service.RealmService"cardinality="1..1"
 * policy="dynamic" bind="setRealmService" unbind="unsetRealmService"
 */
public class AssociateAccountAuthenticatorServiceComponent {

    private static Log log = LogFactory.getLog(AssociateAccountAuthenticatorServiceComponent.class);

    private static RealmService realmService;

    protected void activate(ComponentContext ctxt) {
        try {
            Hashtable<String, String> props = new Hashtable<String, String>();

            AssociateAccountAuthenticator associateAccountAuthenticator = new AssociateAccountAuthenticator();
            ctxt.getBundleContext().registerService(ApplicationAuthenticator.class.getName(),
                                                    associateAccountAuthenticator, props);

            if (log.isInfoEnabled()) {
                log.info("Associate account authenticator is activated");
            }
        } catch (Throwable e) {
            log.fatal("Associate account authenticator error in bundle activation", e);
        }
    }

    protected void deactivate(ComponentContext ctxt) {
        if (log.isDebugEnabled()) {
            log.debug("Associate account authenticator  is deactivated");
        }
    }

    protected void setRealmService(RealmService realmService) {
        log.debug("Setting the Realm Service");
        AssociateAccountAuthenticatorServiceComponent.realmService = realmService;
    }

    protected void unsetRealmService(RealmService realmService) {
        log.debug("UnSetting the Realm Service");
        AssociateAccountAuthenticatorServiceComponent.realmService = null;
    }

    public static RealmService getRealmService() {
        return realmService;
    }
}
