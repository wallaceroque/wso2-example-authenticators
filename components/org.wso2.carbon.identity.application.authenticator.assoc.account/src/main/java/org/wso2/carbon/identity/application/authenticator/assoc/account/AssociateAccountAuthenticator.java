package org.wso2.carbon.identity.application.authenticator.assoc.account;

import java.io.IOException;
import java.util.Map;

import javax.servlet	.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.LocalApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.LogoutFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedIdPData;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.authenticator.assoc.account.internal.AssociateAccountAuthenticatorServiceComponent;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.user.profile.mgt.AssociatedAccountDTO;
import org.wso2.carbon.identity.user.profile.mgt.UserProfileAdmin;
import org.wso2.carbon.identity.user.profile.mgt.UserProfileException;
import org.wso2.carbon.ui.util.CharacterEncoder;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

/**
 *This can be used to link user local account with any other federated accounts
 */
public class AssociateAccountAuthenticator extends AbstractApplicationAuthenticator
        implements LocalApplicationAuthenticator {

    private static final long serialVersionUID = -8204990058450262900L;
    private static final String LOGIN_PAGE = "/authenticationendpoint/login.jsp";
    private static final String USERNAME = "username";
    private static final String PASSWORD = "password";

    private static Log log = LogFactory.getLog(AssociateAccountAuthenticator.class);

    @Override
    public AuthenticatorFlowStatus process(HttpServletRequest request, HttpServletResponse response,
                                           AuthenticationContext context)
            throws AuthenticationFailedException, LogoutFailedException {

        if (context.isLogoutRequest()) {
            return AuthenticatorFlowStatus.SUCCESS_COMPLETED;
        }
        //todo: need to get through OSGI service later
        UserProfileAdmin userProfileAdmin = new UserProfileAdmin();
        String localUsername = null;
        try {
            localUsername =
                    userProfileAdmin.getNameAssociatedWith(getAuthenticatedIDP(context), getAuthenticatedUser(context).getUserName());
        } catch (UserProfileException e) {
            throw new AuthenticationFailedException("Error occurred while retrieving associated accounts", e);
        }
        if(localUsername!=null){
            context.setSubject(getAuthenticatedUser(context));
            return  AuthenticatorFlowStatus.SUCCESS_COMPLETED;
        }
        String username = CharacterEncoder.getSafeText(request.getParameter(USERNAME));
        char password[] = null;
        if (request.getParameter(PASSWORD) != null) {
            password = CharacterEncoder.getSafeText(request.getParameter(PASSWORD)).toCharArray();
        }
        if (username != null && password != null) {
            processAuthenticationResponse(request,response,context);
            return  AuthenticatorFlowStatus.SUCCESS_COMPLETED;
        }
        return super.process(request, response, context);
    }

    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context) throws AuthenticationFailedException {

        if (log.isDebugEnabled()) {
            log.debug("Associate authenticator initiating the authentication request.");
        }

        String queryParams = FrameworkUtils.getQueryStringWithFrameworkContextId(
                context.getQueryParams(), context.getCallerSessionKey(),
                context.getContextIdentifier());
        try {
            String retryParam = "";


            if (context.isRetrying()) {
                retryParam = "&authFailure=true&authFailureMsg=login.fail.message";
            }

            //redirect user to login page
            response.sendRedirect(response.encodeRedirectURL(
                    LOGIN_PAGE + "?" + queryParams + "&authenticators=" + getName() + ":" +
                    FrameworkConstants.LOCAL_IDP_NAME + retryParam));

        } catch (IOException e) {
            throw new AuthenticationFailedException("Error occurred while redirecting request", e);
        }
    }

    /**
     * @param request
     * @return always return true because this step does not have any other authenticator
     */
    public boolean canHandle(HttpServletRequest request) {

        if (log.isDebugEnabled()) {
            log.debug("Associate account authenticator picked the request to handle.");
        }
        return true;
    }

    public String getContextIdentifier(HttpServletRequest request) {
        return request.getParameter("sessionDataKey");
    }

    public String getFriendlyName() {
        return "assoc-account";
    }

    public String getName() {
        return "Assoc_Account_Authenticator";
    }

    @Override
    protected void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context) throws AuthenticationFailedException {

        if (log.isDebugEnabled()) {
            log.debug("AssociateAccountAuthenticator processed the response.");
        }
        String username = CharacterEncoder.getSafeText(request.getParameter(USERNAME));
        char password[] = null;
        if (request.getParameter(PASSWORD) != null) {
            password = CharacterEncoder.getSafeText(request.getParameter(PASSWORD)).toCharArray();
        }
        if (username != null && password != null) {

            AuthenticatedUser authenticatedUser = getAuthenticatedUser(context);

            try {
                if (!isAuthenticated(username, password)) {
                    context.setRetrying(true);
                    context.setCurrentAuthenticator(getName());
                    initiateAuthenticationRequest(request, response, context);
                }

                //todo: need to get through OSGI service
                UserProfileAdmin userProfileAdmin = new UserProfileAdmin();
                PrivilegedCarbonContext.getThreadLocalCarbonContext().setUsername(username);

                //associate current authenticated federated account with local account
                userProfileAdmin.associateID(getAuthenticatedIDP(context), getAuthenticatedUser(context).getUserName());
                
                context.setSubject(getAuthenticatedUser(context));
            } catch (UserProfileException e) {
                throw new AuthenticationFailedException("User Association Fails", e);
            } catch (IdentityException e) {
                throw new AuthenticationFailedException("Error occurred while getting tenant ID from username", e);
            } catch (org.wso2.carbon.user.api.UserStoreException e) {
                throw new AuthenticationFailedException("Something went wrong while authenticating user", e);
            }
        }
    }

        /**
         * get authenticated user from Authentication context
         *
         * @param context
         * @return
         * @throws AuthenticationFailedException
         */

    private AuthenticatedUser getAuthenticatedUser(AuthenticationContext context)
            throws AuthenticationFailedException {

        Map<String, AuthenticatedIdPData> currentAuthenticatedIDPs = context.getCurrentAuthenticatedIdPs();
        if (currentAuthenticatedIDPs.isEmpty()) {
            throw new AuthenticationFailedException("No Authenticated IDP in AuthenticationContext");
        }
        Map.Entry<String, AuthenticatedIdPData> firstIDP =
                currentAuthenticatedIDPs.entrySet().iterator().next();
        AuthenticatedUser authenticatedUsername = firstIDP.getValue().getUser();
        if (log.isDebugEnabled()) {
            log.debug("authenticated user: " + authenticatedUsername);
        }
        if (authenticatedUsername == null) {
            throw new AuthenticationFailedException(
                    "Cannot retrieve authenticated username from AuthenticationContext");
        }
        return authenticatedUsername;
    }

    /**
     * get authenticated IDP from authentication context
     *
     * @param context
     * @return
     * @throws AuthenticationFailedException
     */
    private String getAuthenticatedIDP(AuthenticationContext context)
            throws AuthenticationFailedException {

        Map<String, AuthenticatedIdPData> currentAuthenticatedIDPs = context.getCurrentAuthenticatedIdPs();
        if (currentAuthenticatedIDPs.isEmpty()) {
            throw new AuthenticationFailedException("No Authenticated IDP in AuthenticationContext");
        }
        Map.Entry<String, AuthenticatedIdPData> firstIDP =
                currentAuthenticatedIDPs.entrySet().iterator().next();
        String authenticatedIdpName = firstIDP.getValue().getIdpName();
        if (log.isDebugEnabled()) {
            log.debug("authenticated user: " + authenticatedIdpName);
        }
        if (authenticatedIdpName == null) {
            throw new AuthenticationFailedException(
                    "Cannot retrieve authenticated IDP from AuthenticationContext");
        }
        return authenticatedIdpName;
    }

    /**
     * check local user authenticity
     *
     * @param username
     * @param password
     * @return
     * @throws AuthenticationFailedException
     * @throws org.wso2.carbon.user.api.UserStoreException
     * @throws IdentityException
     */
    private boolean isAuthenticated(String username, char password[]) throws AuthenticationFailedException,
                                                                             org.wso2.carbon.user.api.UserStoreException,
                                                                             IdentityException {
        boolean isAuthenticated = false;
        UserStoreManager userStoreManager;
        int tenantId = MultitenantConstants.SUPER_TENANT_ID;
        
        String tenantDomain = MultitenantUtils.getTenantDomain(username);
        tenantId = IdentityTenantUtil.getRealmService().getTenantManager().getTenantId(tenantDomain);

        UserRealm userRealm =
                AssociateAccountAuthenticatorServiceComponent.getRealmService().getTenantUserRealm(
                        tenantId);

        if (userRealm != null) {
            userStoreManager = (UserStoreManager) userRealm.getUserStoreManager();
            isAuthenticated = userStoreManager
                    .authenticate(MultitenantUtils.getTenantAwareUsername(username), new String(password));
        } else {
            throw new AuthenticationFailedException(
                    "Cannot find the user realm for the given tenant: " + tenantId);
        }
        if (!isAuthenticated) {
            if (log.isDebugEnabled()) {
                log.debug("user authentication failed due to invalid credentials.");
            }
        }
        return isAuthenticated;
    }

    private String getAssociatedAccounts(String localUsername) throws UserProfileException {
        //todo: need to get through OSGI service later
        UserProfileAdmin userProfileAdmin = new UserProfileAdmin();
        //String associatedAccounts[] = userProfileAdmin.getAssociatedIDs(localUsername);
        AssociatedAccountDTO[] associatedAccounts = userProfileAdmin.getAssociatedIDs();
        StringBuilder userIDs = new StringBuilder();
        for (int i = 0; i < associatedAccounts.length; i++) {
            // Building user list query params which needs to display on select page
            userIDs.append("&userid=" + associatedAccounts[i].getIdentityProviderName() + "/" + associatedAccounts[i].getUsername());
        }
        return userIDs.toString();
    }

}