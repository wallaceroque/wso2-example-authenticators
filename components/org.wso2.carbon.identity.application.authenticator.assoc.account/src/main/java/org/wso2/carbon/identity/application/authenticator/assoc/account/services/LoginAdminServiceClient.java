package org.wso2.carbon.identity.application.authenticator.assoc.account.services;

import java.rmi.RemoteException;

import org.apache.axis2.AxisFault;
import org.apache.axis2.context.ServiceContext;
import org.apache.axis2.transport.http.HTTPConstants;
import org.wso2.carbon.authenticator.stub.AuthenticationAdminStub;
import org.wso2.carbon.authenticator.stub.LoginAuthenticationExceptionException;
import org.wso2.carbon.authenticator.stub.LogoutAuthenticationExceptionException;

public class LoginAdminServiceClient { 
	  private final String serviceName = "AuthenticationAdmin"; 
	    private AuthenticationAdminStub authenticationAdminStub; 
	    private String endPoint; 
	   
	    public LoginAdminServiceClient(String backEndUrl) throws AxisFault { 
	      this.endPoint = backEndUrl + "/services/" + serviceName; 
	      authenticationAdminStub = new AuthenticationAdminStub(endPoint); 
	    } 
	   
	    public String authenticate(String userName, String password) throws RemoteException, 
	                                      LoginAuthenticationExceptionException { 
	   
	      String sessionCookie = null; 
	   
	      if (authenticationAdminStub.login(userName, password, "localhost")) { 
	        System.out.println("Login Successful"); 
	   
	        ServiceContext serviceContext = authenticationAdminStub. 
	            _getServiceClient().getLastOperationContext().getServiceContext(); 
	        sessionCookie = (String) serviceContext.getProperty(HTTPConstants.COOKIE_STRING); 
	        System.out.println(sessionCookie); 
	      } 
	   
	      return sessionCookie; 
	    } 
	   
	    public void logOut() throws RemoteException, LogoutAuthenticationExceptionException { 
	      authenticationAdminStub.logout(); 
	    } 
	}