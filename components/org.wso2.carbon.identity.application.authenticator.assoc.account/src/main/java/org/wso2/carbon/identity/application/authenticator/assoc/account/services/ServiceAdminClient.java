package org.wso2.carbon.identity.application.authenticator.assoc.account.services;

import java.rmi.RemoteException;

import org.apache.axis2.AxisFault;
import org.apache.axis2.client.Options;
import org.apache.axis2.client.ServiceClient;
import org.wso2.carbon.service.mgt.stub.ServiceAdminStub; 
import org.wso2.carbon.service.mgt.stub.types.carbon.ServiceMetaDataWrapper;

public class ServiceAdminClient { 
	  private final String serviceName = "ServiceAdmin"; 
	  private ServiceAdminStub serviceAdminStub; 
	  private String endPoint; 
	   
	  public ServiceAdminClient(String backEndUrl, String sessionCookie) throws AxisFault { 
	    this.endPoint = backEndUrl + "/services/" + serviceName; 
	    serviceAdminStub = new ServiceAdminStub(endPoint); 
	    //Authenticate Your stub from sessionCooke 
	    ServiceClient serviceClient; 
	    Options option; 
	   
	    serviceClient = serviceAdminStub._getServiceClient(); 
	    option = serviceClient.getOptions(); 
	    option.setManageSession(true); 
	    option.setProperty(org.apache.axis2.transport.http.HTTPConstants.COOKIE_STRING, sessionCookie); 
	  } 
	   
	  public void deleteService(String[] serviceGroup) throws RemoteException { 
	    serviceAdminStub.deleteServiceGroups(serviceGroup); 
	   
	  } 
	   
	  public ServiceMetaDataWrapper listServices() throws RemoteException { 
	    return serviceAdminStub.listServices("ALL", "*", 0); 
	  } 
	}
