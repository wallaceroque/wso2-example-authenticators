/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.sample.extension.auth;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.LogoutFailedException;
import org.wso2.carbon.identity.application.common.model.Property;

import java.util.ArrayList;
import java.util.List;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Retina.
 */
public class SampleRetinaAuthenticator extends AbstractSampleAuthenticator {

    private static final long serialVersionUID = 6439291340285653402L;
    private static final String APP_URL = "RetinaAppUrl";

    private static final Log log = LogFactory.getLog(SampleRetinaAuthenticator.class);

    @Override
    public boolean canHandle(HttpServletRequest request) {
        return true;
    }

    @Override
    public AuthenticatorFlowStatus process(HttpServletRequest request, HttpServletResponse response,
                                           AuthenticationContext context) throws AuthenticationFailedException,
            LogoutFailedException {
        String status = request.getParameter("status");

        if ("fail".equals(status)) {
            return AuthenticatorFlowStatus.FAIL_COMPLETED;
        }
        if ("fallback".equals(status)) {
            return AuthenticatorFlowStatus.FALLBACK;
        }
        return super.process(request, response, context);
    }

    @Override
    protected String getPageUrlProperty() {
        return APP_URL;
    }

    @Override
    public String getContextIdentifier(HttpServletRequest request) {
        String identifier = request.getParameter("sessionDataKey");
        return identifier;
    }

    @Override
    public String getName() {
        return "SampleRetinaAuthenticator";
    }

    @Override
    public String getFriendlyName() {
        return "Sample Retina Authenticator";
    }

    @Override
    public String getClaimDialectURI() {
        return null;
    }

    @Override
    public List<Property> getConfigurationProperties() {
        List<Property> configProperties = new ArrayList<>();

        Property appUrl = new Property();
        appUrl.setName(APP_URL);
        appUrl.setDisplayName("Retuna Sample URL");
        appUrl.setRequired(true);
        appUrl.setDescription("Enter sample Retina url value.");
        appUrl.setDisplayOrder(0);
        configProperties.add(appUrl);
        return configProperties;
    }
}
