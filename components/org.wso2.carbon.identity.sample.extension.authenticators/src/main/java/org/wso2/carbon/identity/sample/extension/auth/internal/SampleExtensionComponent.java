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

package org.wso2.carbon.identity.sample.extension.auth.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.wso2.carbon.identity.application.authentication.framework.ApplicationAuthenticator;
import org.wso2.carbon.identity.sample.extension.auth.SampleErrorAuthenticator;
import org.wso2.carbon.identity.sample.extension.auth.SampleFingerprintAuthenticator;
import org.wso2.carbon.identity.sample.extension.auth.SampleHardwareKeyAuthenticator;
import org.wso2.carbon.identity.sample.extension.auth.SampleRetinaAuthenticator;

/**
 * @scr.component name="identity.sample.auth.extension.component" immediate="true"
 */
public class SampleExtensionComponent {

    private static Log log = LogFactory.getLog(SampleExtensionComponent.class);

    /**
     * @param ctxt
     */
    protected void activate(ComponentContext ctxt) {
        log.info("The Sample Authenticator extension is activated."
                + " Identity server will use this extension instead of the one provided by Carbon framework");

        SampleHardwareKeyAuthenticator sampleHardwareKeyAuthenticator = new SampleHardwareKeyAuthenticator();
        SampleFingerprintAuthenticator sampleFingerprintAuthenticator = new SampleFingerprintAuthenticator();
        SampleRetinaAuthenticator retinaAuthenticator = new SampleRetinaAuthenticator();
        SampleErrorAuthenticator sampleErrorAuthenticator = new SampleErrorAuthenticator();
        ctxt.getBundleContext()
                .registerService(ApplicationAuthenticator.class.getName(), sampleHardwareKeyAuthenticator, null);
        ctxt.getBundleContext()
                .registerService(ApplicationAuthenticator.class.getName(), sampleFingerprintAuthenticator, null);
        ctxt.getBundleContext()
                .registerService(ApplicationAuthenticator.class.getName(), retinaAuthenticator, null);
        ctxt.getBundleContext().registerService(ApplicationAuthenticator.class.getName(), sampleErrorAuthenticator,
                null);
    }

    /**
     * @param ctxt
     */
    protected void deactivate(ComponentContext ctxt) {
        log.info("The Sample Key Store extension is de-activated."
                + " Identity server will use the one provided by Carbon framework hereafter");
    }

}
