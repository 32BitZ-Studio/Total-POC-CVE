/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.myfaces.cdi.view;

import jakarta.enterprise.inject.spi.BeanManager;
import jakarta.faces.component.UIViewRoot;
import jakarta.faces.context.FacesContext;
import jakarta.faces.event.AbortProcessingException;
import jakarta.faces.event.SystemEvent;
import jakarta.faces.event.ViewMapListener;
import org.apache.myfaces.cdi.util.CDIUtils;
import org.apache.myfaces.util.ExternalSpecifications;
import org.apache.myfaces.util.lang.Lazy;

public class ViewScopeEventListener implements ViewMapListener
{
    private Lazy<ViewScopeEventListenerBridge> bridge = new Lazy<>(() ->
    {
        FacesContext facesContext = FacesContext.getCurrentInstance();
        if (ExternalSpecifications.isCDIAvailable(facesContext.getExternalContext()))
        {
            BeanManager beanManager = CDIUtils.getBeanManager(facesContext);
            return CDIUtils.get(beanManager, ViewScopeEventListenerBridge.class);
        }
        return null;
    });

    @Override
    public boolean isListenerForSource(Object source)
    {
        return source instanceof UIViewRoot;
    }

    @Override
    public void processEvent(SystemEvent event) throws AbortProcessingException
    {
        if (bridge.get() != null)
        {
            bridge.get().processEvent(event);
        }
    }
}
