/*
 *
 *
 * Copyright 2017 Symphony Communication Services, LLC.
 *
 * Licensed to The Symphony Software Foundation (SSF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The SSF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.symphonyoss.symphony.tools.rest.ui.browser;

import java.net.URL;
import java.util.List;

import javax.inject.Inject;

import org.eclipse.e4.ui.model.application.MApplication;
import org.eclipse.e4.ui.model.application.ui.basic.MBasicFactory;
import org.eclipse.e4.ui.model.application.ui.basic.MPart;
import org.eclipse.e4.ui.model.application.ui.basic.MPartStack;
import org.eclipse.e4.ui.workbench.modeling.EModelService;
import org.eclipse.e4.ui.workbench.modeling.EPartService;
import org.eclipse.e4.ui.workbench.modeling.EPartService.PartState;

public class BrowserManager implements IBrowserManager
{
  private static final String PLUGIN_ID = "org.symphonyoss.symphony.tools.rest.ui";

  private static final String PART_STACK_ID = "org.symphonyoss.symphony.tools.rest.ui.partstack.work";

  @Inject
  private EPartService partService_;
  
  @Inject
  private MApplication application_;
  
  @Inject
  private EModelService modelService_;
  
  @Override
  public BrowserView createBrowser(URL url, String html)
  {
    MPart part = MBasicFactory.INSTANCE.createPart();
    
    part.setLabel("New Part " + url.getHost());
    part.setContributionURI("bundleclass://" + PLUGIN_ID + "/" + BrowserView.class.getName());
    
    List<MPartStack> stacks = modelService_.findElements(application_, PART_STACK_ID, MPartStack.class, null);
    stacks.get(0).getChildren().add(part);
    
    partService_.showPart(part, PartState.ACTIVATE);
    
    Object o = part.getObject();
    
    if(o instanceof BrowserView)
    {
      BrowserView view = (BrowserView)o;
      
      view.setUrl(url, html);
      
      return view;
    }
    
    return null;
  }
}
