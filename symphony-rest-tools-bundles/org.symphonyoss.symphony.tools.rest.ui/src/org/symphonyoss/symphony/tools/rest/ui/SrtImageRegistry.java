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

package org.symphonyoss.symphony.tools.rest.ui;

import java.util.HashMap;
import java.util.Map;

import javax.inject.Inject;

import org.eclipse.jface.resource.JFaceResources;
import org.eclipse.jface.resource.LocalResourceManager;
import org.eclipse.jface.resource.ResourceManager;
import org.eclipse.swt.graphics.Image;
import org.eclipse.swt.widgets.Display;
import org.symphonyoss.symphony.tools.rest.model.osmosis.ComponentStatus;
import org.symphonyoss.symphony.tools.rest.ui.pods.ModelObjectView;

public class SrtImageRegistry
{
  private final ResourceManager                     resourceManager    = new LocalResourceManager(
      JFaceResources.getResources());
  private final Map<ComponentStatus, Image>         statusImageMap_    = new HashMap<>();
  private final Map<String, Image> objectMap_ = new HashMap<>();

  @Inject
  public SrtImageRegistry(Display display)
  {
    for(ComponentStatus status : ComponentStatus.values())
    {
      statusImageMap_.put(status, 
          resourceManager.createImage(ModelObjectView.getObjectImageDescriptor("status/" + status.toString())));
    }
  }

  public Image get(ComponentStatus status)
  {
    return statusImageMap_.get(status);
  }

  public Image getObject(String name)
  {
    if(!objectMap_.containsKey(name))
    {
      Image image = resourceManager.createImage(ModelObjectView.getObjectImageDescriptor(name));
      objectMap_.put(name, image);
      
      return image;
    }
    
    return objectMap_.get(name);
  }
}
