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

package org.symphonyoss.symphony.tools.rest.model;

import java.util.HashMap;
import java.util.Map;

import javax.annotation.Nullable;

import org.symphonyoss.symphony.tools.rest.model.osmosis.ComponentStatus;
import org.symphonyoss.symphony.tools.rest.model.osmosis.IComponent;
import org.symphonyoss.symphony.tools.rest.model.osmosis.IComponentListener;
import org.symphonyoss.symphony.tools.rest.util.typeutils.ISetter;

public class DynamicComponentContainer extends ModelObjectContainer implements IDynamicComponentContainer,
  IComponentListener
{
  public static final String TYPE_NAME = "DynamicComponentContainer";
  
  private Map<String, IModelObject>             componentMap_ = new HashMap<>();

  public DynamicComponentContainer(IModelObjectContainer parent)
  {
    super(parent, TYPE_NAME, "Dynamic Components");
  }
  
  public DynamicComponentContainer(IModelObjectContainer parent, String name)
  {
    super(parent, TYPE_NAME, name);
  }

  public DynamicComponentContainer(IModelObjectContainer parent, String typeName, String name)
  {
    super(parent, typeName, name);
  }

  @Override
  public IModelObject getComponent(String name)
  {
    return getComponent(name,
        (parent, componentName) -> new ModelObject(this, GENERIC_COMPONENT, componentName),
        null);
  }

  @Override
  public IModelObject getComponent(String name,
      IModelObjectConstructor<? extends IModelObject> constructor,
      @Nullable ISetter<IModelObject> setExisting)
  {
    while(name.startsWith("_"))
      name = name.substring(1);
    
    while(name.endsWith("_"))
      name = name.substring(0, name.length() - 1);
    
    synchronized (componentMap_)
    {
      IModelObject component = componentMap_.get(name);
      
      if(component == null)
      {
        IModelObject vmo = constructor.newInstance(this, name);
        vmo.addListener(this);
        componentMap_.put(name, vmo);
        
        addChild(vmo);
        
        return vmo;
      }
      
      setExisting.set(component);
      return component;
    }
  }

  @Override
  public void componentStatusChanged(IComponent component)
  {
    setComponentStatusIfMoreSevere(component.getComponentStatus(), component.getComponentStatusMessage());
  }
}
