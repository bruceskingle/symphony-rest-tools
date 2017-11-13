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

package org.symphonyoss.symphony.tools.rest.ui.selection;

import java.util.HashMap;
import java.util.Map;

import org.symphonyoss.symphony.tools.rest.ISrtSelectable;
import org.symphonyoss.symphony.tools.rest.model.IModelObject;
import org.symphonyoss.symphony.tools.rest.util.ProgramFault;
import org.symphonyoss.symphony.tools.rest.util.command.Flag;
import org.symphonyoss.symphony.tools.rest.util.home.SrtCommandLineHome;

public class SrtSelectionService implements ISrtSelectionService
{
  private Map<Class<?>, Object>   selectionMap_ = new HashMap();
  
  @Override
  public synchronized <T extends IModelObject> void setSelection(Class<T> type, T selection)
  {
    if(selection == null)
      selectionMap_.remove(type);
    else
      selectionMap_.put(type, selection);
  }

  @Override
  public void setSelection(Object selection)
  {
    if(selection instanceof ISrtSelectable)
    {
      Class<?> type = ((ISrtSelectable) selection).getSelectionType();
      
      if(!type.isInstance(selection))
        throw new ProgramFault("Object " + selection + " is ISrtSelectable of " + type + " but is not an instance of that type");
      
      if(!(selection instanceof IModelObject))
        throw new ProgramFault("Object " + selection + " is ISrtSelectable of " + type + " but is not an instance of IModelObject");

      selectionMap_.put(type, selection);
    }
    
    if(selection instanceof IModelObject)
    {
      IModelObject parent = ((IModelObject) selection).getParent();
      
      if(parent != null)
        setSelection(parent);
    }
  }

  @Override
  public void populate(SrtCommandLineHome parser)
  {
    for(Flag flag : parser.getFlags())
    {
      Class<? extends IModelObject> type = flag.getSelectionType();
      
      if(type != null)
      {
        IModelObject selection = (IModelObject) selectionMap_.get(type);
        
        if(selection != null)
          flag.set(selection.getName());
      }
    }
  }
}
