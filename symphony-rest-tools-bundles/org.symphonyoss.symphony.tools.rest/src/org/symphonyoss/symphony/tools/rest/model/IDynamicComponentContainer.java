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

import javax.annotation.Nullable;

import org.symphonyoss.symphony.tools.rest.model.osmosis.IComponentProxy;
import org.symphonyoss.symphony.tools.rest.util.typeutils.ISetter;

public interface IDynamicComponentContainer extends IModelObjectContainer
{
  /**
   * Get the child component with the given name. If no such component exists
   * then it is created as a generic ModelObject.
   * 
   * @param   name    Name of the required component.
   * @return  The required component.
   */
  IComponentProxy getComponent(String name);

  /**
   * Get the child component with the given name. If no such component exists
   * then it is created.
   * 
   * @param   name        Name of the required component.
   * @param   constructor An IModelObjectConstructor to create a new child component if necessary
   * @param   setExisting A setter which is called with the existing component if it is not constructed.
   * 
   * @return  The required component.
   */
  IComponentProxy getComponent(String name,
      IModelObjectConstructor<? extends IModelObject> constructor,
      @Nullable ISetter<IModelObject> setExisting);
}
