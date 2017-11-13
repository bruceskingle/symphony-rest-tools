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

import java.io.IOException;
import java.net.URL;

import org.symphonyoss.symphony.tools.rest.model.Principal.Builder;
import org.symphonyoss.symphony.tools.rest.model.osmosis.IComponent;
import org.symphonyoss.symphony.tools.rest.util.typeutils.ISetter;

public interface IPod extends IModelObject, IComponent, IModelObjectContainer, IUrlEndpoint
{
  Long getPodId();

  IPodManager getManager();

  URL getKeyManagerUrl();

  URL getPodUrl();

  URL getWebUrl();
  
  String getWebTitle();
  
  URL getPodApiUrl();

  URL getSessionAuthUrl();

  URL getKeyAuthUrl();

  Principal addPrincipal(Builder principalBuilder);

  void save() throws IOException;
  
  void delete() throws IOException;

  IModelObject getComponent(String name);

  IModelObject getComponent(String name, IModelObjectConstructor<? extends IModelObject> constructor,
      ISetter<IModelObject> setExisting);
}
