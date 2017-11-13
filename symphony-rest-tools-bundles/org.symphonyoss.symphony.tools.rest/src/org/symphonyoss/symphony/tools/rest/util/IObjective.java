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

package org.symphonyoss.symphony.tools.rest.util;

import org.symphonyoss.symphony.tools.rest.model.osmosis.ComponentStatus;
import org.symphonyoss.symphony.tools.rest.model.osmosis.IComponent;

/**
 * Represents an objective.
 * 
 * All of the setObjective... methods can be called multiple times and the result status
 * will be the most severe of all the values passed. All worse than OK states will be 
 * recorded and may be recalled.
 * 
 * @author Bruce Skingle
 *
 */
public interface IObjective extends IComponent
{
  public void setObjectiveStatusOK();
  
  void setObjectiveStatus(ComponentStatus status, String statusMessageFormat, Object ...args);

  String getLabel();
}
