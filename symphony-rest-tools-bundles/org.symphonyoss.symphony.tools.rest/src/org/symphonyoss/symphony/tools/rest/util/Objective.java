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

import org.symphonyoss.symphony.tools.rest.model.osmosis.Component;
import org.symphonyoss.symphony.tools.rest.model.osmosis.ComponentStatus;

public class Objective extends Component implements IObjective
{
  private final String                             label_;
    
  public Objective(String label)
  {
    label_ = label;
  }

  @Override
  public void setObjectiveStatusOK()
  {
    super.setComponentStatusIfMoreSevere(ComponentStatus.OK, "");
  }

  @Override
  public void setObjectiveStatus(ComponentStatus status, String statusMessageFormat, Object ...args)
  {
    super.setComponentStatusIfMoreSevere(status, statusMessageFormat, args);
  }

  @Override
  public String getLabel()
  {
    return label_;
  }
}
