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

package org.symphonyoss.symphony.tools.rest.model.osmosis;

public enum ComponentStatus
{
  NotReady(0), 
  Initializing(1), Starting(1), 
  OK(21), Warning(22), Error(23), Failed(24),
  Stopping(0), Stopped(0);
  
  private final int severity_;

  private ComponentStatus(int severity)
  {
    severity_ = severity;
  }
  
  public boolean isMoreSevereThan(ComponentStatus other)
  {
    return other==null || severity_ > other.severity_;
  }
}
