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

import org.symphonyoss.symphony.tools.rest.console.IConsole;

public class SubTaskMonitor
{
  private IConsole console_;
  private int      remainingWork_;
  private int      totalWork_;

  public SubTaskMonitor(IConsole console, String name, int totalWork)
  {
    console_ = console;
    remainingWork_ = totalWork;
    
    console_.beginSubTask(name);
  }

  public boolean worked(int work)
  {
    remainingWork_ -= work;
    totalWork_ += work;
    console_.taskWorked(work);
    
    return console_.isTaskCanceled();
  }

  public int getRemainingWork()
  {
    return remainingWork_;
  }

  public int getTotalWork()
  {
    return totalWork_;
  }
  
  public void done()
  {
    console_.taskWorked(remainingWork_);
    totalWork_ = -1;
  }
}
