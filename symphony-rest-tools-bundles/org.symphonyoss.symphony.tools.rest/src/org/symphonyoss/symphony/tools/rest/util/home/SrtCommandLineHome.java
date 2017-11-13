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

package org.symphonyoss.symphony.tools.rest.util.home;

import org.symphonyoss.symphony.tools.rest.console.IConsole;
import org.symphonyoss.symphony.tools.rest.util.command.CommandLineParser;
import org.symphonyoss.symphony.tools.rest.util.command.Flag;
import org.symphonyoss.symphony.tools.rest.util.command.Switch;

public class SrtCommandLineHome extends CommandLineParser
{
  private String  home_;

  public SrtCommandLineHome(String commandName)
  {
    super(commandName);
    withFlag(
      new Flag<String>("Location of SRT home", String.class, (v) -> home_ = v)
        .withName(ISrtHome.SRT_HOME));
  }


  public ISrtHome createSrtHome(IConsole console)
  {
    return new SrtHome(console, home_, "Command Line Flag");
  }


  @Override
  public SrtCommandLineHome withSwitch(Switch aswitch)
  {
    super.withSwitch(aswitch);
    
    return this;
  }


  @Override
  public SrtCommandLineHome withFlag(Flag<?> flag)
  {
    super.withFlag(flag);
    
    return this;
  }
}
