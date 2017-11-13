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

package org.symphonyoss.symphony.tools.rest;

import org.symphonyoss.symphony.tools.rest.console.Console;
import org.symphonyoss.symphony.tools.rest.util.home.ISrtHome;

public abstract class SrtDaemonCommand extends SrtCommand
{
  private Console multiConsole_;

  public SrtDaemonCommand(String programName, String[] argv)
  {
    this(programName, new Console(System.in, System.out, System.err), null);
    
    getParser().process(argv);
  }

  private SrtDaemonCommand(String programName, Console console, ISrtHome srtHome)
  {
    super(programName, console, srtHome);
    
    multiConsole_ = console;
  }

  public Console getMultiConsole()
  {
    return multiConsole_;
  }

}
