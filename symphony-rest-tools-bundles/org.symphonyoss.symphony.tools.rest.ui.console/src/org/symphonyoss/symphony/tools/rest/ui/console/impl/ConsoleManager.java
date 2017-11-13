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

package org.symphonyoss.symphony.tools.rest.ui.console.impl;

import java.util.HashSet;
import java.util.Set;

import javax.inject.Inject;

import org.eclipse.e4.core.services.log.Logger;
import org.eclipse.e4.ui.di.UISynchronize;
import org.eclipse.e4.ui.services.EMenuService;
import org.eclipse.jface.text.DocumentEvent;
import org.eclipse.swt.widgets.Composite;
import org.eclipse.swt.widgets.Shell;
import org.symphonyoss.symphony.tools.rest.ui.console.IConsole;
import org.symphonyoss.symphony.tools.rest.ui.console.IConsoleManager;

public class ConsoleManager implements IConsoleManager
{
  @Inject
  private Logger          logger_;
  @Inject
  private UISynchronize   sync_;
  
  private Set<IConsole>    consoles_ = new HashSet<>();
  private Set<ConsoleView> views_    = new HashSet<>();
  
  public ConsoleManager()
  {
        System.err.println("ConsoleManager created");
  }
  
  @Override
  public synchronized void createView(Composite parent, EMenuService menuService)
  {
    ConsoleView view = new ConsoleView(parent, menuService);

    views_.add(view);
  }

  @Override
  public IConsole createConsole()
  {
    Console  console = new Console(this, logger_, sync_);
    
    synchronized(this)
    {
      consoles_.add(console);
      
      for(ConsoleView view : views_)
        view.consoleAdded(console);
    }
    
    return console;
  }
  
  public synchronized void consoleOutput(Console console, DocumentEvent event)
  {
    for(ConsoleView view : views_)
      view.consoleOutput(console, event);
  }

  public void consoleClosed(Console console)
  {
    console.getErr().println("CLOSED");
    
    synchronized(this)
    {
      for(ConsoleView view : views_)
        view.consoleClosed(console);
    }
  }
}
