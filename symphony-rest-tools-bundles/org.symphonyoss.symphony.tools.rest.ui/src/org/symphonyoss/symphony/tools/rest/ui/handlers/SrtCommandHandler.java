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

package org.symphonyoss.symphony.tools.rest.ui.handlers;

import javax.inject.Inject;

import org.eclipse.core.runtime.ICoreRunnable;
import org.eclipse.core.runtime.jobs.Job;
import org.eclipse.e4.core.di.annotations.Execute;
import org.eclipse.swt.widgets.Shell;
import org.symphonyoss.symphony.tools.rest.SrtCommand;
import org.symphonyoss.symphony.tools.rest.console.Console;
import org.symphonyoss.symphony.tools.rest.console.IConsole;
import org.symphonyoss.symphony.tools.rest.ui.ExceptionDialog;
import org.symphonyoss.symphony.tools.rest.ui.SrtImageRegistry;
import org.symphonyoss.symphony.tools.rest.ui.console.IConsoleManager;
import org.symphonyoss.symphony.tools.rest.ui.console.SwtConsole;
import org.symphonyoss.symphony.tools.rest.ui.selection.ISrtSelectionService;
import org.symphonyoss.symphony.tools.rest.util.home.ISrtHome;

public abstract class SrtCommandHandler
{
  @Inject
  private IConsoleManager consoleManager_;
  
  @Inject
  private ISrtSelectionService  selectionService_;
  
  @Inject
  private ISrtHome        srtHome_;
  
  @Inject
  private SrtImageRegistry  imageRegistry_;

  @Execute
  public void execute(Shell shell)
  {
    final org.symphonyoss.symphony.tools.rest.ui.console.IConsole console = consoleManager_.createConsole();
    final Console srtConsole = new SwtConsole(shell, imageRegistry_, console.getIn(), console.getOut(), console.getErr());
    
    srtConsole.setDefaultsProvider(srtHome_);
    
    SrtCommand   command = createCommand(srtConsole, srtHome_);
    
    selectionService_.populate(command.getParser());
    
    srtConsole.getOut().println(command.getProgramName() + " starting...");
    
    Job job = Job.create(command.getProgramName() + " Task", (ICoreRunnable) monitor ->
    {
      try
      {
        command.run();
        srtConsole.getOut().println(command.getProgramName() + " Finished.");
      }
      catch (RuntimeException e)
      {
        shell.getDisplay().asyncExec(() ->
        {
          srtConsole.getOut().flush();
          srtConsole.getErr().println(command.getProgramName() + " Failed.");
          e.printStackTrace(srtConsole.getErr());
          srtConsole.getErr().flush();
          
          ExceptionDialog.openError(shell,
            "Command Failed",
            "Command " + command.getProgramName() + " failed",
            e
            );
        });
      }
    });
    
    job.schedule();
  }

  protected abstract SrtCommand createCommand(IConsole console, ISrtHome srtHome);
}
