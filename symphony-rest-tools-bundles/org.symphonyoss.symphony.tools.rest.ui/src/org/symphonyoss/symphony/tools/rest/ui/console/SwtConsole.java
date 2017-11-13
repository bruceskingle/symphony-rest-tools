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

package org.symphonyoss.symphony.tools.rest.ui.console;

import java.io.BufferedReader;
import java.io.PrintWriter;

import org.eclipse.core.runtime.IProgressMonitor;
import org.eclipse.jface.window.Window;
import org.eclipse.swt.widgets.Shell;
import org.symphonyoss.symphony.tools.rest.SrtCommand;
import org.symphonyoss.symphony.tools.rest.console.Console;
import org.symphonyoss.symphony.tools.rest.ui.SrtImageRegistry;
import org.symphonyoss.symphony.tools.rest.ui.util.ConsoleWizard;
import org.symphonyoss.symphony.tools.rest.ui.util.ConsoleWizardDialog;
import org.symphonyoss.symphony.tools.rest.util.command.Flag;

public class SwtConsole extends Console
{

  private Shell shell_;
  private IProgressMonitor monitor_;
  private SrtImageRegistry imageRegistry_;
  private int ok_;

  public SwtConsole(Shell shell, SrtImageRegistry imageRegistry, BufferedReader in, PrintWriter out, PrintWriter err)
  {
    super(in, out, err);
    shell_ = shell;
    imageRegistry_ = imageRegistry;
  }

  @Override
  public void execute(SrtCommand srtCommand)
  {
    ok_ = -1;
    shell_.getDisplay().syncExec(() ->
    {
      ConsoleWizard wizard = new ConsoleWizard(shell_, SwtConsole.this, srtCommand);
      
      ConsoleWizardDialog wizardDialog = new ConsoleWizardDialog(shell_,
          wizard, this);
      
      wizard.setDialog(wizardDialog);
      ok_ = wizardDialog.open();
    });
    
    if(ok_ == Window.OK)
    {
      for(Flag flag : srtCommand.getParser().getFlags())
      {
        getDefaultsProvider().setDefault(flag.getPrompt(), flag.getValue());
      }
    }
  }

  public void setProgressMonitor(IProgressMonitor monitor)
  {
    monitor_ = monitor;
  }


  @Override
  public String beginTask(int totalWork, String format, Object... args)
  {
    String name = super.beginTask(totalWork, format, args);
    monitor_.beginTask(name, totalWork);
    return name;
  }

  @Override
  public String beginSubTask(String format, Object... args)
  {
    String name = super.beginSubTask(format, args);
    monitor_.subTask(name);
    return name;
  }

  @Override
  public void taskDone()
  {
    monitor_.done();
  }

  @Override
  public boolean isTaskCanceled()
  {
    return monitor_.isCanceled();
  }

  @Override
  public boolean taskWorked(int work)
  {
    monitor_.worked(work);
    return isTaskCanceled();
  }

  public SrtImageRegistry getImageRegistry()
  {
    return imageRegistry_;
  }

}
