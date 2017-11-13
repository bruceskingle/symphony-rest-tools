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

import javax.inject.Named;

import org.eclipse.core.runtime.ICoreRunnable;
import org.eclipse.core.runtime.jobs.Job;
import org.eclipse.e4.core.di.annotations.Execute;
import org.eclipse.e4.core.di.annotations.Optional;
import org.eclipse.e4.ui.services.IServiceConstants;
import org.eclipse.jface.dialogs.MessageDialog;
import org.eclipse.swt.widgets.Shell;
import org.symphonyoss.symphony.tools.rest.ui.ExceptionDialog;

public abstract class SelectionHandler<T>
{
  private final String   commandName_;
  private final Class<T> type_;
  private final String   typeName_;
  private boolean selectionRequired_;

  public SelectionHandler(String commandName, Class<T> type, String typeName, boolean selectionRequired)
  {
    commandName_ = commandName;
    type_ = type;
    typeName_ = typeName;
    selectionRequired_ = selectionRequired;
  }
  
  public String getCommandName()
  {
    return commandName_;
  }

  public Class<T> getType()
  {
    return type_;
  }

  public String getTypeName()
  {
    return typeName_;
  }

  @Execute
  public void doExecute(Shell shell, @Named(IServiceConstants.ACTIVE_SELECTION)
  @Optional Object selection)
  {
    @SuppressWarnings("unchecked")
    T typedSelection = (selection!=null && type_.isInstance(selection)) ? (T) selection : null;
    
    if(selectionRequired_ && typedSelection == null)
    {
      MessageDialog.openError(shell,
          "No Selection",
          "Select a " + typeName_ + " to use this command."
          );
    }
    else
    {
      Job job = Job.create(commandName_ + " Task", (ICoreRunnable) monitor ->
      {
        try
        {
          execute(shell, typedSelection);
        }
        catch (RuntimeException e)
        {
          shell.getDisplay().asyncExec(() ->
          {
            ExceptionDialog.openError(shell,
              "Command Failed",
              "Command " + commandName_ + " failed on\n" +
              selection,
              e
              );
          });
        }
      });
      
      job.schedule();
    }
  }

  protected abstract void execute(Shell shell, T selection);
}
