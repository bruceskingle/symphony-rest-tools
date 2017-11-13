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

package org.symphonyoss.symphony.tools.rest.ui.util;

import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.List;

import org.eclipse.core.runtime.IProgressMonitor;
import org.eclipse.jface.dialogs.IDialogConstants;
import org.eclipse.jface.operation.IRunnableWithProgress;
import org.eclipse.jface.wizard.Wizard;
import org.eclipse.swt.SWT;
import org.eclipse.swt.events.SelectionEvent;
import org.eclipse.swt.events.SelectionListener;
import org.eclipse.swt.widgets.Button;
import org.eclipse.swt.widgets.Listener;
import org.eclipse.swt.widgets.Shell;
import org.symphonyoss.symphony.tools.rest.SrtCommand;
import org.symphonyoss.symphony.tools.rest.ui.console.SwtConsole;

public class ConsoleWizard extends Wizard
{
  private final Shell             shell_;
  private final SwtConsole        console_;
  private final SrtCommand        command_;
  private ConsoleWizardConfigPage objectivePage_;
  private boolean holdClose_;
  private ConsoleWizardDialog wizardDialog_;

  
  public ConsoleWizard(Shell shell, SwtConsole console, SrtCommand command)
  {
    shell_ = shell;
    console_ = console;
    command_ = command;
    setNeedsProgressMonitor(true);
  }

  @Override
  public String getWindowTitle() {
      return command_.getParser().getCommandName();
  }

  @Override
  public void addPages()
  {
    objectivePage_ = new ConsoleWizardConfigPage(console_, command_.getParser());
    
    addPage(objectivePage_);
  }

  @Override
  public boolean performFinish()
  {
    
    try
    {
      getContainer().run(true, true, new IRunnableWithProgress()
      {
        @Override
        public void run(IProgressMonitor monitor) throws InvocationTargetException, InterruptedException
        {
          if(console_.hasObjectives())
          {
            holdClose_ = true;
            objectivePage_.showObjetives();
          }
          
          console_.setProgressMonitor(monitor);
          
          command_.doExecute();
          
          if(console_.hasObjectives() && wizardDialog_ != null)
          {
            Button finishButton = wizardDialog_.getButton(IDialogConstants.FINISH_ID);
                //.getFinishButton("finishButton");
            List<Button> disableButtons = new ArrayList<>();
            
            for(int id : new int[] {IDialogConstants.CANCEL_ID,
                IDialogConstants.NEXT_ID,
                IDialogConstants.BACK_ID})
            {
              Button button = wizardDialog_.getButton(id);
              
              if(button != null)
                disableButtons.add(button);
            }
            
            if(finishButton != null)
            {
              
              
              finishButton.getDisplay().syncExec(() ->
              {
                for(Button button : disableButtons)
                {
                  button.setVisible(false);
                }
                
                for(Listener listener : finishButton.getListeners(SWT.Selection))
                  finishButton.removeListener(SWT.Selection, listener);
                
                finishButton.addSelectionListener(new SelectionListener()
                {
                  @Override
                  public void widgetSelected(SelectionEvent e)
                  {
                    wizardDialog_.reallyClose();
                  }
                  
                  @Override
                  public void widgetDefaultSelected(SelectionEvent e)
                  {
                    wizardDialog_.reallyClose();
                  }
                });
                
                finishButton.setText("Close");
                finishButton.setEnabled(true);
              });
            }
          }
        }
      });
    }
    catch (Exception e)
    {
      e.printStackTrace();
    }

    return true;
  }

  public void setDialog(ConsoleWizardDialog wizardDialog)
  {
    wizardDialog_ = wizardDialog;
  }
}