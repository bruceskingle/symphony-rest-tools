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

import java.lang.reflect.Field;
import java.util.ArrayList;

import org.eclipse.jface.wizard.IWizard;
import org.eclipse.jface.wizard.WizardDialog;
import org.eclipse.swt.widgets.Button;
import org.eclipse.swt.widgets.Shell;
import org.symphonyoss.symphony.tools.rest.ui.console.SwtConsole;

/**
 * Sub-clss of Wizard dialog which forces the Finish button to change to Close and
 * the wizard dialog remains open until this is pressed.
 * 
 * Does some nasty mirror magic to access private fields in WizardDialog.
 * 
 * @author Bruce Skingle
 *
 */
public class ConsoleWizardDialog extends WizardDialog
{
  private final SwtConsole   console_;
  private int                closeCnt_;

  // Local copies of private fields from WizardDialog
  private ArrayList<IWizard> nestedWizards;
  private IWizard            wizard;
  
  public ConsoleWizardDialog(Shell parentShell, IWizard newWizard, SwtConsole console)
  {
    super(parentShell, newWizard);
    
    console_ = console;
    wizard = newWizard;
    
    try
    {
      Field field = WizardDialog.class.getDeclaredField("nestedWizards");
      
      field.setAccessible(true);
      
      nestedWizards =  (ArrayList<IWizard>) field.get(this);
    }
    catch (NoSuchFieldException | SecurityException | IllegalArgumentException | IllegalAccessException e)
    {
      e.printStackTrace();
      nestedWizards =  new ArrayList<>();
    }
  }

  // Make visible.
  @Override
  public Button getButton(int id)
  {
    return super.getButton(id);
  }

  public boolean reallyClose()
  {
    if(closeCnt_++ > 0)
      return super.close();
    else
      return false;
  }
  
  /*
   * An almost copy of the WIzardDIalog method of the same name with the hardClose() removed.
   */
  @Override
  protected void finishPressed() {
    // THIS IS OUR CODE
    
    if(!console_.hasObjectives())
    {
      super.finishPressed();
      return;
    }
    
    // THIS IS THE SUPERCLASS IMPL
    
    // Wizards are added to the nested wizards list in setWizard.
    // This means that the current wizard is always the last wizard in the
    // list.
    // Note that we first call the current wizard directly (to give it a
    // chance to
    // abort, do work, and save state) then call the remaining n-1 wizards
    // in the
    // list (to save state).
    if (wizard.performFinish()) {
      // Call perform finish on outer wizards in the nested chain
      // (to allow them to save state for example)
      for (int i = 0; i < nestedWizards.size() - 1; i++) {
        nestedWizards.get(i).performFinish();
      }
      // Hard close the dialog.
      setReturnCode(OK);
      // WE DON"T WANT THIS ---->    hardClose();
    }
  }
}
