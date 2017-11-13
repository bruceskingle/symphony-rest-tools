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

import org.eclipse.jface.wizard.WizardPage;
import org.eclipse.swt.SWT;
import org.eclipse.swt.custom.StackLayout;
import org.eclipse.swt.events.KeyEvent;
import org.eclipse.swt.events.KeyListener;
import org.eclipse.swt.events.SelectionEvent;
import org.eclipse.swt.events.SelectionListener;
import org.eclipse.swt.layout.GridData;
import org.eclipse.swt.layout.GridLayout;
import org.eclipse.swt.widgets.Button;
import org.eclipse.swt.widgets.Composite;
import org.eclipse.swt.widgets.Label;
import org.eclipse.swt.widgets.Text;
import org.symphonyoss.symphony.tools.rest.ui.console.SwtConsole;
import org.symphonyoss.symphony.tools.rest.util.IObjective;
import org.symphonyoss.symphony.tools.rest.util.command.Flag;
import org.symphonyoss.symphony.tools.rest.util.command.Switch;
import org.symphonyoss.symphony.tools.rest.util.home.SrtCommandLineHome;

public class ConsoleWizardConfigPage extends WizardPage
{
  private Composite          configContainer_;
  private Composite          objectiveContainer_;
  private SrtCommandLineHome parser_;
  private SwtConsole         console_;
  private StackLayout stackLayout_;
  private Composite stackContainer_;

  public ConsoleWizardConfigPage(SwtConsole console, SrtCommandLineHome parser) {
      super("config");
      setTitle("Parameters");
      setDescription("Command Parameters");
      
      console_ = console;
      parser_ = parser;
  }

  @Override
  public void createControl(Composite parent)
  {
    stackContainer_ = new Composite(parent, SWT.NONE);
    stackLayout_ = new StackLayout();
    stackContainer_.setLayout(stackLayout_);
    
    configContainer_ = new Composite(stackContainer_, SWT.NONE);
    GridLayout layout = new GridLayout();
    configContainer_.setLayout(layout);
    layout.numColumns = 2;
    
    for(Switch s : parser_.getSwitches().values())
    {
      createControl(configContainer_, s);
    }
    
    for(Flag flag : parser_.getFlags())
    {
      createControl(configContainer_, flag);
    }
    
    objectiveContainer_ = new Composite(stackContainer_, SWT.NONE);
    layout = new GridLayout();
    objectiveContainer_.setLayout(layout);
    layout.numColumns = 3;
    
    for(IObjective objective : console_.getObjectives())
    {
      createControl(objectiveContainer_, objective);
    }
    
    showConfig();
    setControl(stackContainer_);
    setPageComplete();

  }

  private void createControl(Composite container, IObjective objective)
  {
    final Label label = new Label(container, SWT.NONE);
    label.setText(objective.getLabel());
    
    final Label imageLabel = new Label(container, SWT.NONE);
    imageLabel.setImage(console_.getImageRegistry().get(objective.getComponentStatus()));
    
    final Label statusLabel = new Label(container, SWT.NONE);
    statusLabel.setText(objective.getComponentStatusMessage());
    
    objective.addListener((o) ->
      container.getDisplay().asyncExec(() -> 
      {
        imageLabel.setImage(console_.getImageRegistry().get(o.getComponentStatus()));
        statusLabel.setText(objective.getComponentStatusMessage());
      }
    ));
   
    GridData gd = new GridData(GridData.FILL_HORIZONTAL);
    statusLabel.setLayoutData(gd);
  }

  private void setPageComplete()
  {
    boolean   ok = true;
    
    for(Flag flag : parser_.getFlags())
    {
      if(flag.isRequired() && flag.getValue().length()==0)
      {
        ok = false;
        break;
      }
    }
    
    setPageComplete(ok);
  }

  private void createControl(Composite container, Flag flag)
  {
    Label label1 = new Label(container, SWT.NONE);
    label1.setText(flag.getPrompt());
    
    Text text1 = new Text(container, SWT.BORDER | SWT.SINGLE);
    
    String value = flag.getValue();
    
    if(value.length()==0)
    {
      value = console_.getDefaultsProvider().getDefault(flag.getPrompt());
      flag.set(value);
    }
    
    text1.setText(value);
    text1.addKeyListener(new KeyListener()
    {

      @Override
      public void keyPressed(KeyEvent e)
      {
      }

      @Override
      public void keyReleased(KeyEvent e)
      {
        flag.set(text1.getText().trim());
        
        setPageComplete();
      }

    });
    GridData gd = new GridData(GridData.FILL_HORIZONTAL);
    text1.setLayoutData(gd);
  }

  private void createControl(Composite container, Switch s)
  {
    Label label1 = new Label(container, SWT.NONE);
    label1.setText(s.getLabel());
    
    Button button = new Button(container, SWT.CHECK);
    
    button.addSelectionListener(new SelectionListener()
    {
      
      @Override
      public void widgetSelected(SelectionEvent e)
      {
        s.setCount(button.getSelection() ? 1 : 0);
      }
      
      @Override
      public void widgetDefaultSelected(SelectionEvent e)
      {}
    });
  }

  public void showConfig()
  {
    stackLayout_.topControl = configContainer_;
    stackContainer_.getDisplay().asyncExec(() ->stackContainer_.layout());
  }

  public void showObjetives()
  {
    stackLayout_.topControl = objectiveContainer_;
    stackContainer_.getDisplay().asyncExec(() ->stackContainer_.layout());
  }
}
