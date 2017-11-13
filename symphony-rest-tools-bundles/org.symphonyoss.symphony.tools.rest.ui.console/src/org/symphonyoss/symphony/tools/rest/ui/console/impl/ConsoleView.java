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

import org.eclipse.e4.ui.services.EMenuService;
import org.eclipse.jface.text.DocumentEvent;
import org.eclipse.jface.text.TextViewer;
import org.eclipse.swt.SWT;
import org.eclipse.swt.custom.StyledText;
import org.eclipse.swt.custom.VerifyKeyListener;
import org.eclipse.swt.events.VerifyEvent;
import org.eclipse.swt.widgets.Composite;

public class ConsoleView
{
  private TextViewer viewer_;
  private Console console_;
  private boolean autoScroll_ = true;
  private boolean autoShow_ = true;
  
  public ConsoleView(Composite parent, EMenuService menuService)
  {
    viewer_ = new TextViewer(parent, SWT.H_SCROLL | SWT.V_SCROLL);
    
    viewer_.appendVerifyKeyListener(new VerifyKeyListener()
    {
      @Override
      public void verifyKey(VerifyEvent event)
      {
        if(console_ != null && console_.isWritable())
        {
          console_.input(event.character);
        }
      }
    });
//  document_ = new Document();
//  viewer_.setDocument(document_);
//  
//  println("Hello world!");
//  println("This is my console!");
//
//  // register context menu on the table
//  menuService.registerContextMenu(viewer_.getControl(), "org.symphonyoss.symphony.tools.rest.ui.popupmenu.pods");

  }

  public void consoleAdded(Console console)
  {
    if(autoShow_ || console_ == null)
    {
      console_ = console;
      
      StyledText c = viewer_.getTextWidget();
      
      if(c != null)
      {
        c.getDisplay().asyncExec(() -> viewer_.setDocument(console_.getDocument()));
      }
    }
  }

  public void consoleOutput(Console console, DocumentEvent event)
  {
    if(autoShow_ && console_ != console)
    {
      console_ = console;
      viewer_.setDocument(console_.getDocument());
    }
    
    if(autoScroll_ && console_ == console)
    {
      viewer_.revealRange(event.getOffset(), event.getLength());
    }
  }

  public void consoleClosed(Console console)
  {
    // TODO Auto-generated method stub
    
  }
}
