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

package org.symphonyoss.symphony.tools.rest.ui.pods;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Iterator;

import javax.annotation.PostConstruct;
import javax.inject.Inject;

import org.eclipse.e4.ui.services.EMenuService;
import org.eclipse.e4.ui.workbench.modeling.ESelectionService;
import org.eclipse.jface.dialogs.MessageDialog;
import org.eclipse.jface.viewers.ColumnViewerToolTipSupport;
import org.eclipse.jface.viewers.DoubleClickEvent;
import org.eclipse.jface.viewers.IDoubleClickListener;
import org.eclipse.jface.viewers.ISelectionChangedListener;
import org.eclipse.jface.viewers.IStructuredSelection;
import org.eclipse.jface.viewers.SelectionChangedEvent;
import org.eclipse.jface.viewers.TreeViewer;
import org.eclipse.jface.viewers.TreeViewerColumn;
import org.eclipse.swt.SWT;
import org.eclipse.swt.widgets.Composite;
import org.eclipse.swt.widgets.Display;
import org.symphonyoss.symphony.jcurl.JCurl;
import org.symphonyoss.symphony.tools.rest.model.IModelListener;
import org.symphonyoss.symphony.tools.rest.model.IModelObject;
import org.symphonyoss.symphony.tools.rest.model.IPodManager;
import org.symphonyoss.symphony.tools.rest.model.IUrlEndpoint;
import org.symphonyoss.symphony.tools.rest.ui.ModelObjectContentProvider;
import org.symphonyoss.symphony.tools.rest.ui.ModelObjectLabelProvider;
import org.symphonyoss.symphony.tools.rest.ui.ModelObjectStatusImageAndLabelProvider;
import org.symphonyoss.symphony.tools.rest.ui.ModelObjectTypeImageAndLabelProvider;
import org.symphonyoss.symphony.tools.rest.ui.SrtImageRegistry;
import org.symphonyoss.symphony.tools.rest.ui.browser.IBrowserManager;
import org.symphonyoss.symphony.tools.rest.ui.selection.ISrtSelectionService;
import org.symphonyoss.symphony.tools.rest.util.home.ISrtHome;

public class PodsView extends ModelObjectView
{
//  @Inject
//  private IConsoleManager consoleManager_;
  @Inject
  private ISrtHome        srtHome_;
  @Inject
  private IBrowserManager browserManager_;
  @Inject
  private ISrtSelectionService  selectionService_;
  @Inject
  private SrtImageRegistry  imageRegistry_;
  
  @PostConstruct
  public void createControls(Composite parent, EMenuService menuService, ESelectionService eSelectionService)
  {
    // more code...
    TreeViewer viewer = new TreeViewer(parent, SWT.MULTI);

    viewer.setContentProvider(new ModelObjectContentProvider());
   
    
    viewer.getTree().setHeaderVisible(true);
    Display display = viewer.getControl().getDisplay();

    TreeViewerColumn mainColumn = new TreeViewerColumn(viewer, SWT.NONE);
    mainColumn.getColumn().setText("Name");
    mainColumn.getColumn().setWidth(300);
    mainColumn.setLabelProvider(
            new ModelObjectTypeImageAndLabelProvider(display,
                (o) -> o.getName(), imageRegistry_));
    
    TreeViewerColumn typeColumn = new TreeViewerColumn(viewer, SWT.NONE);
    typeColumn.getColumn().setText("Type");
    typeColumn.getColumn().setWidth(100);
    typeColumn.setLabelProvider(
            new ModelObjectLabelProvider<IModelObject>(display,
                IModelObject.class,
                (o) -> o.getTypeName()));
    
    TreeViewerColumn statusColumn = new TreeViewerColumn(viewer, SWT.NONE);
    statusColumn.getColumn().setText("Status");
    statusColumn.getColumn().setWidth(100);
    statusColumn.setLabelProvider(
            new ModelObjectStatusImageAndLabelProvider(display, imageRegistry_));
    
    TreeViewerColumn statusMessageColumn = new TreeViewerColumn(viewer, SWT.NONE);
    statusMessageColumn.getColumn().setText("Status Message");
    statusMessageColumn.getColumn().setWidth(200);
    statusMessageColumn.setLabelProvider(
            new ModelObjectLabelProvider<IModelObject>(display,
                IModelObject.class,
                (o) -> o.getComponentStatusMessage()));
    
    TreeViewerColumn urlColumn = new TreeViewerColumn(viewer, SWT.NONE);
    urlColumn.getColumn().setText("URL");
    urlColumn.getColumn().setWidth(300);
    urlColumn.setLabelProvider(
            new ModelObjectLabelProvider<IUrlEndpoint>(display,
                IUrlEndpoint.class,
                (o) -> o.getUrl()));
    
    // register context menu on the table
    menuService.registerContextMenu(viewer.getControl(), "org.symphonyoss.symphony.tools.rest.ui.popupmenu.pods");
    
    viewer.addSelectionChangedListener(new ISelectionChangedListener()
    {
      @Override
      public void selectionChanged(SelectionChangedEvent event)
      {
        IStructuredSelection selection = viewer.getStructuredSelection();
        eSelectionService.setSelection(selection.getFirstElement());
        
        selectionService_.setSelection(selection.getFirstElement());
      }
    });
    
    viewer.setInput(srtHome_.getPodManager());
    ColumnViewerToolTipSupport.enableFor(viewer);
    
    IPodManager podManager = srtHome_.getPodManager();
    
    podManager.addListener(new IModelListener()
    {
      
      @Override
      public void modelObjectChanged(IModelObject modelObject)
      {
        display.asyncExec(() -> viewer.update(modelObject, null));
      }

      @Override
      public void modelObjectStructureChanged(IModelObject modelObject)
      {
        if(modelObject == podManager)
          display.asyncExec(() -> viewer.refresh());
        else
          display.asyncExec(() -> viewer.refresh(modelObject));
      }
    });
    
    podManager.loadAll();
  }
  
}
