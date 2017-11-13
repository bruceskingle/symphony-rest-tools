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

package org.symphonyoss.symphony.tools.rest.ui;

import org.eclipse.jface.viewers.ColumnLabelProvider;
import org.eclipse.swt.SWT;
import org.eclipse.swt.graphics.Color;
import org.eclipse.swt.widgets.Display;
import org.symphonyoss.symphony.tools.rest.model.IModelObject;

public class ModelObjectLabelProvider<M> extends ColumnLabelProvider
{
  private final Class<M>          type_;
  private final ILabelProvider<M> labelProvider_;
  private final Display           display_;
    
  public ModelObjectLabelProvider(Display display,
      Class<M> type, ILabelProvider<M> labelProvider)
  {
    display_ = display;
    type_ = type;
    labelProvider_ = labelProvider;
  }


  @SuppressWarnings("unchecked") // We know that type is Class<M> so the cast is safe
  @Override
  public String getText(Object element)
  {
    if(type_.isInstance(element))
    {
      Object label = labelProvider_.getLabel((M) element);
      
      if(label == null)
        return null;
      
      return label.toString();
    }
    
    return null;
  }


  @Override
  public Color getForeground(Object element)
  {
    if(element instanceof IModelObject)
      return ((IModelObject)element).getErrorText() == null ? null : 
        display_.getSystemColor(SWT.COLOR_RED);
    
    return super.getForeground(element);
  }


  


  @Override
  public String getToolTipText(Object element)
  {
    if(element instanceof IModelObject)
      return ((IModelObject)element).getErrorText();
    return null;
  }
}
