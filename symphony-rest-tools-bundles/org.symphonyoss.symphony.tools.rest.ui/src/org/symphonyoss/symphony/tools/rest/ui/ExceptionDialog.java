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

import java.util.ArrayList;
import java.util.List;

import org.eclipse.core.runtime.IStatus;
import org.eclipse.core.runtime.MultiStatus;
import org.eclipse.core.runtime.Status;
import org.eclipse.jface.dialogs.ErrorDialog;
import org.eclipse.swt.widgets.Shell;

public class ExceptionDialog
{

  public static void openError(Shell parent, String dialogTitle, String message, Throwable cause)
  {
    ErrorDialog.openError(parent, dialogTitle, message, 
        createMultiStatus(cause.getLocalizedMessage(), cause));
  }

  private static MultiStatus createMultiStatus(String msg, Throwable t)
  {
    List<Status> childStatuses = new ArrayList<>();
    StackTraceElement[] stackTraces = t.getStackTrace();

    for (StackTraceElement stackTrace : stackTraces)
    {
      Status status = new Status(IStatus.ERROR, RestUI.PLUGIN_ID, stackTrace.toString());
      childStatuses.add(status);
    }

    MultiStatus ms = new MultiStatus(RestUI.PLUGIN_ID, IStatus.ERROR, childStatuses.toArray(new Status[] {}),
        t.toString(), t);
    return ms;
  }
}
