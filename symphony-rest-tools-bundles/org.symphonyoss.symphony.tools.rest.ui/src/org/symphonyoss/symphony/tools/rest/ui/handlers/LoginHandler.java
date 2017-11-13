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

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;

import org.eclipse.jface.dialogs.MessageDialog;
import org.eclipse.swt.widgets.Shell;
import org.symphonyoss.symphony.jcurl.JCurl;
import org.symphonyoss.symphony.tools.rest.console.IConsole;
import org.symphonyoss.symphony.tools.rest.model.IPod;
import org.symphonyoss.symphony.tools.rest.ui.login.PodLoginDialog;

public class LoginHandler extends ConsoleSelectionHandler<IPod>
{
  public LoginHandler()
  {
    super("Login", IPod.class, "Pod", true);
  }

  @Override
  protected void execute(Shell shell, IPod pod, IConsole console)
  {
    URL url = pod.getUrl();
    
    try 
    {
      JCurl jCurl = JCurl.builder().build();
      HttpURLConnection connection = jCurl.connect(url);
      
      
  
      if(connection.getResponseCode() != 200)
      {
        MessageDialog.openError(shell,
            "Failed to connect",
            "Error " + connection.getResponseCode()
            );

        return;
      }
      
      try(
          BufferedReader reader = new BufferedReader(
              new InputStreamReader(
                  connection.getInputStream())))
      {
        StringBuilder s = new StringBuilder();
        String line;
        
        while((line = reader.readLine()) != null)
        {
          line = line.replaceAll("href=\"", "href=\"" + url + "/")
              .replaceAll("<script src=\"app-", "<script src=\"" + url + "/app-")
              .replaceAll("\"./browsers.html\"", "\"" + url + "/browsers.html\"")
              .replaceAll("'/login'", "'" + url + "/login'")
              .replaceAll("var chrome32 = \\(chromeVer >= 32\\);", "var chrome32 = true;")
              ;
          s.append(line);
          s.append("\n");
        }
        
        PodLoginDialog dialog = new PodLoginDialog(shell, pod, console, s.toString());
        
        shell.getDisplay().asyncExec(() -> dialog.open());
      }
    }
    catch(IOException e)
    {
      shell.getDisplay().asyncExec(() -> MessageDialog.openError(shell,
          "Failed to connect",
          "Error " + e
          ));
    } 
  }
}
