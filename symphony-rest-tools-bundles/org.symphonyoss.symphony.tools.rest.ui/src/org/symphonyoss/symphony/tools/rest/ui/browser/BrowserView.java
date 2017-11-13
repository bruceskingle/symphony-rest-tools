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

package org.symphonyoss.symphony.tools.rest.ui.browser;

import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.net.URLEncoder;

import javax.annotation.PostConstruct;

import org.eclipse.e4.ui.di.Focus;
import org.eclipse.swt.SWT;
import org.eclipse.swt.browser.Browser;
import org.eclipse.swt.browser.LocationEvent;
import org.eclipse.swt.browser.LocationListener;
import org.eclipse.swt.events.SelectionAdapter;
import org.eclipse.swt.events.SelectionEvent;
import org.eclipse.swt.layout.GridData;
import org.eclipse.swt.layout.GridLayout;
import org.eclipse.swt.widgets.Button;
import org.eclipse.swt.widgets.Composite;
import org.eclipse.swt.widgets.Text;

public class BrowserView
{
  
  private Text    text;
  private Browser browser;
  private URL url_;

  @PostConstruct
  public void createControls(Composite parent)
  {
    parent.setLayout(new GridLayout(2, false));

    text = new Text(parent, SWT.BORDER);
    text.setMessage("Enter City");
    text.setLayoutData(new GridData(SWT.FILL, SWT.CENTER, true, false, 1, 1));

    Button button = new Button(parent, SWT.PUSH);
    button.setText("Search");
    button.addSelectionListener(new SelectionAdapter()
    {
      @Override
      public void widgetSelected(SelectionEvent e)
      {
        String city = text.getText();
        if (city.isEmpty())
        {
          return;
        }
        try
        {
          // not supported at the moment by Google
          // browser.setUrl("http://maps.google.com/maps?q="
          // + URLEncoder.encode(city, "UTF-8")
          // + "&output=embed");
          browser.setUrl("https://www.google.com/maps/place/" + URLEncoder.encode(city, "UTF-8") + "/&output=embed");

        }
        catch (UnsupportedEncodingException e1)
        {
          e1.printStackTrace();
        }
      }
    });

    browser = new Browser(parent, SWT.NONE);
    browser.setLayoutData(new GridData(SWT.FILL, SWT.FILL, true, true, 2, 1));
    browser.addLocationListener(new LocationListener()
    {
      
      private String skey_;
      private String kmsession_;

      @Override
      public void changing(LocationEvent event)
      {
        System.err.println("Changing location " + event.location);
        skey_ = Browser.getCookie("skey", url_.toString());
        kmsession_ = Browser.getCookie("kmsession", url_.toString());
        
        System.err.println("skey=" + skey_);
        System.err.println("kmsession=" + kmsession_);
        
        if(event.location.contains("file://"))
        {
          String newLocation = event.location.replaceAll("file://", url_.toString());
        
          System.err.println("I changed it to " + newLocation);
          
          event.doit = false;
          
          browser.getDisplay().asyncExec(() -> browser.setUrl(newLocation));
        }
      }
      
      @Override
      public void changed(LocationEvent event)
      {
        System.err.println("Changed location " + event.location);
        
        System.err.println("HTML------------------------\n" + browser.getText());
        System.err.println("HTML------------------------\n\n\n");
        
        skey_ = Browser.getCookie("skey", url_.toString());
        kmsession_ = Browser.getCookie("kmsession", url_.toString());
        System.err.println("skey=" + skey_);
        System.err.println("kmsession=" + kmsession_);
      }
    });
  }

  @Focus
  public void onFocus()
  {
    text.setFocus();
  }

  public void setUrl(URL url, String html)
  {
    url_ = url;
    
    if(html == null)
    {
      final String[] headers = 
        new String[]
        {
           "Custom-header: this is just a demo: " + url,
           "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0.3163.91 Safari/537.36",
//           "x-symphony-csrf-token: 31a95220a6b7ab18ae7201879f93e31e9f686f8f78be71424ef93eee184e53b568fd232846b960acb15d9a616aed06a6168f749ab07187becc73ce1cfff3f266",
           "Origin: https://qa6.symphony.com"
       // "User-agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/604.1.38 (KHTML, like Gecko) Version/11.0 Safari/604.1.38"
        };
//    new String[] {"User-Agent: SWT Browser","Custom-header: this is just a demo"};
    
    browser.setUrl(
//        "http://request.urih.com/"
        url.toString()// + "/webcontroller/ingestor/MessageService"
        //"file:///Users/bruce.skingle/eclipse/workspaces/s2/SRT_HOME/test.html"
//        "https://perzoinc.atlassian.net/wiki/spaces/PLAT/pages/146089501/Embedded+Chat+Module+-+Internal+Showcase"
        , null, headers);
    }
    else
    {
      browser.setText(html);
    }
  }
}
