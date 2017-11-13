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

package org.symphonyoss.symphony.tools.rest.probe;

import java.net.MalformedURLException;
import java.net.URL;

import org.symphonyoss.symphony.jcurl.JCurl;
import org.symphonyoss.symphony.jcurl.JCurl.Response;
import org.symphonyoss.symphony.tools.rest.util.ProgramFault;

import com.fasterxml.jackson.databind.JsonNode;

public class Probe
{
  private final int      port_;
  private final String   basePath_;

  private final String   hostName_;
  private final URL      baseUrl_;

  private URL            probeUrl_;
  private String         expectedContentType_;

  private int            httpStatus_;
  private JCurl.Response jcurlResponse_;
  private boolean        failed_ = true;
  private boolean        failedCertAuth_;
  private boolean        unhealthy_;
  private boolean        valid_;
    
  public Probe(String name, String suffix, String domain, int port,
      String basePath)
  {
    try
    {
      port_ = port;
      basePath_ = basePath;
      
      hostName_ = name + suffix + domain;
      baseUrl_ = new URL("https://" + hostName_ + 
          (port == 443 ? "" : ":" + port_) + basePath_);
      probeUrl_ = baseUrl_;
    }
    catch(MalformedURLException e)
    {
      throw new ProgramFault(e);
    }
  }
  
  public Probe setProbePath(String probePath, String expectedContentType)
  {
    String base = baseUrl_.toString();
    
    while(base.endsWith("/"))
      base = base.substring(0, base.length() - 1);
    
    try
    {
      probeUrl_ = new URL(base + probePath);
    }
    catch (MalformedURLException e)
    {
      throw new ProgramFault(e);
    }
    expectedContentType_ = expectedContentType;
    
    failed_ = true;
    unhealthy_ = false;
    valid_ = false;
    jcurlResponse_ = null;
    
    return this;
  }

  public boolean isFailed()
  {
    return failed_;
  }

  public boolean setFailed(boolean failed)
  {
    return failed_ = failed;
  }

  public JsonNode getJsonNode()
  {
    if(jcurlResponse_ == null)
      return null;
    
    return jcurlResponse_.getJsonNode();
  }

  public String getHostName()
  {
    return hostName_;
  }

  public URL getBaseUrl()
  {
    return baseUrl_;
  }

  public URL getProbeUrl()
  {
    return probeUrl_;
  }

  public String getExpectedContentType()
  {
    return expectedContentType_;
  }

  public JCurl.Response getJcurlResponse()
  {
    return jcurlResponse_;
  }

  public Response setJcurlResponse(JCurl.Response jcurlResponse)
  {
    return jcurlResponse_ = jcurlResponse;
  }

  public int getHttpStatus()
  {
    return httpStatus_;
  }

  public int setHttpStatus(int httpStatus)
  {
    return httpStatus_ = httpStatus;
  }

  public boolean isFailedCertAuth()
  {
    return failedCertAuth_;
  }

  public boolean setFailedCertAuth(boolean failedCertAuth)
  {
    return failedCertAuth_ = failedCertAuth;
  }

  public int getPort()
  {
    return port_;
  }

  public boolean isResponseTypeValid()
  {
    return expectedContentType_ == null || jcurlResponse_.getContentType().equals(expectedContentType_);
  }

  public String getHostNameAndPort()
  {
    return hostName_ + ":" + port_;
  }

  public boolean isUnhealthy()
  {
    return unhealthy_;
  }

  public void setUnhealthy(boolean unhealty)
  {
    unhealthy_ = unhealty;
  }

  public boolean isValid()
  {
    return valid_;
  }

  public void setValid(boolean valid)
  {
    valid_ = valid;
  }
}
