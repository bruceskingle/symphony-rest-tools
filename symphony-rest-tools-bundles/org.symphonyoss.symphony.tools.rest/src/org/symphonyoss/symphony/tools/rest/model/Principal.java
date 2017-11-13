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

package org.symphonyoss.symphony.tools.rest.model;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.security.cert.CertificateParsingException;

import org.symphonyoss.symphony.jcurl.JCurl;
import org.symphonyoss.symphony.jcurl.JCurl.Response;
import org.symphonyoss.symphony.tools.rest.Srt;
import org.symphonyoss.symphony.tools.rest.console.IConsole;
import org.symphonyoss.symphony.tools.rest.model.osmosis.ComponentStatus;
import org.symphonyoss.symphony.tools.rest.util.ProgramFault;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

public class Principal extends ModelObject
{
  public static final String  TYPE_NAME   = "Principal";

  private static final String SESSION_INFO = "/v2/sessioninfo";
  
  private static final String USER_NAME   = "username";
  private static final String USER_ID     = "id";
  private static final String CERTIFICATE = "certificate";
  private static final String SKEY = "skey";
  private static final String KMSESSION = "kmsession";

  // Immutable Config
  private final String        certificate_;
  
  // Persistable State
  private String        userName_;
  private long          userId_;
  private String skey_;
  private String kmsession_;
  
  // Members
  private final Pod pod_;

  
  
  public Principal(Pod pod, JsonNode config) throws InvalidConfigException
  {
    super(pod, TYPE_NAME, config);
    pod_ = pod;
    
    userName_         = getOptionalTextNode(config, USER_NAME);
    userId_           = getRequiredLongNode(config, USER_ID);
    certificate_      = getOptionalTextNode(config, CERTIFICATE);
    
    skey_      = getOptionalTextNode(config, SKEY);
    kmsession_ = getOptionalTextNode(config, KMSESSION);
  }
  
  public static class Builder extends ModelObject.Builder
  {
    @Override
    public Builder setName(String name)
    {
      super.setName(name);
      return this;
    }

    public Builder setUserName(String userName)
    {
      putIfNotNull(jsonNode_, USER_NAME, userName);
      return this;
    }

    public Builder setUserId(long userId)
    {
      putIfNotNull(jsonNode_, USER_ID, userId);
      
      return this;
    }

    public Builder setCertificate(String certificate)
    {
      putIfNotNull(jsonNode_, CERTIFICATE, certificate);
      return this;
    }
    
    public Builder setSkey(String skey)
    {
      putIfNotNull(jsonNode_, SKEY, skey);
      return this;
    }
    
    public Builder setKmsession(String kmSesion)
    {
      putIfNotNull(jsonNode_, KMSESSION, kmSesion);
      return this;
    }
    
    public Principal build(Pod pod)
    {
      try
      {
        return new Principal(pod, jsonNode_);
      }
      catch (InvalidConfigException e)
      {
       throw new ProgramFault(e);
      }
    }
  }
  
  public static Builder  newBuilder()
  {
    return new Builder();
  }
  
  @Override
  public void storeConfig(ObjectNode config, boolean includeMutable)
  {
    super.storeConfig(config, includeMutable);
    
    putIfNotNull(config, USER_NAME, userName_);
    putIfNotNull(config, USER_ID, userId_);
    putIfNotNull(config, CERTIFICATE, certificate_);
    
    if(includeMutable)
    {
      putIfNotNull(config, SKEY, skey_);
      putIfNotNull(config, KMSESSION, kmsession_);
    }
  }

  public static Principal newInstance(IConsole console, IPod pod, String skey, String kmsession) throws IOException
  {
    Builder builder = Principal.newBuilder()
    .setSkey(skey)
    .setKmsession(kmsession);
    
    console.printfln("Validating session");
    
    JCurl jcurl = JCurl.builder()
        .header(Srt.SESSION_TOKEN, skey)
        .extract(KMSESSION, KMSESSION)
        .build();
    
    try
    {
      HttpURLConnection con = jcurl.connect(pod.getPodApiUrl() + SESSION_INFO);
      
      Response response = jcurl.processResponse(con);
      JsonNode json = response.getJsonNode();
      
      console.println(json);
      
      // {"id":206158450786,"emailAddress":"bruce+qa4@symphony.com","firstName":"Bruce","lastName":"Sk","displayName":"Bruce Sk","company":"companyNameFour","username":"bruce","avatars":[{"size":"original","url":"../avatars/static/orig/default.png"},{"size":"small","url":"../avatars/static/150/default.png"}]}
      
      builder.setUserId(getRequiredLongNode(json, "id"));
      builder.setName(getRequiredTextNode(json, "username"));
    }
    catch(IOException | CertificateParsingException | InvalidConfigException  e)
    {
      console.error(e, "Unable to validate user");
    }
    
    Principal principal = pod.addPrincipal(builder);
    
    pod.save();
    
    principal.setComponentStatus(ComponentStatus.OK, "Logged In");
    
    return principal;
  }

}
