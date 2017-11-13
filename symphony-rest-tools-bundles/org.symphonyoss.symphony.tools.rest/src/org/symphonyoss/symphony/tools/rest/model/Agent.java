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

import java.net.MalformedURLException;
import java.net.URL;

import javax.annotation.Nullable;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

public class Agent extends ModelObject implements IAgent
{
  public static final String AGENT_URL = "agentUrl";

  public static final String TYPE_NAME = "Agent";
  
  //Immutable Config
  private final String                agentApiUrl_;
  
  // Persistable State
  
  // Members
  private final Pod pod_;
  private URL url_;

  /* package */ Agent(Pod pod, JsonNode config) throws InvalidConfigException
  {
    super(pod, TYPE_NAME, config);
    
    pod_ = pod;
    agentApiUrl_ = getRequiredTextNode(config, AGENT_URL);
    
    try
    {
      url_ = new URL(agentApiUrl_);
    }
    catch (MalformedURLException e)
    {
      throw new InvalidConfigException("Invalid URL \"" + agentApiUrl_ + "\"");
    }
  }
  
  public static class Builder extends ModelObject.Builder
  {
    private URL agentApiUrl_;
    
    @Override
    public Builder setName(String name)
    {
      super.setName(name);
      return this;
    }

    public Builder setAgentApiUrl(URL agentApiUrl)
    {
      agentApiUrl_ = agentApiUrl;
      putIfNotNull(jsonNode_, AGENT_URL, agentApiUrl);
      return this;
    }
    
    public @Nullable URL getAgentApiUrl()
    {
      return agentApiUrl_;
    }
    
    public Agent build(Pod pod) throws InvalidConfigException
    {
      return new Agent(pod, jsonNode_);
    }
  }
  
  public static Builder  newBuilder()
  {
    return new Builder();
  }
  
  @Override
  public void storeConfig(ObjectNode jsonNode, boolean includeMutable)
  {
    super.storeConfig(jsonNode, includeMutable);
    
    putIfNotNull(jsonNode, AGENT_URL, agentApiUrl_);
  }

  @Override
  public String getAgentApiUrl()
  {
    return agentApiUrl_;
  }

  @Override
  public String getTypeName()
  {
    return TYPE_NAME;
  }
  
  @Override
  public URL getUrl()
  {
    return url_;
  }

  

  @Override
  public IModelObject getParent()
  {
    return pod_;
  }
}
