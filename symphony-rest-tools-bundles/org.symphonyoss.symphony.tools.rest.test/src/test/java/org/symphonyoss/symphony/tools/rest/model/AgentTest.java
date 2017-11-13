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

import static org.junit.Assert.assertEquals;

import java.net.MalformedURLException;
import java.net.URL;

import org.junit.Test;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

public class AgentTest
{

  @Test(expected=InvalidConfigException.class)
  public void testInvalidURL() throws InvalidConfigException
  {
    Agent.Builder builder = Agent.newBuilder();
    builder.jsonNode_
        .put(Agent.NAME, "Test Agent")
        .put(Agent.AGENT_URL, "not a URL");
    
    builder.build(null);
  }
  
  @Test
  public void testOK() throws InvalidConfigException, JsonProcessingException, MalformedURLException
  {
    Agent.Builder builder = Agent.newBuilder();
    
    Agent agent = builder.setName("Test Agent")
        .setAgentApiUrl(new URL("http://www.symphony.com"))
        .build(null);
    
    String json = new ObjectMapper().writeValueAsString(agent.toJson());
    
    assertEquals(json, "{\"name\":\"Test Agent\",\"agentUrl\":\"http://www.symphony.com\"}");
  }

}
