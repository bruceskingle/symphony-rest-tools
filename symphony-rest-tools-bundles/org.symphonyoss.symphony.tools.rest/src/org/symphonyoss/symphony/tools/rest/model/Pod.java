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
import java.net.URL;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import javax.annotation.Nullable;

import org.symphonyoss.symphony.tools.rest.ISrtSelectable;
import org.symphonyoss.symphony.tools.rest.util.typeutils.ISetter;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

public class Pod extends SslServer implements IPod, ISrtSelectable
{
  public static final String        TYPE_NAME                    = "Pod";
  public static final String        WEB_TYPE_NAME                = "WebServer";
  public static final String        TYPE_KEY_MANAGER             = "KeyManager";
  public static final String        TYPE_SESSION_AUTH            = "SessionAuth";
  public static final String        TYPE_KEY_AUTH                = "KeyAuth";

  private static final String       FORMAT_1_AGENTS_NO_ARRAY     = "Agents element \"%s\" must be an array";
  private static final String       FORMAT_1_PRINCIPALS_NO_ARRAY = "Principals element \"%s\" must be an array";

  private static final String       POD_ID                       = "pod.id";
  private static final String       AGENTS                       = "agents";
  private static final String       PRINCIPALS                   = "principals";
  private static final String       POD_URL                      = "podUrl";
  private static final String       WEB_URL                      = "webUrl";
  private static final String       WEB_TITLE                    = "webTitle";
  private static final String       KEY_MANAGER_URL              = "keymanagerUrl";
  private static final String       SESSION_AUTH_URL             = "sessionauthUrl";
  private static final String       KEY_AUTH_URL                 = "keyauthUrl";
  private static final String       POD_API_URL                  = "podApiUrl";

  // Immutable Config
  private final URL                 keyManagerUrl_;
  private final URL                 podUrl_;
  private final URL                 webUrl_;
  private final String              webTitle_;
  private final URL                 podApiUrl_;
  private final URL                 sessionAuthUrl_;
  private final URL                 keyAuthUrl_;

  // Persistable State
  private Long                      podId_;

  // Members
  private final PodManager          manager_;
  private Map<String, Agent>        agentMap_                    = new HashMap<>();
  private Map<String, Principal>    principalMap_                = new HashMap<>();
  private DynamicComponentContainer dynamicContainer_;
  
  /* package */ Pod(PodManager manager, JsonNode config) throws InvalidConfigException
  {
    super(manager,
        config.get(POD_URL) != null ? TYPE_NAME : WEB_TYPE_NAME,
        config);
    
    manager_ = manager;
    
    podUrl_         = getOptionalUrlNode(config, POD_URL);
    webUrl_         = getOptionalUrlNode(config, WEB_URL);
    webTitle_       = getOptionalTextNode(config, WEB_TITLE);
    keyManagerUrl_  = getOptionalUrlNode(config, KEY_MANAGER_URL);
    sessionAuthUrl_ = getOptionalUrlNode(config, SESSION_AUTH_URL);
    keyAuthUrl_     = getOptionalUrlNode(config, KEY_AUTH_URL);
    podApiUrl_      = getOptionalUrlNode(config, POD_API_URL);
    
    addUrlEndpoint(TYPE_KEY_MANAGER, "Key Manager", keyManagerUrl_);
    addUrlEndpoint(TYPE_SESSION_AUTH, "Session Auth", sessionAuthUrl_);
    addUrlEndpoint(TYPE_KEY_AUTH, "Key Auth", keyAuthUrl_);
    
    podId_ = getOptionalLongNode(config, POD_ID);
    
    JsonNode agentsNode = config.get(AGENTS);
    
    if(agentsNode != null)
    {
      if(agentsNode.isArray())
      {
        synchronized (agentMap_)
        {
          for(JsonNode node : ((ArrayNode)agentsNode))
          {         
            Agent agent = new Agent(this, node);
            
            addAgent(agent);
          }
        }
      }
      else
      {
        throw new InvalidConfigException(String.format(FORMAT_1_AGENTS_NO_ARRAY, AGENTS));
      }
    }
    
    JsonNode principalsNode = config.get(PRINCIPALS);
    
    if(principalsNode != null)
    {
      if(principalsNode.isArray())
      {
        synchronized (principalMap_)
        {
          for(JsonNode node : ((ArrayNode)principalsNode))
          {            
            Principal principal = new Principal(this, node);
            
            Principal oldAgent = principalMap_.put(principal.getName(), principal);
            
            if(oldAgent != null)
            {
              oldAgent.modelUpdated(principal);
            }
          }
        }
      }
      else
      {
        throw new InvalidConfigException(String.format(FORMAT_1_PRINCIPALS_NO_ARRAY, AGENTS));
      }
    }
  }
  
  public Agent addAgent(Agent agent)
  {
    Agent oldAgent = agentMap_.put(agent.getName(), agent);

    if (oldAgent != null)
    {
      oldAgent.modelUpdated(agent);
    }
    
    replaceChild(oldAgent, agent);
    
    return agent;
  }
  
  public Agent addAgent(Agent.Builder agentBuilder) throws InvalidConfigException
  {
    return addAgent(agentBuilder.build(this));
  }
  
  public Principal addPrincipal(Principal principal)
  {
    Principal oldPrincipal = principalMap_.put(principal.getName(), principal);

    if (oldPrincipal != null)
    {
      oldPrincipal.modelUpdated(principal);
    }
    
    replaceChild(oldPrincipal, principal);
    
    return principal;
  }
  
  @Override
  public Principal addPrincipal(Principal.Builder principalBuilder)
  {
    return addPrincipal(principalBuilder.build(this));
  }

  public static class Builder extends SslServer.Builder
  {
    private URL podUrl_;
    private URL podApiUrl_;
    private URL webUrl_;
    private URL keyManagerUrl_;
    private URL keyAuthUrl_;
    private URL sessionAuthUrl_;
    
    @Override
    public Builder setName(String name)
    {
      super.setName(name);
      return this;
    }

    @Override
    public Builder addTrustCerts(Collection<X509Certificate> trustCerts)
    {
      super.addTrustCerts(trustCerts);
      return this;
    }
    
    @Override
    public Builder addTrustCert(X509Certificate trustCert)
    {
      super.addTrustCert(trustCert);
      return this;
    }

    public Builder setPodUrl(URL podUrl)
    {
      podUrl_ = podUrl;
      putIfNotNull(jsonNode_, POD_URL, podUrl);
      return this;
    }

    public Builder setWebUrl(URL webUrl)
    {
      webUrl_ = webUrl;
      putIfNotNull(jsonNode_, WEB_URL, webUrl);
      return this;
    }

    public Builder setWebTitle(String webTitle)
    {
      putIfNotNull(jsonNode_, WEB_TITLE, webTitle);
      return this;
    }

    public Builder setKeyManagerUrl(URL keyManagerUrl)
    {
      keyManagerUrl_ = keyManagerUrl;
      putIfNotNull(jsonNode_, KEY_MANAGER_URL, keyManagerUrl);
      return this;
    }

    public Builder setSessionAuthUrl(URL sessionAuthUrl)
    {
      sessionAuthUrl_ = sessionAuthUrl;
      putIfNotNull(jsonNode_, SESSION_AUTH_URL, sessionAuthUrl);
      return this;
    }

    public Builder setKeyAuthUrl(URL keyAuthUrl)
    {
      keyAuthUrl_ = keyAuthUrl;
      putIfNotNull(jsonNode_, KEY_AUTH_URL, keyAuthUrl);
      return this;
    }

    public Builder setPodApiUrl(URL podApiUrl)
    {
      podApiUrl_ = podApiUrl;
      putIfNotNull(jsonNode_, POD_API_URL, podApiUrl);
      return this;
    }
    
    public @Nullable URL getPodUrl()
    {
      return podUrl_;
    }

    public @Nullable URL getPodApiUrl()
    {
      return podApiUrl_;
    }

    public @Nullable URL getWebUrl()
    {
      return webUrl_;
    }
    
    public @Nullable String getWebTitle()
    {
      return getOptionalTextNode(jsonNode_, WEB_TITLE);
    }

    public @Nullable URL getKeyManagerUrl()
    {
      return keyManagerUrl_;
    }

    public @Nullable URL getKeyAuthUrl()
    {
      return keyAuthUrl_;
    }

    public @Nullable URL getSessionAuthUrl()
    {
      return sessionAuthUrl_;
    }

    public Pod build(PodManager manager) throws InvalidConfigException
    {
      return new Pod(manager, jsonNode_);
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
    
    putIfNotNull(config, POD_URL, podUrl_);
    putIfNotNull(config, WEB_URL, webUrl_);
    putIfNotNull(config, WEB_TITLE, webTitle_);
    putIfNotNull(config, KEY_MANAGER_URL, keyManagerUrl_);
    putIfNotNull(config, SESSION_AUTH_URL, sessionAuthUrl_);
    putIfNotNull(config, KEY_AUTH_URL, keyAuthUrl_);
    putIfNotNull(config, POD_API_URL, podApiUrl_);
    
    if(includeMutable)
    {
      putIfNotNull(config, POD_ID, podId_);
    }
    
    synchronized (agentMap_)
    {
      if(!agentMap_.isEmpty())
      {
        ArrayNode agentsNode = config.putArray(AGENTS);
        
        for(Agent agent : agentMap_.values())
        {
          ObjectNode node = agentsNode.addObject();
          
          agent.storeConfig(node, includeMutable);
        }
      }
    }
    
    synchronized (principalMap_)
    {
      if(!principalMap_.isEmpty())
      {
        ArrayNode principalsNode = config.putArray(PRINCIPALS);
        
        for(Principal principal : principalMap_.values())
        {
          ObjectNode node = principalsNode.addObject();
          
          principal.storeConfig(node, includeMutable);
        }
      }
    }
  }

  @Override
  public IPodManager getManager()
  {
    return manager_;
  }

  /**
   * This object has been replaced with the given one.
   * 
   * @param newPod The new instance which replaces the current one
   */
  public void modelUpdated(Pod newPod)
  {
  }

  @Override
  public URL getUrl()
  {
    return podUrl_ == null ? webUrl_ : podUrl_;
  }

  @Override
  public Long getPodId()
  {
    return podId_;
  }
  
  @Override
  public URL getKeyManagerUrl()
  {
    return keyManagerUrl_;
  }

  @Override
  public URL getPodUrl()
  {
    return podUrl_;
  }

  @Override
  public URL getWebUrl()
  {
    return webUrl_;
  }

  @Override
  public String getWebTitle()
  {
    return webTitle_;
  }

  @Override
  public URL getPodApiUrl()
  {
    return podApiUrl_;
  }

  @Override
  public URL getSessionAuthUrl()
  {
    return sessionAuthUrl_;
  }

  @Override
  public URL getKeyAuthUrl()
  {
    return keyAuthUrl_;
  }

  @Override
  public void save() throws IOException
  {
    manager_.save(this);
  }
  
  @Override
  public void delete() throws IOException
  {
    manager_.deletePod(this);
  }
  
  public synchronized DynamicComponentContainer getDynamicContainer()
  {
    if(dynamicContainer_ == null)
    {
      dynamicContainer_ = new DynamicComponentContainer(this, "PodServer", "Pod Components");
      addChild(dynamicContainer_);
    }
    return dynamicContainer_;
  }

  @Override
  public IModelObject getComponent(String name)
  {
    return getDynamicContainer().getComponent(name,
        (parent, componentName) -> new ModelObject(this, GENERIC_COMPONENT, componentName),
        null);
  }

  @Override
  public IModelObject getComponent(String name,
      IModelObjectConstructor<? extends IModelObject> constructor,
      @Nullable ISetter<IModelObject> setExisting)
  {
    return getDynamicContainer().getComponent(name,
        (parent, componentName) -> new ModelObject(this, GENERIC_COMPONENT, componentName),
        setExisting);
  }

  @Override
  public Class<? extends IModelObject> getSelectionType()
  {
    return IPod.class;
  }
}
