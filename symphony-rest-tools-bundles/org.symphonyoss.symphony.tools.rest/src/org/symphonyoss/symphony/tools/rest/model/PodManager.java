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

import java.io.File;
import java.io.IOException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.symphonyoss.symphony.tools.rest.util.ProgramFault;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

public class PodManager extends FileSystemModelObjectManager implements IPodManager
{
  private Map<String, Pod>                     podMap_    = new HashMap<>();
  private boolean                              allLoaded_;

  public PodManager(File configDir)
  {
    super(null, "Pod Manager", "PodManager", configDir);
  }
  
  @Override
  public int getSize()
  {
    synchronized(podMap_)
    {
      if(allLoaded_)
        return podMap_.size();
    }
    
    String[] names = getConfigDir().list();
    
    if(names == null)
      return 0;
    
    return names.length;
  }


  @Override
  public String getDefaultPodName()
  {
    synchronized(podMap_)
    {
      if(allLoaded_)
      {
        Set<String> keySet = podMap_.keySet();
        
        if(keySet.size() == 1)
          return keySet.iterator().next();
        
        return null;
      }
    }
    
    String[] names = getConfigDir().list();
    
    if(names.length == 1)
      return names[0];
    
    return null;
  }


  @Override
  public Set<IPod> getAll()
  {
    loadAll();
    
    return new HashSet<IPod>(podMap_.values());
  }

  @Override
  public void loadAll()
  {
    if(!allLoaded_)
    {
      synchronized(podMap_)
      {
        for(File file : getConfigDir().listFiles())
        {
          if(podMap_.get(file.getName()) == null)
          {
            try
            {
              Pod newPod = loadPod(file);
              podMap_.put(file.getName(), newPod);
              addChild(newPod);
            }
            catch(IOException | InvalidConfigException e)
            {
              throw new ProgramFault("Failed to read pod config", e);
            }
          }
        }
      }
    }
  }

  @Override
  public Pod getPod(String hostName)
  {
    synchronized(podMap_)
    {
      if(!podMap_.containsKey(hostName))
      {
        File configDir = getConfigPath(hostName);
       
        try
        {
          Pod pod = loadPod(configDir);
          
          podMap_.put(hostName, pod);
          addChild(pod);
          
          return pod;
        }
        catch(IOException | InvalidConfigException e)
        {
         return null;
        }
      }
    }
    
    return podMap_.get(hostName);
  }

  private Pod loadPod(File configDir) throws JsonProcessingException, IOException, InvalidConfigException
  {
    File podConfig = new File(configDir, IModelObject.CONFIG_FILE_NAME + IModelObject.DOT_JSON);
    ObjectMapper mapper = new ObjectMapper();
    
    JsonNode jsonNode = mapper.readTree(podConfig);
    
    return new Pod(this, jsonNode);
  }

  @Override
  public IPod save(IPod pod) throws IOException
  {
    File configDir = getConfigPath(pod.getName());
    pod.store(configDir);
    
    return pod;
  }

  @Override
  public IPod createOrUpdatePod(Pod.Builder podConfig, Agent.Builder agentBuilder) throws InvalidConfigException, IOException
  {
    File configDir = getConfigPath(podConfig.getName());
    
    Pod   newPod = podConfig.build(this);
    
    if(agentBuilder.getAgentApiUrl() != null)
    {
      newPod.addAgent(agentBuilder);
    }
    
    newPod.store(configDir);
    
    Pod oldPod;
    synchronized (podMap_)
    {
      oldPod = podMap_.put(podConfig.getName(), newPod);
      replaceChild(oldPod, newPod);
    }
    
    if(oldPod != null)
    {
      oldPod.modelUpdated(newPod);
    }
    
    return newPod;
  }
  
  public void deletePod(Pod oldPod) throws IOException
  {
    File configDir = getConfigPath(oldPod.getName());
    
    deleteRecursively(configDir);
    
    synchronized (podMap_)
    {
      podMap_.remove(oldPod.getName());
      removeChild(oldPod);
    }
    
    oldPod.modelUpdated(null);
  }
}
