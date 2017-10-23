/*
 *
 *
 * Copyright 2017 Symphony Communication Services, LLC.
 *
 * Licensed to The Symphony Software Foundation (SSF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
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
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.symphonyoss.symphony.tools.rest.util.ProgramFault;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.symphony.s2.common.exception.BadFormatException;

public class CertificateManager extends FileSystemModelObjectManager implements ICertificateManager
{
  private Map<String, Certificate>             certHashMap_    = new HashMap<>();
  private boolean                              allLoaded_;

  public CertificateManager(File configDir)
  {
    super(null, "Certificate Manager", "CertificateManager", configDir);
  }
  
  @Override
  public int getSize()
  {
    synchronized(certHashMap_)
    {
      if(allLoaded_)
        return certHashMap_.size();
    }
    
    String[] names = getConfigDir().list();
    
    if(names == null)
      return 0;
    
    return names.length;
  }

  @Override
  public Set<ICertificate> getAll()
  {
    loadAll();
    
    return new HashSet<ICertificate>(certHashMap_.values());
  }

  @Override
  public void loadAll()
  {
    if(!allLoaded_)
    {
      synchronized(certHashMap_)
      {
        for(File file : getConfigDir().listFiles())
        {
          if(certHashMap_.get(file.getName()) == null)
          {
            try
            {
              Certificate newCertificate = loadCertificate(file);
              certHashMap_.put(file.getName(), newCertificate);
              addChild(newCertificate);
            }
            catch(IOException | InvalidConfigException e)
            {
              throw new ProgramFault("Failed to read cert", e);
            }
          }
        }
      }
    }
  }

  @Override
  public Certificate getCertificate(String fingerprint)
  {
    synchronized(certHashMap_)
    {
      if(!certHashMap_.containsKey(fingerprint))
      {
        try
        {
          Certificate pod = loadCertificate(fingerprint);
          
          certHashMap_.put(fingerprint, pod);
          addChild(pod);
          
          return pod;
        }
        catch(IOException | InvalidConfigException e)
        {
         return null;
        }
      }
    }
    
    return certHashMap_.get(fingerprint);
  }

  private Certificate loadCertificate(String fingerprint) throws JsonProcessingException, IOException, InvalidConfigException
  {
    return loadCertificate(new File(getConfigDir(), fingerprint + IModelObject.DOT_JSON));
  }

  private Certificate loadCertificate(File file) throws JsonProcessingException, IOException, InvalidConfigException
  {
    ObjectMapper mapper = new ObjectMapper();
    
    JsonNode jsonNode = mapper.readTree(file);
    
    return new Certificate(this, jsonNode);
  }

  @Override
  public ICertificate save(ICertificate pod) throws IOException
  {
    File configDir = getConfigPath(pod.getName());
    pod.store(configDir);
    
    return pod;
  }

  @Override
  public ICertificate getOrCreateCertificate(File file, String alias, X509Certificate x509Cert, boolean privateKeyEntry) throws BadFormatException, InvalidConfigException, IOException
  {
    Certificate newCert = Certificate.newBuilder(x509Cert)
       // .withKeyStore(file, alias, privateKeyEntry)
        .build(this);
    Certificate oldCert = getCertificate(newCert.getName());
    
    if(oldCert == null)
    {
      save(newCert);
      
      synchronized (certHashMap_)
      {
        certHashMap_.put(newCert.getName(), newCert);
        replaceChild(oldCert, newCert);
      }
      
      return newCert;
    }
    else
    {
      
      oldCert.modelUpdated(newCert);
    }
    return newCert; // TODO: FIXME
  }
  
  public void deleteCertificate(Certificate oldCertificate) throws IOException
  {
    File configDir = getConfigPath(oldCertificate.getName());
    
    deleteRecursively(configDir);
    
    synchronized (certHashMap_)
    {
      certHashMap_.remove(oldCertificate.getName());
      removeChild(oldCertificate);
    }
    
    oldCertificate.modelUpdated(null);
  }
}
