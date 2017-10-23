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
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.symphonyoss.s2.common.crypto.cert.CertificateUtils;
import org.symphonyoss.symphony.tools.rest.ISrtSelectable;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.symphony.s2.common.exception.BadFormatException;
import com.symphony.s2.common.type.InvalidPersistentEnumException;

public class Certificate extends ModelObjectContainer implements ICertificate, ISrtSelectable
{
  public static final String        TYPE_NAME                    = "Certificate";
//  public static final String        TYPE_KEY_MANAGER             = "KeyManager";
//  public static final String        TYPE_SESSION_AUTH            = "SessionAuth";
//  public static final String        TYPE_KEY_AUTH                = "KeyAuth";
//
//  private static final String       FORMAT_1_AGENTS_NO_ARRAY     = "Agents element \"%s\" must be an array";
//  private static final String       FORMAT_1_PRINCIPALS_NO_ARRAY = "Principals element \"%s\" must be an array";
//
  private static final String       SUBJECT_NAME                 = "subject.name";
  private static final String       ISSUER_NAME                  = "issuer.name";
  private static final String       SUBJECT_ALTERNATE_NAMES      = "subject.alternate.names";
  private static final String       ISSUER_ALTERNATE_NAMES       = "issuer.alternate.names";
  private static final String       ALT_NAME_TYPE                = "type";
  private static final String       ALT_NAME_DESC                = "type.description";
  private static final String       ALT_NAME                     = "name";
  private static final String       REFS                         = "keystoreRefs";

  // Immutable Config
  private final String                subjectName_;
  private final String                issuerName_;
//  private final URL                 podUrl_;
//  private final URL                 webUrl_;
//  private final String              webTitle_;
//  private final URL                 podApiUrl_;
//  private final URL                 sessionAuthUrl_;
//  private final URL                 keyAuthUrl_;

  // Persistable State
//  private Long                      podId_;

  // Members
  private final CertificateManager          manager_;
  private final Map<String, KeystoreRef>    refsMap_ = new HashMap<>();
    
  /* package */ Certificate(CertificateManager manager, JsonNode config) throws InvalidConfigException
  {
    super(manager, TYPE_NAME, config);
    
    manager_ = manager;
    
    subjectName_   = getRequiredTextNode(config, SUBJECT_NAME);
    issuerName_    = getRequiredTextNode(config, ISSUER_NAME);
    
    JsonNode refsNode = config.get(REFS);
    
//    if(refsNode != null)
//    {
//      if(refsNode.isArray())
//      {
//        synchronized (refsMap_)
//        {
//          for(JsonNode node : ((ArrayNode)refsNode))
//          {         
//            Agent ref = new KeystoreRef(this, node);
//            
//            addAgent(ref);
//          }
//        }
//      }
//      else
//      {
//        throw new InvalidConfigException(String.format(FORMAT_1_AGENTS_NO_ARRAY, AGENTS));
//      }
//    }
    
//    JsonNode principalsNode = config.get(PRINCIPALS);
//    
//    if(principalsNode != null)
//    {
//      if(principalsNode.isArray())
//      {
//        synchronized (principalMap_)
//        {
//          for(JsonNode node : ((ArrayNode)principalsNode))
//          {            
//            Principal principal = new Principal(this, node);
//            
//            Principal oldAgent = principalMap_.put(principal.getName(), principal);
//            
//            if(oldAgent != null)
//            {
//              oldAgent.modelUpdated(principal);
//            }
//          }
//        }
//      }
//      else
//      {
//        throw new InvalidConfigException(String.format(FORMAT_1_PRINCIPALS_NO_ARRAY, AGENTS));
//      }
//    }
  }
  
//  public Agent addAgent(Agent agent)
//  {
//    Agent oldAgent = agentMap_.put(agent.getName(), agent);
//
//    if (oldAgent != null)
//    {
//      oldAgent.modelUpdated(agent);
//    }
//    
//    replaceChild(oldAgent, agent);
//    
//    return agent;
//  }
//  
//  public Agent addAgent(Agent.Builder agentBuilder) throws InvalidConfigException
//  {
//    return addAgent(agentBuilder.build(this));
//  }

  public static class X509Builder extends ModelObject.Builder
  {
    private final X509Certificate x509Certificate_;

    public X509Builder(X509Certificate x509Certificate) throws BadFormatException
    {
      x509Certificate_ = x509Certificate;
      try
      {
        jsonNode_.put(NAME, CertificateUtils.getFingerPrint(x509Certificate_));
        jsonNode_.put(SUBJECT_NAME, x509Certificate.getSubjectX500Principal().getName());
        putAltNames(jsonNode_, SUBJECT_ALTERNATE_NAMES, x509Certificate.getSubjectAlternativeNames());
        jsonNode_.put(ISSUER_NAME, x509Certificate.getIssuerX500Principal().getName());

        putAltNames(jsonNode_, ISSUER_ALTERNATE_NAMES, x509Certificate.getIssuerAlternativeNames());
      }
      catch (CertificateParsingException | CertificateEncodingException e)
      {
        throw new BadFormatException(e);
      }
    }
    
    private void putAltNames(ObjectNode jsonNode, String fieldName,
        Collection<List<?>> altNames)
    {
      if(altNames == null || altNames.isEmpty())
        return;
      
      ArrayNode altNamesNode = jsonNode.putArray(fieldName);
      
      for(List<?> altName : altNames)
      {
        if(altName.size()>1)
        {
          ObjectNode altNameNode = altNamesNode.addObject();
          
          String type;
          
          try
          {
            GeneralNameType nameType = GeneralNameType.newInstance((int)altName.get(0));
            
            altNameNode.put(ALT_NAME_TYPE, nameType.toInt());
            altNameNode.put(ALT_NAME_DESC, nameType.toString());
          }
          catch(ClassCastException | InvalidPersistentEnumException e)
          {
            altNameNode.put(ALT_NAME_DESC, "Unknown Type " + altName.get(0));
          }
          altNameNode.put(ALT_NAME, altName.get(1).toString());
        }
      }
    }

    public Certificate build(CertificateManager manager) throws InvalidConfigException
    {
      return new Certificate(manager, jsonNode_);
    }

    public X509Builder withKeystoreRef(File file, String alias, boolean privateKeyEntry)
    {
      // TODO Auto-generated method stub
      return null;
    }
  }
  

  
  public class KeystoreRef
  {
    private File    file_;
    private String  alias_;
    private boolean privateKeyEntry_;
    
    public KeystoreRef(File file, String alias, boolean privateKeyEntry)
    {
      file_ = file;
      alias_ = alias;
      privateKeyEntry_ = privateKeyEntry;
    }
  }
  
  public static X509Builder  newBuilder(X509Certificate x509Certificate) throws BadFormatException
  {
    return new X509Builder(x509Certificate);
  }

//  public static class Builder extends ModelObject.Builder
//  {
//    private URL podUrl_;
//    private URL podApiUrl_;
//    private URL webUrl_;
//    private URL keyManagerUrl_;
//    private URL keyAuthUrl_;
//    private URL sessionAuthUrl_;
//    
//    @Override
//    public Builder setName(String name)
//    {
//      super.setName(name);
//      return this;
//    }
//
//    @Override
//    public Builder addTrustCerts(Collection<X509Certificate> trustCerts)
//    {
//      super.addTrustCerts(trustCerts);
//      return this;
//    }
//    
//    @Override
//    public Builder addTrustCert(X509Certificate trustCert)
//    {
//      super.addTrustCert(trustCert);
//      return this;
//    }
//
//    public Builder setCertificateUrl(URL podUrl)
//    {
//      podUrl_ = podUrl;
//      putIfNotNull(jsonNode_, POD_URL, podUrl);
//      return this;
//    }
//
//    public Builder setWebUrl(URL webUrl)
//    {
//      webUrl_ = webUrl;
//      putIfNotNull(jsonNode_, WEB_URL, webUrl);
//      return this;
//    }
//
//    public Builder setWebTitle(String webTitle)
//    {
//      putIfNotNull(jsonNode_, WEB_TITLE, webTitle);
//      return this;
//    }
//
//    public Builder setKeyManagerUrl(URL keyManagerUrl)
//    {
//      keyManagerUrl_ = keyManagerUrl;
//      putIfNotNull(jsonNode_, KEY_MANAGER_URL, keyManagerUrl);
//      return this;
//    }
//
//    public Builder setSessionAuthUrl(URL sessionAuthUrl)
//    {
//      sessionAuthUrl_ = sessionAuthUrl;
//      putIfNotNull(jsonNode_, SESSION_AUTH_URL, sessionAuthUrl);
//      return this;
//    }
//
//    public Builder setKeyAuthUrl(URL keyAuthUrl)
//    {
//      keyAuthUrl_ = keyAuthUrl;
//      putIfNotNull(jsonNode_, KEY_AUTH_URL, keyAuthUrl);
//      return this;
//    }
//
//    public Builder setCertificateApiUrl(URL podApiUrl)
//    {
//      podApiUrl_ = podApiUrl;
//      putIfNotNull(jsonNode_, POD_API_URL, podApiUrl);
//      return this;
//    }
//    
//    public @Nullable URL getCertificateUrl()
//    {
//      return podUrl_;
//    }
//
//    public @Nullable URL getCertificateApiUrl()
//    {
//      return podApiUrl_;
//    }
//
//    public @Nullable URL getWebUrl()
//    {
//      return webUrl_;
//    }
//    
//    public @Nullable String getWebTitle()
//    {
//      return getOptionalTextNode(jsonNode_, WEB_TITLE);
//    }
//
//    public @Nullable URL getKeyManagerUrl()
//    {
//      return keyManagerUrl_;
//    }
//
//    public @Nullable URL getKeyAuthUrl()
//    {
//      return keyAuthUrl_;
//    }
//
//    public @Nullable URL getSessionAuthUrl()
//    {
//      return sessionAuthUrl_;
//    }
//
//    public Certificate build(CertificateManager manager) throws InvalidConfigException
//    {
//      return new Certificate(manager, jsonNode_);
//    }
//  }
//  
//  public static Builder  newBuilder()
//  {
//    return new Builder();
//  }
  
  @Override
  public void storeConfig(ObjectNode config, boolean includeMutable)
  {
    super.storeConfig(config, includeMutable);
    
    putIfNotNull(config, SUBJECT_NAME, subjectName_);
    putIfNotNull(config, ISSUER_NAME, issuerName_);
    
    // TODO: add alternate names
    
    if(includeMutable)
    {
//      putIfNotNull(config, POD_ID, podId_);
    }
    
//    synchronized (agentMap_)
//    {
//      if(!agentMap_.isEmpty())
//      {
//        ArrayNode agentsNode = config.putArray(AGENTS);
//        
//        for(Agent agent : agentMap_.values())
//        {
//          ObjectNode node = agentsNode.addObject();
//          
//          agent.storeConfig(node, includeMutable);
//        }
//      }
//    }
//    
//    synchronized (principalMap_)
//    {
//      if(!principalMap_.isEmpty())
//      {
//        ArrayNode principalsNode = config.putArray(PRINCIPALS);
//        
//        for(Principal principal : principalMap_.values())
//        {
//          ObjectNode node = principalsNode.addObject();
//          
//          principal.storeConfig(node, includeMutable);
//        }
//      }
//    }
  }

  @Override
  public ICertificateManager getManager()
  {
    return manager_;
  }

  /**
   * This object has been replaced with the given one.
   * 
   * @param newCertificate
   */
  public void modelUpdated(Certificate newCertificate)
  {
  }

  

  @Override
  public String getSubjectName()
  {
    return subjectName_;
  }

  @Override
  public String getIssuerName()
  {
    return issuerName_;
  }

  @Override
  public void save() throws IOException
  {
    manager_.save(this);
  }
  
  @Override
  public void delete() throws IOException
  {
    manager_.deleteCertificate(this);
  }

  @Override
  public Class<? extends IModelObject> getSelectionType()
  {
    return ICertificate.class;
  }
}
