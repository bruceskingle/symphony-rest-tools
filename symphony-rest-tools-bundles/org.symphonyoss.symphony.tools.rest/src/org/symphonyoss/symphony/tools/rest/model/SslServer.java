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
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;

import org.symphonyoss.symphony.tools.rest.util.ProgramFault;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

public class SslServer extends ModelObjectContainer implements ISslServerConfig
{
//  private static final String   TRUSTED_SERVER_CERTS                = "trustedServerCerts";
  
  private static final String   PKCS12                = "pkcs12";

  private final Set<X509Certificate> trustCerts_       = new HashSet<>();

  
  public SslServer(IModelObjectContainer parent, String typeName, JsonNode config) throws InvalidConfigException
  {
    super(parent, typeName, config);
    
//    JsonNode certsNode = config.get(TRUSTED_SERVER_CERTS);
//    
//    if(certsNode != null)
//    {
//      try
//      {
//        for(X509Certificate cert : CertificateUtils.decode(certsNode.asText()))
//        {
//          trustCerts_.add(cert);
//        }
//      }
//      catch (IOException e)
//      {
//        throw new InvalidConfigException(e);
//      }
//    }
  }
  
  public static class Builder extends ModelObject.Builder
  {
    private Set<X509Certificate> trustCerts_ = new HashSet<>();
    
    @Override
    public Builder setName(String name)
    {
      super.setName(name);
      return this;
    }

    public Builder addTrustCerts(Collection<X509Certificate> trustCerts)
    {
      trustCerts_.addAll(trustCerts);
      
//      jsonNode_.put(TRUSTED_SERVER_CERTS, CertificateUtils.encode(trustCerts_));
      return this;
    }
    
    public Builder addTrustCert(X509Certificate trustCert)
    {
      trustCerts_.add(trustCert);
      
//      jsonNode_.put(TRUSTED_SERVER_CERTS, CertificateUtils.encode(trustCerts_));
      return this;
    }

    public Set<X509Certificate> getTrustCerts()
    {
      return trustCerts_;
    }
    
//    public SslServerConfig build(IModelObject parent) throws InvalidConfigException
//    {
//      return new SslServerConfig(parent, jsonNode_);
//    }
  }
  
//  public static Builder  newBuilder()
//  {
//    return new Builder();
//  }

  @Override
  public void storeConfig(ObjectNode config, boolean includeMutable)
  {
    super.storeConfig(config, includeMutable);
    
//    if(!trustCerts_.isEmpty())
//      config.put(TRUSTED_SERVER_CERTS, CertificateUtils.encode(trustCerts_));
  }

  @Override
  public Set<X509Certificate>  getTrustCerts()
  {
    return new HashSet<X509Certificate>(trustCerts_);
  }

  public void importTrustStore(File trustStoreFile, String trustStorePassword)
  {
    try
    {
      KeyStore  trustStore      = KeyStore.getInstance(PKCS12);
      char[]    password        = trustStorePassword.toCharArray();
      
      try(InputStream stream = new FileInputStream(trustStoreFile))
      {
        trustStore.load(stream, password);
        
        Enumeration<String> en = trustStore.aliases();
        
        while(en.hasMoreElements())
        {
          Certificate cert = trustStore.getCertificate(en.nextElement());
          
          if(cert instanceof X509Certificate)
            trustCerts_.add((X509Certificate) cert);
          else
            throw new ProgramFault("Unexpected certificate type " + cert.getClass().getName());
        }
      }
    }
    catch (IOException | KeyStoreException | NoSuchAlgorithmException | CertificateException e)
    {
      addError("Unable to read truststore: " + e.getMessage());
    }
  }
  
  public void exportTrustStore(File trustStoreFile, String trustStorePassword)
  {
    try
    {
      KeyStore  trustStore      = KeyStore.getInstance(PKCS12);
      
      char[]    password        = trustStorePassword.toCharArray();
      int       certIndex       = 1;
      
      trustStore.load(null, null);
      
      for (X509Certificate cert : trustCerts_)
        trustStore.setCertificateEntry(String.valueOf(certIndex++), cert);
      
      try(OutputStream stream = new FileOutputStream(trustStoreFile))
      {
        trustStore.store(stream, password);
      }
    }
    catch (IOException | KeyStoreException | NoSuchAlgorithmException | CertificateException e)
    {
      throw new ProgramFault(e);
    }
  }
}
