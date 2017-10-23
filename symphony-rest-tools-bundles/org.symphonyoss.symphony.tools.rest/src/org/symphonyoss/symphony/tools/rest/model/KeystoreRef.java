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
import java.net.MalformedURLException;
import java.net.URL;

import javax.annotation.Nullable;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

public class KeystoreRef extends ModelObject implements IKeystoreRef
{
  public static final String FILE_NAME   = "file.name";
  public static final String ALIAS       = "alias";
  public static final String PRIVATE_KEY = "isPrivateKey";

  public static final String TYPE_NAME   = "KeystoreRef";

  // Immutable Config
  private final File         file_;
  private final String       alias_;
  private final boolean      privateKey_;
  
  // Persistable State
  
  // Members
  private final Certificate cert_;

  /* package */ KeystoreRef(Certificate cert, JsonNode config, File base) throws InvalidConfigException
  {
    super(cert, TYPE_NAME, config);
    
    cert_ = cert;
    file_ = getRequiredFileNode(config, FILE_NAME, base);
    alias_ = getRequiredTextNode(config, ALIAS);
    privateKey_ = getRequiredBooleanNode(config, PRIVATE_KEY);
  }
  
  public static class Builder extends ModelObject.Builder
  {
    private File         file_;
    private String       alias_;
    private boolean      privateKey_;
    
    public Builder setFile(File file)
    {
      file_ = file;
      putIfNotNull(jsonNode_, FILE_NAME, file_);
      return this;
    }
    
    public Builder setAlias(String alias)
    {
      alias_ = alias;
      putIfNotNull(jsonNode_, ALIAS, alias_);
      return this;
    }
    
    public Builder setPrivateKey(boolean privateKey)
    {
      privateKey_ = privateKey;
      jsonNode_.put(PRIVATE_KEY, privateKey);
      return this;
    }
    
    public File getFile()
    {
      return file_;
    }

    public String getAlias()
    {
      return alias_;
    }

    public boolean isPrivateKey()
    {
      return privateKey_;
    }

    public KeystoreRef build(Certificate cert, File base) throws InvalidConfigException
    {
      return new KeystoreRef(cert, jsonNode_, base);
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
    
    putIfNotNull(jsonNode, FILE_NAME, file_);
    putIfNotNull(jsonNode, ALIAS, alias_);
    jsonNode.put(PRIVATE_KEY, privateKey_);
  }

  @Override
  public String getTypeName()
  {
    return TYPE_NAME;
  }

  @Override
  public File getFile()
  {
    return file_;
  }

  @Override
  public String getAlias()
  {
    return alias_;
  }

  @Override
  public boolean isPrivateKey()
  {
    return privateKey_;
  }

  @Override
  public IModelObject getParent()
  {
    return cert_;
  }
}
