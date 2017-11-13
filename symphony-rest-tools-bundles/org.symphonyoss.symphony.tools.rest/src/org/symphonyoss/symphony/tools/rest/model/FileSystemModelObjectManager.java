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

public class FileSystemModelObjectManager extends ModelObjectContainer
{
  private final File    configDir_;

  public FileSystemModelObjectManager(IModelObjectContainer parent, String typeName, String name, File configDir)
  {
    super(parent, typeName, name);
    configDir_ = configDir;
  }

  public File getConfigPath(String ...names)
  {
    File dir = configDir_;
    
    for(String name : names)
      dir = new File(dir, name);
    
    return dir;
  }

  public File getConfigDir()
  {
    return configDir_;
  }

  protected void deleteRecursively(File f)
  {
    if(f.isDirectory())
    {
      for(File ff : f.listFiles())
      {
        deleteRecursively(ff);
      }
    }
    f.delete();
  }
}
