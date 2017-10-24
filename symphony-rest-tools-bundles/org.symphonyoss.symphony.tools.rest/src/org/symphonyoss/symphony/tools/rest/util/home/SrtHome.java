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

package org.symphonyoss.symphony.tools.rest.util.home;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.Reader;
import java.io.Writer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.util.EnumSet;
import java.util.Properties;

import org.symphonyoss.symphony.tools.rest.console.IConsole;
import org.symphonyoss.symphony.tools.rest.model.ICertificateManager;
import org.symphonyoss.symphony.tools.rest.model.IPodManager;
import org.symphonyoss.symphony.tools.rest.model.PodManager;
import org.symphonyoss.symphony.tools.rest.util.ProgramFault;
import org.symphonyoss.symphony.tools.rest.util.command.CommandLineParserFault;

public class SrtHome implements ISrtHome
{
  private final File        home_;
  private final String      setBy_;
  private final File        configDir_;
  private final File        sessionDir_;
  private final IConsole     console_;
  private final IPodManager podManager_;
  private File              defaultsFile_;
  private Properties        defaultsProps_; //TODO: switch to JSON

  public SrtHome(IConsole console)
  {
    this(console, null, null);
  }
  
  public SrtHome(IConsole console, String homeStr, String setBy)
  {
    console_ = console;
    console_.setDefaultsProvider(this);
    
    Builder builder = new Builder(homeStr, setBy);
    
    home_ = builder.builderHome_;
    setBy_ = builder.setBy_;
    
    console_.printfln(SRT_HOME + " set by " + setBy_);
    
    if (!home_.exists())
      throw new CommandLineParserFault(SRT_HOME + " \"" +
          home_.getAbsolutePath() + "\" set by " + setBy_ + " does not exist.");
    
    configDir_ = new File(home_, "config");
    configDir_.mkdirs();
    
    sessionDir_ = new File(home_, "session");
    sessionDir_.mkdirs();
    
    podManager_ = new PodManager(configDir_);
    
    defaultsFile_ = new File(home_, "defaults.properties");
    defaultsProps_ = new Properties();
    
    try(Reader reader = new FileReader(defaultsFile_))
    {
      defaultsProps_.load(reader);
    }
    catch (FileNotFoundException e)
    {
      // No defaults
    }
    catch (IOException e)
    {
      throw new ProgramFault("Unable to read defaults file \"" + defaultsFile_.getAbsolutePath() + "\"", e);
    }
  }
  
  private class Builder
  {
    private File    builderHome_;
    private String  setBy_;
    
    public Builder(String homeStr, String setBy)
    {
      setHome(homeStr, setBy);
  
      if(builderHome_ == null)
      {
        setHome(System.getProperty(SRT_HOME), "System Property");
      }
      
      if(builderHome_ == null)
      {
        setHome(System.getenv(SRT_HOME), "Environment Variable");
      }
      
      if (builderHome_ == null)
      {
        builderHome_ = new File(new File(System.getProperty("user.home")), ".srt");
        setBy_ = "Default";
  
        if (!builderHome_.exists())
        {
          try
          {
            Path dir = builderHome_.toPath();
  
            Files.createDirectory(dir);
            
            console_.printfln("Default home area \"" +
                builderHome_.getAbsolutePath() + "\" created.");
            
            try
            {
              Files.setPosixFilePermissions(dir, 
                EnumSet.of( PosixFilePermission.OWNER_READ,
                            PosixFilePermission.OWNER_WRITE,
                            PosixFilePermission.OWNER_EXECUTE));
            }
            catch(UnsupportedOperationException e)
            {
              console_.printfln("But we are unable to make this drectory read only to the owner, this is expected when running on Windows.");
            }
          }
          catch (IOException e)
          {
            throw new CommandLineParserFault("Cannot create default home area \"" +
                builderHome_.getAbsolutePath() + "\"", e);
          }
        }
      }
    }
  
    private void setHome(String homeStr, String setBy)
    {
      if(homeStr != null)
      {
        homeStr = homeStr.trim();
        
        if(!homeStr.isEmpty())
        {
          builderHome_ = new File(homeStr);
          setBy_ = setBy;
        }
      }
    }
  }

  @Override
  public File getHome()
  {
    return home_;
  }

  public String getSetBy()
  {
    return setBy_;
  }
  
  @Override
  public File getConfigDir(String name)
  {
    return new File(configDir_, name);
  }

  @Override
  public void saveSessionToken(String hostName, String tokenName, String token)
  {
    File dir = new File(sessionDir_, hostName);
    
    dir.mkdirs();
    
    File file = new File(dir, tokenName);
    
    try(FileOutputStream fos = new FileOutputStream(file);
        PrintWriter p = new PrintWriter(fos);)
    {
      p.println(token);
    }
    catch (IOException e)
    {
      throw new ProgramFault("Unable to save session token " + file.getAbsolutePath(), e);
    }
  }

  @Override
  public IPodManager getPodManager()
  {
    return podManager_;
  }

  @Override
  public ICertificateManager getCertificateManager()
  {
    // TODO Auto-generated method stub
    return null;
  }

  @Override
  public String getDefault(String label)
  {
    return defaultsProps_.getProperty(labelToPropName(label), "");
  }
  
  @Override
  public void setDefault(String label, String name)
  {
    label = labelToPropName(label);
    
    String current = defaultsProps_.getProperty(label);
    
    if(current != null && current.equals(name))
      return;
    
    defaultsProps_.setProperty(label, name);
    try(Writer writer = new FileWriter(defaultsFile_))
    {
      defaultsProps_.store(writer, "");
    }
    catch (IOException e)
    {
      throw new ProgramFault("Unable to write defaults file \"" + defaultsFile_.getAbsolutePath() + "\"", e);
    }
  }

  private String labelToPropName(String label)
  {
    return label.replaceAll("  *", "");
  }
}
