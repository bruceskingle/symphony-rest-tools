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

package org.symphonyoss.symphony.tools.rest.util.command;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.symphonyoss.symphony.tools.rest.util.ProgramFault;

public class CommandLineParser
{
  private static final String    EM_DASH   = "\u2014";

  private String                 commandName_;
  private Map<String, Flag<?>>   flagMap_  = new HashMap<>();
  private List<Flag<?>>          flags_    = new ArrayList<>();
  private Flag<?>                argSetter_;
  private int                    argc_;
  private Map<Character, Switch> switches_ = new HashMap<>();
  
  public CommandLineParser(String commandName)
  {
    commandName_ = commandName;
  }
  
  public CommandLineParser  withSwitch(Switch aswitch)
  {
    if(switches_.put(aswitch.getName(), aswitch) != null)
      throw new ProgramFault("Duplicate switch \"" + aswitch.getName() + "\"");
    
    if(flagMap_.containsKey(String.valueOf(aswitch.getName())))
      throw new ProgramFault("Switch duplicates flag \"" + aswitch.getName() + "\"");
    
    return this;
  }
  
  public CommandLineParser  withFlag(Flag<?> flag)
  {
    if(flag.getNames().isEmpty())
    {
      if(argSetter_ == null)
        argSetter_ = flag;
      else
        throw new ProgramFault("Only one nameless Flag is allowed");
    }
    else
    {
      for(String name : flag.getNames())
      {
        if(name.length()==1 && switches_.containsKey(name.charAt(0)))
          throw new ProgramFault("Flag duplicates switch \"" + name + "\"");
        
        if(flagMap_.put(name, flag) != null)
          throw new ProgramFault("Duplicate flag \"" + name + "\"");
      }
    }
    flags_.add(flag);
    
    return this;
  }
  
  public String getUsage()
  {
    StringBuilder s = new StringBuilder("Usage: ");
    
    s.append(commandName_);
    
    if(!switches_.isEmpty())
    {
      s.append(" [-");
      for(Character sw : switches_.keySet())
      {
        s.append(sw);
      }
      s.append("]");
    }
    
    for(Flag<?> flag : flags_)
    {
      String close = "";
      String sep = "";
      
      s.append(" ");
      
      if(!flag.isRequired())
        s.append("[");
      
      if(flag.getNames().size() > 1)
      {
        s.append("[");
        close = "] ";
      }
      else if(flag.getNames().isEmpty())
      {
        close = "";
      }
      else
      {
        close = " ";
      }
      
      for(String name : flag.getNames())
      {
        s.append(sep);
        
        sep = " | ";
        
        if(name.length() > 1)
          s.append("--");
        else
          s.append("-");
        
        s.append(name);
      }
      
      s.append(close);
      
      s.append(flag.getPrompt().replaceAll("  *", "_"));
      
      if(!flag.isRequired())
        s.append("]");
      
      if(flag.isDuplicatesAllowed())
        s.append("...");
    }
    
//    if(argSetter_ != null)
//    {
//      s.append(" ");
//      s.append(argSetter_.getPrompt().replaceAll("  *", "_"));
//      
//      if(argSetter_.isDuplicatesAllowed())
//        s.append("...");
//    }
    
    return s.toString();
  }
  
  public void process(String[] argv)
  {
    while(argc_ < argv.length)
    {
      String arg = argv[argc_++];
      
      if(arg.startsWith("--"))
      {
        handleFlag(arg.substring(2), arg, argv);
      }
      else if(arg.startsWith(EM_DASH))
      {
        handleFlag(arg.substring(1), arg, argv);
      }
      else if(arg.startsWith("-"))
      {
        char[] flags = arg.toCharArray();
        
        for(int i=1 ; i<flags.length ; i++)
        {
          Switch s = switches_.get(flags[i]);
  
          if(s == null)
          {
            throw new CommandLineParserFault("Unrecognized switch \"" + arg + "\"");
          }
          
          s.increment();
        }
      }
      else
      {
        if(argSetter_ == null)
        {
          throw new CommandLineParserFault("Invalid argument \"" + arg + "\"");
        }
        
        argc_--;
        set(null, argSetter_, argv);
      }
    }
  }

  private void handleFlag(String flagName, String arg, String[] argv)
  {
    Flag<?> flag = flagMap_.get(flagName);
    
    if(flag == null)
    {
      throw new CommandLineParserFault("Unrecognized flag \"" + arg + "\"");
    }
    
    set(arg, flag, argv);
  }

  private void set(String flagName, Flag<?> flag, String[] argv)
  {
    if(!flag.checkCount())
    {
      if(flagName == null)
        throw new CommandLineParserFault("Duplicate argument values not allowed");
      else
        throw new CommandLineParserFault("Duplicate values for flag \"" + flagName + "\" not allowed");
    }
      
    if(argc_ < argv.length)
      flag.set(argv[argc_++]);
    else if(flagName == null)
      throw new CommandLineParserFault("Insufficient argument values");
    else
      throw new CommandLineParserFault("Insufficient values for flag \"" + flagName + "\"");
  }

  public String getCommandName()
  {
    return commandName_;
  }

  public List<Flag<?>> getFlags()
  {
    return flags_;
  }
  
  public Flag<?> getFlag(String name)
  {
    return flagMap_.get(name);
  }

  public Flag<?> getArgSetter()
  {
    return argSetter_;
  }

  public Map<Character, Switch> getSwitches()
  {
    return switches_;
  }
}
