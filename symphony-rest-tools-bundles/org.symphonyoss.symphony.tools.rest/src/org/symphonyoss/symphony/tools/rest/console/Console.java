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

package org.symphonyoss.symphony.tools.rest.console;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.util.Collection;
import java.util.Collections;
import java.util.Locale;
import java.util.concurrent.CopyOnWriteArrayList;

import javax.annotation.Nullable;

import org.symphonyoss.symphony.tools.rest.SrtCommand;
import org.symphonyoss.symphony.tools.rest.util.IObjective;
import org.symphonyoss.symphony.tools.rest.util.Objective;
import org.symphonyoss.symphony.tools.rest.util.ProgramFault;
import org.symphonyoss.symphony.tools.rest.util.command.CommandLineParserFault;
import org.symphonyoss.symphony.tools.rest.util.command.Flag;
import org.symphonyoss.symphony.tools.rest.util.home.IDefaultsProvider;
import org.symphonyoss.symphony.tools.rest.util.home.SrtCommandLineHome;

public class Console implements IConsole
{
  private final BufferedReader             in_;
  private final PrintWriter                out_;
  private final PrintWriter                err_;
  private IDefaultsProvider                defaultsProvider_;
  private CopyOnWriteArrayList<IObjective> objectives_ = new CopyOnWriteArrayList<>();
  private String taskName_;
  
  public Console(InputStream in, OutputStream out, OutputStream err)
  {
    in_ = new BufferedReader(new InputStreamReader(in));
    out_ = new PrintWriter(out);
    err_ = new PrintWriter(err);
  }
  
  public Console(BufferedReader in, PrintWriter out, PrintWriter err)
  {
    in_ = in;
    out_ = out;
    err_ = err;
  }

  public IDefaultsProvider getDefaultsProvider()
  {
    return defaultsProvider_;
  }

  @Override
  public void setDefaultsProvider(IDefaultsProvider defaultsProvider)
  {
    defaultsProvider_ = defaultsProvider;
  }

  @Override
  public String  promptString(String prompt, String defaultValue)
  {
    String s = doPromptString(prompt + "[" + defaultValue + "]");
    
    return s.equals("") ? defaultValue : s.trim();
  }

  @Override
  public String  promptString(String prompt)
  {
    return doPromptString(prompt).trim();
  }

  public String  doPromptString(String prompt)
  {
    out_.print(prompt);
    out_.print(": ");
    out_.flush();
    
    String line;

    try
    {
      line = in_.readLine();
    }
    catch (IOException e)
    {
      throw new ProgramFault("Error on console input.", e);
    }
    
    if(line == null)
      throw new ProgramFault("Unexpected end of file on console.");
    
    return line;
  }

  @Override
  public boolean  promptBoolean(String prompt)
  {
    while(true)
    {
      String line = promptString(prompt + "[n]");
      
      if(line.length()==0)                return false;
      if("y".equalsIgnoreCase(line))      return true;
      if("yes".equalsIgnoreCase(line))    return true;
      if("n".equalsIgnoreCase(line))      return false;
      if("no".equalsIgnoreCase(line))     return false;
      
      out_.println("Invalid input: enter y or n.");
    }
  }

  @Override
  public PrintWriter getOut()
  {
    return out_;
  }

  @Override
  public PrintWriter getErr()
  {
    return err_;
  }

  public void printStackTrace(Throwable e)
  {
    e.printStackTrace(err_);
  }

  @Override
  public void println()
  {
    out_.println();
  }

  @Override
  public String println(Object obj)
  {
    return doPrintf(true, obj.toString());
  }

  @Override
  public String printf(String format, Object... args)
  {
    return doPrintf(false, format, args);
  }

  @Override
  public String printf(Locale l, String format, Object... args)
  {
    return doPrintf(false, l, format, args);
  }
  
  @Override
  public String printfln(String format, Object... args)
  {
    return doPrintf(true, format, args);
  }
  
  @Override
  public String title(Locale l, String format, Object... args)
  {
    println();
    return doTitle(doPrintf(true, l, format, args));
  }
  
  @Override
  public String title(String format, Object... args)
  {
    println();
    return doTitle(doPrintf(true, format, args));
  }

  private String doTitle(String s)
  {
    StringBuffer b = new StringBuffer();
    
    for(int i=0 ; i<s.length() ; i++)
      b.append('=');
    
    println(b);
    return s;
  }

  @Override
  public String printfln(Locale l, String format, Object... args)
  {
    return doPrintf(true, l, format, args);
  }
  
  public String doPrintf(boolean newLine, String format, Object... args)
  {
    return doPrint(newLine, format(format, args));
  }
  
  public String doPrintf(boolean newLine, Locale l, String format, Object... args)
  {
    return doPrint(newLine, format(l, format, args));
  }
  
  public String doPrint(boolean newLine, String message)
  {
    if(newLine)
      out_.println(message);
    else
      out_.print(message);
    
    return message;
  }
  
  @Override
  public String error(@Nullable Throwable cause, @Nullable Locale l, String format, Object... args)
  {
    String message;
    RuntimeException internalFault = null;
    
    try
    {
      message = l == null ? format(format, args) : format(l, format, args);
    }
    catch(RuntimeException e)
    {
      message = format;
      internalFault = e;
    }
    // The Eclipse console does strange things all this flushing seems to work for all cases....
    out_.flush();
    err_.flush();
    err_.println(message);
    if(cause != null)
      cause.printStackTrace(err_);
    
    if(internalFault != null)
    {
      err_.println("Additionally this exception was thrown formatting the error message above from:");
      err_.printf("Format   %s%n", format);
      
      for(int i=0 ; i<args.length ; i++)
      {
        err_.printf("arg[%2d] %s%n", args[i]);
      }
      
      err_.printf("%d args in total%n", args.length);
      
      internalFault.printStackTrace(err_);
    }
    err_.flush();
    
    return message;
  }

  @Override
  public String error(Locale l, String format, Object... args)
  {
    return error((Throwable)null, l, format, args);
  }

  @Override
  public String error(@Nullable Throwable cause, String format, Object ...args)
  {
    return error(cause, (Locale)null, format, args);
  }
  
  @Override
  public String error(String format, Object ...args)
  {
    return error((Throwable)null, (Locale)null, format, args);
  }

  @Override
  public void close()
  {
    err_.close();
    out_.close();
    try
    {
      in_.close();
    }
    catch (IOException e)
    {
      throw new ProgramFault(e);
    }
  }

  @Override
  public void flush()
  {
    err_.flush();
    out_.flush();
  }

  public boolean setParameters(SrtCommandLineHome parser, int interactiveCount)
  {
    boolean abort = false;
    boolean promptAll = false;
    
    printfln("Press RETURN to accept default values");
    printfln("Enter a space to clear the default value");
    printfln("Leading and trailing whitespace are deleted");
    
    switch(interactiveCount)
    {
      case 0:
        for(Flag<?> flag : parser.getFlags())
        {
          if(flag.isRequired() && flag.getCount()==0)
          {
            error("A value for " + flag.getDescription() + " is required.\n");
            abort = true;
          }
        }
        break;
      
      case 2:
        promptAll = true;
        // Fall through
        
      default:
        for(Flag<?> flag : parser.getFlags())
        {
          if(promptAll || flag.isRequired())
          {
            boolean doAgain;
            
            do
            {
              doAgain = false;
              
              String defaultValue = flag.getValue();
              
              if(defaultValue.length()==0)
                defaultValue = defaultsProvider_.getDefault(flag.getPrompt());
              
              String value = promptString(flag.getPrompt(), defaultValue);
              
              try
              {
                flag.set(value);
                if(flag.isRequired() && value.length()==0)
                {
                  error("A value is required\n");
                  doAgain=true;
                }
              }
              catch(CommandLineParserFault e)
              {
                doAgain = true;
              }
            } while(doAgain);
          }
        }
    }
    
    if(!abort)
    {
      for(Flag<?> flag : parser.getFlags())
      {
        defaultsProvider_.setDefault(flag.getPrompt(), flag.getValue());
      }
    }
    
    return abort;
  }

  @Override
  public void execute(SrtCommand srtCommand)
  {
    try
    {
      boolean abort = setParameters(srtCommand.getParser(), srtCommand.getInteractive().getCount());
      
      if(abort)
      {
        error("Aborted.");
      }
      else
      {
        srtCommand.doExecute();

        
      }
    }
    catch(Exception e)
    {
      error(e, "Command \"%s\" terminated unexpectedly.", srtCommand.getName());
    }
  }

  @Override
  public String beginTask(int totalWork, String format, Object... args)
  {
    if(taskName_ != null)
      throw new IllegalStateException("This method can be called only once per Console.");
    
    taskName_ = format(format, args);
    return title(taskName_);
  }

  @Override
  public void taskDone()
  {
  }

  @Override
  public boolean isTaskCanceled()
  {
    return false;
  }

  @Override
  public String setTaskName(String format, Object... args)
  {
    taskName_ = format(format, args);
    return title(taskName_);
  }

  @Override
  public String beginSubTask(String format, Object... args)
  {
    if(taskName_ == null)
      throw new IllegalStateException("You must call beginTask before this method.");
    
    return title("%s: %s", taskName_, format(format, args));
  }

  private String format(Locale l, String format, Object...args)
  {
    if(format == null)
      return "";
    
    return String.format(l, format, args);
  }
  
  private String format(String format, Object...args)
  {
    if(format == null)
      return "";
    
    return String.format(format, args);
  }

  @Override
  public boolean taskWorked(int work)
  {
    return isTaskCanceled();
  }
  
  @Override
  public IObjective createObjective(String name)
  {
    IObjective objective = new Objective(name);
    
    objectives_.add(objective);
    
    return objective;
  }

  @Override
  public Iterable<IObjective> getObjectives()
  {
    return objectives_;
  }
  
  @Override
  public Collection<IObjective> copyObjectives()
  {
    return Collections.unmodifiableList(objectives_);
  }
  
  @Override
  public boolean hasObjectives()
  {
    return !objectives_.isEmpty();
  }

  /**
   * Allow this console to be re-used to support composite commands in command line mode.
   * 
   * This is not supported in a UI context and this method is not present in IConsole.
   */
  public void reset()
  {
    taskName_ = null;
  }
}
