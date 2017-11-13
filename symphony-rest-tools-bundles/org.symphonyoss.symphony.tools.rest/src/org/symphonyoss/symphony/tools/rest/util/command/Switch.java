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

public class Switch
{
  private final char   name_;
  private final String label_;
  private final String help_;
  private final int    max_;
  private int          count_;
  
  public Switch(char name, String label, String help)
  {
    this(name, label, help, 1);
  }
  
  public Switch(char name, String label, String help, int max)
  {
    name_ = name;
    label_ = label;
    help_ = help;
    max_ = max;
  }
  
  public void setCount(int count)
  {
    count_ = count> max_ ? max_ : count;
  }

  public void increment()
  {
    count_++;
    if(count_ > max_)
    {
      if(max_ == 1)
        throw new CommandLineParserFault("Switch \"" + name_ + "\" may be set only once");
      else
        throw new CommandLineParserFault("Switch \"" + name_ + "\" may be set at most " + max_ + " times");
    }
  }

  public int getCount()
  {
    return count_;
  }

  public char getName()
  {
    return name_;
  }

  public String getLabel()
  {
    return label_;
  }

  public int getMax()
  {
    return max_;
  }

  public String getHelp()
  {
    return help_;
  }
}
