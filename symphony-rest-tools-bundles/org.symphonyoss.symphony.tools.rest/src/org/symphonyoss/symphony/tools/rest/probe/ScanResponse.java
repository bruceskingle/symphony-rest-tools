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

package org.symphonyoss.symphony.tools.rest.probe;

import java.util.ArrayList;
import java.util.List;

/**
 * Represents the results of scanning for something by making multiple
 * probes.
 * 
 * @author bruce.skingle
 *
 */
public class ScanResponse
{
  private final String          name_;
  
  private Probe         validProbe_;
  private List<Probe>   allProbes_ = new ArrayList<>();
  private List<Probe>   successfulProbes_ = new ArrayList<>();
  private List<Probe>   validProbes_ = new ArrayList<>();
  private List<Probe>   certAuthProbes_ = new ArrayList<>();
  
  public ScanResponse(String name)
  {
    name_ = name;
  }

  public void add(Probe probeResponse)
  {
    allProbes_.add(probeResponse);
    
    if(probeResponse.isFailedCertAuth())
      certAuthProbes_.add(probeResponse);
    else if(!probeResponse.isFailed())
    {
      if(probeResponse.isValid())
      {
        if(validProbes_.isEmpty())
          validProbe_ = probeResponse;
        else
          validProbe_ = null;
        
        validProbes_.add(probeResponse);
      }
      
      successfulProbes_.add(probeResponse);
    }
  }

  public String getName()
  {
    return name_;
  }

  public Probe getValidProbe()
  {
    return validProbe_;
  }

  public List<Probe> getCertAuthProbes()
  {
    return certAuthProbes_;
  }


//  public boolean isFailed()
//  {
//    return successfulProbes_.size() != 1;
//  }
//  
//  public boolean isProbable()
//  {
//    return successfulProbes_.size() != 1;
//  }
}
