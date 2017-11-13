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
import java.io.IOException;

import javax.annotation.Nullable;

import org.symphonyoss.symphony.tools.rest.console.IConsole;
import org.symphonyoss.symphony.tools.rest.model.osmosis.IComponentProxy;
import org.symphonyoss.symphony.tools.rest.util.IVisitor;

import com.fasterxml.jackson.databind.node.ObjectNode;

public interface IModelObject extends IComponentProxy
{
  static final String CONFIG_FILE_NAME = "config";
  static final String DOT_JSON         = ".json";
  

  
  /**
   * Returns the parent for the given element, or <code>null</code>
   * indicating that it is a top level node.
   *
   * @return the parent element, or <code>null</code> if it
   *   has none or if the parent cannot be computed
   */
  @Nullable IModelObject  getParent();
  
  String                  getTypeName();
  String                  getName();
  String                  getErrorText();
  void                    print(IConsole console);
  ObjectNode              toJson();
  void store(File configDir, String fileName) throws IOException;
  void store(File configDir) throws IOException;

  void visit(IVisitor<IModelObject> visitor);
}
