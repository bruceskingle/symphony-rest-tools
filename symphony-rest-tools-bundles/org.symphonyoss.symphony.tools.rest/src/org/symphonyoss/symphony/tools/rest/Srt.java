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

package org.symphonyoss.symphony.tools.rest;

public class Srt
{
  public static final String   DEFAULT_DOMAIN          = ".symphony.com";

  public static final String   MIME_HTML               = "text/html";
  public static final String   MIME_JSON               = "application/json";
  public static final String   SESSION_TOKEN           = "sessionToken";
  public static final String   SKEY                    = "skey";
  public static final String   KMSESSION               = "kmsession";
  public static final String   KEYMANAGER_TOKEN        = "keyManagerToken";
  public static final String   DEFAULT_KEYSTORE_TYPE   = "pkcs12";
  public static final String   DEFAULT_TRUSTSTORE_TYPE = "jks";

  public static final String   TOKEN                   = "token";
  public static final String   DISPLAY_NAME            = "displayName";
  public static final String   ID                      = "id";
  public static final String   COMPANY                 = "company";
  public static final String[] SESSION_INFO_FIELDS     = new String[] { DISPLAY_NAME, ID, COMPANY };

  public static final String   POD_CLIENT_PATH         = "/client/index.html";
  public static final String   POD_HEALTHCHECK_PATH    = "/webcontroller/HealthCheck";
  public static final String   AUTHENTICATE_PATH       = "/v1/authenticate";
}
