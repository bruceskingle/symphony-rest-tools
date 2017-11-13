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

import java.io.IOException;
import java.net.ConnectException;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.net.UnknownHostException;
import java.security.cert.Certificate;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.annotation.Nonnull;
import javax.net.ssl.SSLHandshakeException;

import org.symphonyoss.symphony.jcurl.JCurl;
import org.symphonyoss.symphony.jcurl.JCurl.Builder;
import org.symphonyoss.symphony.jcurl.JCurl.HttpMethod;
import org.symphonyoss.symphony.tools.rest.Srt;
import org.symphonyoss.symphony.tools.rest.SrtCommand;
import org.symphonyoss.symphony.tools.rest.console.IConsole;
import org.symphonyoss.symphony.tools.rest.model.Agent;
import org.symphonyoss.symphony.tools.rest.model.IPod;
import org.symphonyoss.symphony.tools.rest.model.InvalidConfigException;
import org.symphonyoss.symphony.tools.rest.model.Pod;
import org.symphonyoss.symphony.tools.rest.model.osmosis.ComponentStatus;
import org.symphonyoss.symphony.tools.rest.util.IObjective;
import org.symphonyoss.symphony.tools.rest.util.ProgramFault;
import org.symphonyoss.symphony.tools.rest.util.SubTaskMonitor;
import org.symphonyoss.symphony.tools.rest.util.command.Switch;
import org.symphonyoss.symphony.tools.rest.util.home.ISrtHome;

import com.fasterxml.jackson.databind.JsonNode;

public class ProbePod extends SrtCommand
{
  private static final String   PROGRAM_NAME = "ProbePod";

  private static final int[]    POD_PORTS    = new int[] { 443, 8443 };
  private static final int[]    AUTH_PORTS   = new int[] { 8444, 8445, 8446 };
  private static final int[]    AgentPorts   = new int[] { 443, 8444, 8445, 8446 };
  private static final String[] SUFFIXES     = new String[] { "-api", "" };

  private static final int PROBE_POD_WORK = 6;
  private static final int AUTH_PROBE_WORK = 1;
  private static final int AGENT_PROBE_WORK = 1;
  private static final int SAVE_CONFIG_WORK = 2;

  private static final String WEBSITE_NOT_POD = "This is a website but not a pod";

  private static final String PROBING = "Probing...";

  private static final String NO_WEB_SERVER = "There is no web server here";

  private static final String UNABLE_TO_LOCATE_URL = "Unable to locate URL";

  private static final String UNABLE_TO_AUTHENTICATE = "Unable to authenticate";

  private boolean               podHealthy_;
  private int                   podId_;

  private ScanResponse          sessionAuthResponse_;
  private ScanResponse          keyAuthResponse_;

  private Probe                 sessionInfoResult_;
  private ScanResponse          agentResponse_;

  private Pod.Builder           podConfig_   = Pod.newBuilder();
  private Agent.Builder         agentConfig_ = Agent.newBuilder();
  private Set<X509Certificate>  serverCerts_ = new HashSet<>();
  
  private Switch               overwriteConfig_;

  private IObjective podObjective_;

  private IObjective keyManagerObjective_;

  private IObjective podApiObjective_;

  private IObjective agentObjective_;

  private IObjective sessionAuthObjective_;

  private IObjective keyAuthObjective_;

  private String sessionToken_;

  private String keymanagerToken_;
  
  public static void main(String[] argv) throws IOException
  {
    new ProbePod(argv).run();
  }

  public ProbePod(IConsole console, ISrtHome srtHome)
  {
    super(PROGRAM_NAME, console, srtHome);
  }

  public ProbePod(String[] argv)
  {
    super(PROGRAM_NAME, argv);
  }

  @Override
  protected void init()
  {
    super.init();
//    interactive_.setCount(2);

    withHostName(true);
    withKeystore(false);
    withTruststore(false);
    
    overwriteConfig_ = new Switch('s', "Overwrite Config", "Overwrite any existingsaved config for this pod", 1);
    
    getParser()
      .withSwitch(overwriteConfig_);
    
    podObjective_ = createObjective("Locate Pod");
    sessionAuthObjective_ = createObjective("Locate Session Auth Endpoint");
    podApiObjective_ = createObjective("Locate Pod API Endpoint");
    keyManagerObjective_ = createObjective("Locate Key Manager");
    keyAuthObjective_ = createObjective("Locate Key Manager Auth Endpoint");
    agentObjective_ = createObjective("Locate Agent");
  }
  
  @Override
  protected Builder getJCurl()
  {
    Builder builder = super.getJCurl()
        .trustAllHostnames(true)
        .trustAllCertificates(true);
    
    return builder;
  }

  @Override
  public void execute()
  {
    podConfig_.setName(getFqdn());
    
    IPod pod = getSrtHome().getPodManager().getPod(getFqdn());
//    boolean   doProbe = true;
//
//    if(pod != null)
//    {
//      println("We have an existing config for this Pod:");
//      println("========================================");
//      
//      pod.print(getOut());
//      
//      doProbe = promptBoolean("Continue with probe?");
//    }
//    
//    if(!doProbe)
//    {
//      error("Aborted.");
//      return;
//    }
    
    int totalWork = (PROBE_POD_WORK  * POD_PORTS.length) + AUTH_PROBE_WORK + AGENT_PROBE_WORK + SAVE_CONFIG_WORK;
    
    beginTask(totalWork, "Probing %s for a Pod", getFqdn());
    podObjective_.setObjectiveStatus(ComponentStatus.Starting, PROBING);
    podApiObjective_.setObjectiveStatus(ComponentStatus.Starting, PROBING);
    sessionAuthObjective_.setObjectiveStatus(ComponentStatus.Starting, PROBING);

    println("Probing for Pod");
    println("===============");
    
    int skippedWork = PROBE_POD_WORK  * POD_PORTS.length;
    
    for(int port : POD_PORTS)
    {
      if(isTaskCanceled())
        return;
      
      probePod(port);
      
      skippedWork -= PROBE_POD_WORK;
      
      if(podConfig_.getPodUrl() != null)
        break;
    }
    
    if(skippedWork > 0)
      taskWorked(skippedWork);
    
    if(podConfig_.getWebUrl() == null)
    {
      flush();
      error("Probe did not even find a website.");
      podObjective_.setObjectiveStatus(ComponentStatus.Failed, NO_WEB_SERVER);
      
      podObjective_.setObjectiveStatus(ComponentStatus.Failed, NO_WEB_SERVER);
      podApiObjective_.setObjectiveStatus(ComponentStatus.Failed, NO_WEB_SERVER);
      sessionAuthObjective_.setObjectiveStatus(ComponentStatus.Failed, NO_WEB_SERVER);
      
      return;
    }
    
    if(podConfig_.getPodUrl() == null)
    {
      println();
      println("Probe Reveals a Website but no Pod");
      println("==================================");
      
      String  format = "%-20s=%s\n";
      
      printf(format, "Web URL", podConfig_.getWebUrl());
      println();
      
      podObjective_.setObjectiveStatus(ComponentStatus.Failed, WEBSITE_NOT_POD);
      podApiObjective_.setObjectiveStatus(ComponentStatus.Failed, WEBSITE_NOT_POD);
      sessionAuthObjective_.setObjectiveStatus(ComponentStatus.Failed, WEBSITE_NOT_POD);
      
      return;
    }
    else
    {
      if(isTaskCanceled())
        return;
      
      podObjective_.setObjectiveStatusOK();
      
      if(podConfig_.getPodApiUrl() == null)
        podApiObjective_.setObjectiveStatus(ComponentStatus.Failed, UNABLE_TO_LOCATE_URL);
      else
        podApiObjective_.setObjectiveStatusOK();
      
      if(podConfig_.getSessionAuthUrl() == null)
      {
        sessionAuthObjective_.setObjectiveStatus(ComponentStatus.Failed, UNABLE_TO_LOCATE_URL);
      }
      else
      {
        if(sessionToken_ == null)
        {
          sessionAuthObjective_.setObjectiveStatus(ComponentStatus.Warning, UNABLE_TO_AUTHENTICATE);
        }
        else
        {
          sessionAuthObjective_.setObjectiveStatusOK();
        }
      }

      if(podConfig_.getKeyManagerUrl() == null)
      {
        println("No podInfo, try to look for an in-cloud key manager...");
        
        podConfig_.setKeyManagerUrl(createURL(podConfig_.getPodUrl(), "/relay"));
      }
      
      // How can this ever be true?
      if(podConfig_.getKeyManagerUrl() == null)
      {
        // We found a pod but can't get podInfo - fatal error
        podObjective_.setObjectiveStatus(ComponentStatus.Failed, "Can't get podinfo");
        return;
      }
      
      keyManagerObjective_.setObjectiveStatus(ComponentStatus.Starting, PROBING);
      
      URL kmUrl = podConfig_.getKeyManagerUrl();
      String keyManagerDomain;
      String keyManagerName = kmUrl.getHost();
      
      int i = keyManagerName.indexOf('.');

      if (i == -1)
        keyManagerDomain = Srt.DEFAULT_DOMAIN;
      else
      {
        keyManagerDomain = keyManagerName.substring(i);
        keyManagerName = keyManagerName.substring(0, i);
      }

      println("keyManagerName=" + keyManagerName);
      println("keyManagerDomain=" + keyManagerDomain);
      

      // Need to find a reliable health check indicator of keymanager in
      // all deployments, for now assume that as the pod told is this
      // is the KM that it is.
      
//      Builder builder = getJCurl();
//      builder = cookieAuth(builder);
//      
//      ProbeResponse response = probe(builder.build(), keyManagerName + keyManagerDomain, podConfig_.getKeyManagerUrl(), MIME_HTML);
//      
//      if(response.isFailed())
//        return;
      println("Found key manager at " + podConfig_.getKeyManagerUrl());
      keyManagerObjective_.setObjectiveStatusOK();
      
      if(isTaskCanceled())
        return;

      println();
      println("Probing for API Keyauth");
      println("=======================");

      keyAuthObjective_.setObjectiveStatus(ComponentStatus.Starting, PROBING);
      SubTaskMonitor subTaskMonitor = new SubTaskMonitor(getConsole(), "Probing for API Keyauth", AUTH_PROBE_WORK);
      
      keyAuthResponse_ = probeAuth("Key Auth", "/keyauth", keyManagerName, keyManagerDomain);
      
      if(keyAuthResponse_ != null)
      {
        podConfig_.setKeyAuthUrl(getUrl(keyAuthResponse_, Srt.TOKEN));
        
        String token = getTag(keyAuthResponse_, Srt.TOKEN);
        
        if(token != null)
        {
          keymanagerToken_ = token;
          getSrtHome().saveSessionToken(getFqdn(), Srt.KEYMANAGER_TOKEN, token);
        }
      }
      
      if(podConfig_.getSessionAuthUrl() == null)
      {
        keyAuthObjective_.setObjectiveStatus(ComponentStatus.Failed, UNABLE_TO_LOCATE_URL);
      }
      else
      {
        if(keymanagerToken_ == null)
        {
          keyAuthObjective_.setObjectiveStatus(ComponentStatus.Warning, UNABLE_TO_AUTHENTICATE);
        }
        else
        {
          keyAuthObjective_.setObjectiveStatusOK();
        }
      }
      
      if(subTaskMonitor.worked(1))
        return;


      agentObjective_.setObjectiveStatus(ComponentStatus.Starting, PROBING);
      subTaskMonitor = new SubTaskMonitor(getConsole(), "Probing for API Agent", AUTH_PROBE_WORK);
      println();
      println("Probing for API Agent");
      println("=====================");
      
      agentResponse_ = probeAgent(getName(), getDomain());
      
      URL agentUrl = getUrl(agentResponse_, null);
      
      if(agentUrl != null)
      {
        agentConfig_.setName(agentUrl.getHost());
        agentConfig_.setAgentApiUrl(agentUrl);
        agentObjective_.setObjectiveStatusOK();
      }
      else
      {
        agentObjective_.setObjectiveStatus(ComponentStatus.Failed, UNABLE_TO_LOCATE_URL);
      }
      
      if(subTaskMonitor.worked(1))
        return;
      
      println();
      println("Probe Successful");
      println("================");
      
      String  format = "%-20s=%s\n";
      
      printf(format, "Web URL", podConfig_.getWebUrl());
      printf(format, "Pod URL", podConfig_.getPodUrl());
      printf(format, "Pod ID", podId_);
      printf(format, "Key Manager URL", podConfig_.getKeyManagerUrl());
      printf(format, "Session Auth URL", podConfig_.getSessionAuthUrl());
      printf(format, "Key Auth URL", podConfig_.getKeyAuthUrl());
      printf(format, "Pod API URL", podConfig_.getPodApiUrl());
      printf(format, "Agent API URL", agentConfig_.getAgentApiUrl());
      
      

      if(getKeystore() != null)
      {
        println();
        printf(format, "Client cert", getKeystore());
        
        if(sessionInfoResult_.isFailed())
        {
          println("This cert was not accepted for authentication");
        }
        else
        {
          println("We authenticated as");
          for(String field : Srt.SESSION_INFO_FIELDS)
            printf(format, "userInfo." + field, sessionInfoResult_.getJcurlResponse().getTag(field));
        }
      }
      println();
    }
    
    if(isTaskCanceled())
      return;

        
    println("Root server certs:");
    for (X509Certificate cert : podConfig_.getTrustCerts())
      println(cert.getSubjectX500Principal().getName());

    println();
    println("End server certs:");
    for (X509Certificate cert : serverCerts_)
      println(cert.getSubjectX500Principal().getName());
        
    if(isTaskCanceled())
      return;

    if(pod==null || overwriteConfig_.getCount()>0)
    {
      System.err.println("OK");
    }
    
    if(pod==null || overwriteConfig_.getCount()>0)
    {
      SubTaskMonitor subTaskMonitor = new SubTaskMonitor(getConsole(), "Saving Configuration", SAVE_CONFIG_WORK);

      try
      {
        getSrtHome().getPodManager().createOrUpdatePod(podConfig_, agentConfig_);
      }
      catch (InvalidConfigException | IOException e)
      {
        error(e, "Faild to save config:");
      }
      
      if(subTaskMonitor.worked(1))
        return;

//        if(agentConfig_.getAgentApiUrl() != null)
//          pod.createOrUpdateAgent(agentConfig_);
      error("Finished.");
    }
  }

  private URL getUrl(ScanResponse scanResponse, String token)
  {
    URL url = null;
    
    if(scanResponse.getValidProbe() != null)
    {
      url = scanResponse.getValidProbe().getBaseUrl();
      
      if(token == null)
        println("Found " + scanResponse.getName() + " endpoint at " + url);
      else if(getTag(scanResponse, token) != null)
        println("Found " + scanResponse.getName() + " endpoint at " + url + " and we authenticated!");
      else
        println("Found " + scanResponse.getName() + " endpoint at " + url + " but we failed to authenticate.");
    }
    else
    {
      List<Probe> certAuthProbes = scanResponse.getCertAuthProbes();
      
      if(certAuthProbes.size() == 1)
      {
        url = certAuthProbes.get(0).getBaseUrl();
        println("Found probable " + scanResponse.getName() + " endpoint at " + url);

      }
      else if(certAuthProbes.size() > 1)
      {
        for(Probe p : certAuthProbes)
          println("Found possible " + scanResponse.getName() + " endpoint at " + p.getBaseUrl());
      }
      else
      {
        println("Failed to find any " + scanResponse.getName() + " endpoint");
      }
    }
    return url;
  }

  private void probePod(int port)
  {
    SubTaskMonitor subTaskMonitor = new SubTaskMonitor(getConsole(), "Probing Port " + port, PROBE_POD_WORK);
    
    Probe probe = new Probe(getName(), "", getDomain(), port,
        "/");
    
    doProbe(probe);
    
    if (probe.isFailed())
    {
      if (probeNonSSL(port))
        println("This is a non-SSL website");
      else
        println("This is not a website");

      subTaskMonitor.done();
      
      return;
    }
    else if(podConfig_.getWebUrl() == null)
    {
      podConfig_.setWebUrl(probe.getProbeUrl());
    }
    
    if(subTaskMonitor.worked(1))
      return;
    

    probe = new Probe(getName(), getDomain(), "", port,
        "/").setProbePath(Srt.POD_CLIENT_PATH, Srt.MIME_HTML);
    
    doProbe(probe);
    
    if (probe.isFailed())
    {
      println("This is a website but not a Symphony Pod");
      
      subTaskMonitor.done();
      
      return;
    }

    Probe healthCheckResult = new Probe(getName(), "", getDomain(), port,
        "/").setProbePath(Srt.POD_HEALTHCHECK_PATH, Srt.MIME_JSON);
    
    JCurl jcurl = getJCurl().build();
    doProbe(jcurl, healthCheckResult, 200, 500);

    if (healthCheckResult.isFailed())
    {
      println("This looks quite like a Symphony Pod, but it isn't");
      
      subTaskMonitor.done();
      
      return;
    }
    
    if(subTaskMonitor.worked(1))
      return;

    JsonNode healthJson = healthCheckResult.getJsonNode();

    if (healthJson == null)
    {
      println("This looks a lot like a Symphony Pod, but it isn't");
      
      subTaskMonitor.done();
      
      return;
    }

    if (!healthJson.isObject())
    {
      println("This looks like a Symphony Pod, but the healthcheck returns something other than an object");
      println(healthJson);
      
      subTaskMonitor.done();
      
      return;
    }
    
    podConfig_.setPodUrl(createUrl("https://" + getFqdn() + (port == 443 ? "" : ":" + port)));
    podHealthy_ = true;
    healthJson.fields().forEachRemaining((field) ->
    {
      if (!field.getValue().asBoolean())
      {
        println(field.getKey() + " is UNHEALTHY");
        podHealthy_ = false;
      }
    });

    if (podHealthy_)
      println("We found a Symphony Pod!");
    else
      println("We found a Symphony Pod, but it's not feeling well");

    println();
    println("Probing for API Sessionauth");
    println("===========================");
    
    sessionAuthResponse_ = probeAuth("Session Auth", "/sessionauth", getName(), getDomain());

    if(subTaskMonitor.worked(1))
      return;
    
    if(sessionAuthResponse_ != null)
    {
      String token = getTag(sessionAuthResponse_, Srt.TOKEN);
      
      if(token != null)
      {
        sessionToken_ = token;
        getSrtHome().saveSessionToken(getFqdn(), Srt.SESSION_TOKEN, token);
      }
      
      podConfig_.setSessionAuthUrl(getUrl(sessionAuthResponse_, Srt.TOKEN));
      
      Builder builder = getJCurl();
      
      for(String field : Srt.SESSION_INFO_FIELDS)
        builder.extract(field, field);
      
      cookieAuth(builder);
      
      sessionInfoResult_ = new Probe(getName(), getDomain(), "", port,
          "/pod").setProbePath("/v2/sessioninfo", Srt.MIME_JSON);
      
      doProbe(builder.build(), sessionInfoResult_);
      
      println("JSON=" + sessionInfoResult_.getJsonNode());
      
      if(sessionInfoResult_.isFailed())
      {
        println("Failed to connect to POD API");
        podConfig_.setPodApiUrl(sessionInfoResult_.getBaseUrl());
      }
      else
      {
        podConfig_.setPodApiUrl(sessionInfoResult_.getBaseUrl());
        
        println("found pod API endpoint at " + podConfig_.getPodApiUrl());
        
        for(String field : Srt.SESSION_INFO_FIELDS)
          printf("%-20s=%s\n", field, sessionInfoResult_.getJcurlResponse().getTag(field));
      }
    }
    
    if(subTaskMonitor.worked(1))
      return;
    
    Builder builder = getJCurl()
        .expect(401)
        .expect(200);
    
    cookieAuth(builder);
    
    Probe checkAuthResult = new Probe(getName(), getDomain(), "", port,
        "/").setProbePath("/login/checkauth?type=user", Srt.MIME_JSON);
    
    doProbe(builder.build(), checkAuthResult, 200, 401);
    
    if(subTaskMonitor.worked(1))
      return;

    if (checkAuthResult.isFailed())
    {
      println("Can't do checkauth from this Pod.");
      
      subTaskMonitor.done();
      
      return;
    }
    
    JsonNode checkAuthJson = checkAuthResult.getJsonNode();

    if (checkAuthJson == null)
    {
      println("Invalid checkAuth response");
      
      subTaskMonitor.done();
      
      return;
    }
    
    JsonNode km = checkAuthJson.get("keymanagerUrl");

    if (km == null)
    {
      println("Invalid checkAuth response");
    }
    else
    {
      podConfig_.setKeyManagerUrl(createURL(km.asText()));
    
      println("keyManagerUrl is " + podConfig_.getKeyManagerUrl());
    }
    
    builder = getJCurl();
    
    cookieAuth(builder);
    
    Probe podInfoResult = new Probe(getName(), getDomain(), "", port,
        "/").setProbePath("/webcontroller/public/podInfo", Srt.MIME_JSON);
    
    doProbe(builder.build(), podInfoResult);
    
    if(subTaskMonitor.worked(1))
      return;

    if (podInfoResult.isFailed())
    {
      println("Can't get podInfo from this Pod.");
      
      subTaskMonitor.done();
      
      return;
    }

    JsonNode podInfoJson = podInfoResult.getJsonNode();

    if (podInfoJson == null)
    {
      println("Invalid podInfo response");
      
      subTaskMonitor.done();
      
      return;
    }
    
    JsonNode podInfoJsonData = podInfoJson.get("data");

    if (podInfoJsonData == null || !podInfoJsonData.isObject())
    {
      println("This looks like a Symphony Pod, but the podInfo returns something unexpected");
      println(podInfoJson);
      
      subTaskMonitor.done();
      
      return;
    }
    
    podId_ = podInfoJsonData.get("podId").asInt();
    podConfig_.setKeyManagerUrl(createURL(podInfoJsonData.get("keyManagerUrl").asText()));

    
    subTaskMonitor.done();
    
  }

  

  private URL createUrl(String url)
  {
    try
    {
      return new URL(url);
    }
    catch (MalformedURLException e)
    {
      throw new ProgramFault(e);
    }
  }

  private @Nonnull ScanResponse probeAuth(String title, String basePath, String name, String domain)
  {
    ScanResponse  response = new ScanResponse(title);
    
    for(String suffix : SUFFIXES)
    {
      for(int authPort : AUTH_PORTS)
      {
        Probe probe = new Probe(name, suffix, domain, authPort,
            basePath);
        
        JCurl jcurl = getJCurl()
            .method(JCurl.HttpMethod.POST)
            .extract(Srt.TOKEN, Srt.TOKEN)
            .build();
        
        probe.setProbePath("/v1/authenticate", Srt.MIME_JSON);
        
        doProbe(jcurl, probe);
        
        if(!probe.isFailed())
        {
          probe.setValid(true);
        }
        
        response.add(probe);
      }
    }
    
    return response;
  }
  
  private @Nonnull ScanResponse probeAgent(String name, String domain)
  {
    ScanResponse  response = new ScanResponse("Agent API");
    
    for(String suffix : SUFFIXES)
    {
      for(int authPort : AgentPorts)
      {
        Probe agentProbe = new Probe(name, suffix, domain, authPort,
            "/agent");
            
        probeAgent(agentProbe);
        
        response.add(agentProbe);
      }
    }
    
    return response;
  }
  
  private void probeAgent(Probe probe)
  {
    Builder builder = getJCurl()
        .method(HttpMethod.POST)
        .data("{ \"message\": \"Hello World\"}");
    
    headerAuth(builder);

    probe.setProbePath("/v1/util/echo", Srt.MIME_JSON);
    doProbe(builder.build(), probe);
    
    if(probe.isFailed())
      return;
    
    // Can't do 2 calls on one probe, leave this out for now....
    probe.setValid(true);
    
//    builder = getJCurl();
//    
//    headerAuth(builder);
//
//    probe.setProbePath("/v2/HealthCheck", Srt.MIME_JSON);
//    doProbe(builder.build(), probe);
//    
//    if(probe.isFailed())
//    {
//      println("This looks like a pre-1.47 Agent.");
//      
//      probe.setValid(true);
//    }
//    else
//    {
//      JsonNode agentHealthJson = probe.getJsonNode();
//
//      if (agentHealthJson == null)
//      {
//        println("This looks a lot like an Agent, but it isn't");
//        return;
//      }
//  
//      if (!agentHealthJson.isObject())
//      {
//        println("This looks like an Agent, but the healthcheck returns something other than an object");
//        println(agentHealthJson);
//        return;
//      }
//    
//      probe.setValid(true);
//      
//      agentHealthJson.fields().forEachRemaining((field) ->
//      {
//        switch(field.getKey())
//        {
//          case "podVersion":
//          case "agentVersion":
//            println(field.getKey() + " is " + field.getValue().asText());
//            break;
//            
//          default:
//            if (field.getValue().asBoolean())
//            {
//              println(field.getKey() + " is OK");
//            }
//            else
//            {
//              println(field.getKey() + " is UNHEALTHY");
//              probe.setUnhealthy(true);
//            }
//        }
//      });
//    }
  }

  private void doProbe(Probe probe)
  {
    doProbe(getJCurl().build(), probe);
  }
  
  private void doProbe(JCurl jcurl, Probe probe, int ...expectedStatus)
  {
    try
    {
      println("Probing " + probe.getProbeUrl() + "...");
      
      HttpURLConnection connection = jcurl.connect(probe.getProbeUrl());

      boolean ok = false;
      int status = connection.getResponseCode();
      
      probe.setHttpStatus(status);
      
      if(expectedStatus.length == 0)
      {
        ok = status == 200;
      }
      else
      {
        for(int exp : expectedStatus)
        {
          if(status == exp)
          {
            ok = true;
            break;
          }
        }
      }
      
      if (!ok)
      {
        println("Failed with HTTP status " + probe.getHttpStatus());
        return;
      }

      JCurl.Response jcr = probe.setJcurlResponse(jcurl.processResponse(connection));

      Certificate[] certs = jcr.getServerCertificates();

      X509Certificate cert = (X509Certificate) certs[certs.length - 1];
      podConfig_.addTrustCert(cert);

      println("Root server cert " + cert.getSubjectX500Principal().getName());
      
      cert = (X509Certificate) certs[0];
      
      println("End server cert " + cert.getSubjectX500Principal().getName());
      serverCerts_.add(cert);

      if (!probe.isResponseTypeValid())
        return;

      probe.setFailed(false);
    }
    catch (SSLHandshakeException e)
    {
      String msg = e.getMessage().toLowerCase();
      
      if (msg.contains("bad_certificate") || msg.contains("certificate_unknown"))
      {
        probe.setFailedCertAuth(true);
        println("Certificate auth required for " + probe.getHostNameAndPort());
      }
      else
        println("SSL problem to " + probe.getHostNameAndPort());
    }
    catch (UnknownHostException e)
    {
      println(probe.getHostName() + " is not a valid host name");
    }
    catch (SocketTimeoutException | ConnectException e)
    {
      println("Cannot connect to " + probe.getHostNameAndPort());
    }
    catch (CertificateParsingException | IOException e)
    {
      e.printStackTrace();
    }
    finally
    {
      flush();
    }
  }

  
  
  private Builder headerAuth(Builder builder)
  {
    String token = getTag(sessionAuthResponse_, Srt.TOKEN);
        
    if(token != null)
      builder.header(Srt.SESSION_TOKEN, token);
    
    token = getTag(keyAuthResponse_, Srt.TOKEN);
    
    if(token != null)
      builder.header(Srt.KEYMANAGER_TOKEN, token);
    
    return builder;
  }
  
  private String getTag(ScanResponse scanResponse, String tag)
  {
    if(scanResponse == null)
      return null;
    
    Probe probe = scanResponse.getValidProbe();
    
    if(probe == null)
      return null;
    
    return probe.getJcurlResponse().getTag(tag);
  }
  
  private Builder cookieAuth(Builder builder)
  {
    StringBuilder s = new StringBuilder();
    
    String token = getTag(sessionAuthResponse_, Srt.TOKEN);
    
    if(token != null)
      s = appendCookie(s, "skey", token);
    
    token = getTag(keyAuthResponse_, Srt.TOKEN);
    
    if(token != null)
      s = appendCookie(s, "kmsession", token);
    
    if(s != null)
    {
      builder.header("Cookie", s.toString());
    }
    
    return builder;
  }

  private StringBuilder appendCookie(StringBuilder s, String name, String value)
  {
    if(s == null)
      s = new StringBuilder();
    else
      s.append(";");
    
    s.append(name);
    s.append("=");
    s.append(value);
    
    return s;
  }

  private boolean probeNonSSL(int port)
  {
    JCurl jcurl = getJCurl().build();
    
    try
    {
      URL url = new URL("http://" + getFqdn() + ":" + port);
      
      HttpURLConnection connection = jcurl.connect(url);

      println("response from " + url + " = " + connection.getResponseCode());

      if(connection.getResponseCode() == 200)
      {
        podConfig_.setWebUrl(url);
        
        return true;
      }
      return false;
    }
    catch(MalformedURLException e)
    {
      throw new ProgramFault(e);
    }
    catch (IOException e)
    {
      return false;
    }
    finally
    {
    }
  }
}
