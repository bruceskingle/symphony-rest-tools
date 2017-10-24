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

package org.symphonyoss.symphony.tools.rest.probe;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;

import javax.net.ssl.SSLHandshakeException;

import org.symphonyoss.s2.common.crypto.cert.CertificateUtils;
import org.symphonyoss.symphony.jcurl.JCurl;
import org.symphonyoss.symphony.jcurl.JCurl.Builder;
import org.symphonyoss.symphony.jcurl.JCurl.HttpMethod;
import org.symphonyoss.symphony.tools.rest.Srt;
import org.symphonyoss.symphony.tools.rest.SrtCommand;
import org.symphonyoss.symphony.tools.rest.console.IConsole;
import org.symphonyoss.symphony.tools.rest.model.IPod;
import org.symphonyoss.symphony.tools.rest.model.osmosis.ComponentStatus;
import org.symphonyoss.symphony.tools.rest.util.IObjective;
import org.symphonyoss.symphony.tools.rest.util.home.ISrtHome;

public class CheckCerts extends SrtCommand
{
  private static final String PROGRAM_NAME          = "CheckCerts";
  private static final String WE_CANT_TELL          = "We cannot tell if these certs are good for this pod.";
  private static final String CERTS_ARE_GOOD_SERVER = "This truststore is good for this pod.";
  private static final String CERTS_ARE_GOOD        = "These certs are good for this pod.";
  private static final String CERTS_ARE_BAD_TRUST   = "Server certs not in truststore.";
  private static final String CERTS_ARE_BAD_AUTH    = "Client cert is NOT valid.";
  private static final String CERTS_ARE_BAD_ACCOUNT = "Client cert is valid, auth failed FORBIDDEN.";
  private static final String UNKNOWN_CERT          = "Received fatal alert: certificate_unknown";
  private static final String BAD_CERT              = "Received fatal alert: bad_unknown";
  private static final String AUTHENTICATED         = "Authenticated OK";
  private static final String CERTS_ARE_BAD_UNKNOWN = "Client cert is valid, auth failed %d.";
  private static final Object ERROR                 = "ERROR";
  private static final Object WARNING               = "WARNING";

  private IPod                pod_;
  private String              clientCertCommonName_;
  private IObjective          keystoreObjective_;
  private IObjective          truststoreObjective_;
  private IObjective          sessionAuthObjective_;
  private IObjective          keyAuthObjective_;
  private IObjective          podObjective_;
  
  public static void main(String[] argv) throws IOException
  {
    new CheckCerts(argv).run();
  }

  public CheckCerts(IConsole console, ISrtHome srtHome)
  {
    super(PROGRAM_NAME, console, srtHome);
  }

  public CheckCerts(String[] argv)
  {
    super(PROGRAM_NAME, argv);
  }
  
  @Override
  protected void init()
  {
    super.init();

    withHostName(true);
    withKeystore(true);
    withTruststore(true);
    
    keystoreObjective_ = createObjective("Validate Keystore");
    truststoreObjective_ = createObjective("Validate Truststore");
    podObjective_ = createObjective("Connect to Pod");
    sessionAuthObjective_ = createObjective("Authenticate to Pod");
    keyAuthObjective_ = createObjective("Authenticate to Key Manager");
  }
  
  @Override
  public void execute()
  {
    int totalWork = 10; // TOD: count this
    
    beginTask(totalWork, "Check Certs");
    
    pod_ = getSrtHome().getPodManager().getPod(getFqdn());

    if(pod_ == null)
    {
      flush();
      error(getFqdn() + " is not a known pod. Try probe instead?");
      return;
    }
    
    
    
    title("Pod Configuration");
    
    pod_.print(getConsole());

    println();
    
    if(validateKeyStore("KeyStore", getKeystore(), getStoretype(), getStorepass().toCharArray(),
        true, keystoreObjective_) != null)
    {
      return;
    }
    
    if(validateKeyStore("TrustStore", getTruststore(), getTrusttype(), getTrustpass().toCharArray(),
        false, truststoreObjective_) != null)
    {
      return;
    }
    
    if(pod_.getPodUrl() == null)
    {
      error("No pod URL for this pod.");
    }
    else
    {
      println("Checking Pod");
      println("=============");
      
      probe("Pod", createURL(pod_.getPodUrl(),
          Srt.POD_HEALTHCHECK_PATH), false, podObjective_);
    }
    
    if(pod_.getSessionAuthUrl() == null)
    {
      error("No session auth URL for this pod.");
    }
    else
    {
      println("Checking Session Auth");
      println("=====================");
      
      probe("Session Auth", createURL(pod_.getSessionAuthUrl(),
          Srt.AUTHENTICATE_PATH), true, sessionAuthObjective_);
    }
    
    if(pod_.getPodUrl() == null)
    {
      sessionAuthObjective_.setObjectiveStatus(ComponentStatus.Failed,
          error("No key manager URL for this pod."));
    }
    else
    {
      
      
      println("Checking Key Manager");
      println("====================");
      
      probe("Key Manager", pod_.getKeyManagerUrl(), false, null);
    }
    
    if(pod_.getKeyAuthUrl() == null)
    {
      keyAuthObjective_.setObjectiveStatus(ComponentStatus.Failed,
          error("No key auth URL for this pod."));
    }
    else
    {
      println("Checking Key Auth");
      println("=================");
      
      probe("Key Auth", createURL(pod_.getKeyAuthUrl(),
          Srt.AUTHENTICATE_PATH), true, keyAuthObjective_);
    }
  }

  

  private String validateKeyStore(String name, String keystore, String storetype, char[] storepass, boolean isKeyStore, IObjective objective)
  {
    boolean warn = false;
    
    beginSubTask("Validate %s %s", name, keystore);
    try
    {
      File keyStoreFile = new File(keystore);
      
      if(!keyStoreFile.isFile())
      {
        objective.setObjectiveStatus(ComponentStatus.Failed, "Not a file");
        return error("%s is not a valid file", name);
      }
      
      if(!keyStoreFile.canRead())
      {
        objective.setObjectiveStatus(ComponentStatus.Failed, "Not readable");
        return error("%s is not readable", name);
      }
      
      KeyStore keyStore;
      if(storetype == null)
      {
        keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
      }
      else
      {
        keyStore = KeyStore.getInstance(storetype);
      }
      try(InputStream in = new FileInputStream(keyStoreFile))
      {
        keyStore.load(in, storepass);
      }
      catch (NoSuchAlgorithmException | CertificateException | IOException e)
      {
        objective.setObjectiveStatus(ComponentStatus.Failed, "Not valid keystore file (%s)", e);
        return error(e, "%s is not readable", name);
      }
      
      List<String>  aliases = new ArrayList<>();
      Enumeration<String> it = keyStore.aliases();
      
      while(it.hasMoreElements())
        aliases.add(it.nextElement());
      
      if(aliases.isEmpty())
      {
        objective.setObjectiveStatus(ComponentStatus.Failed, "Empty Keystore");
        return error("%s is empty", name);
      }
      
      if(isKeyStore && aliases.size() != 1)
      {
        warn = true;
        objective.setObjectiveStatus(ComponentStatus.Warning, "Keystore has multiple entries");
        error("%s has %d entries", name, aliases.size());
      }
      else
      {
        printfln("%s has %d entries", name, aliases.size());
      }
      
      for(String alias : aliases)
      {
        if(keyStore.isCertificateEntry(alias))
        {
          Certificate cert = keyStore.getCertificate(alias);
          
          if(cert == null)
          {
            error("%-20s is an unreadable Trusted Certificate", alias);
          }
          else
          {
            printfln("%-20s is a Trusted Certificate", alias);
            X509Certificate x509Cert = (X509Certificate) cert;
            String dn = x509Cert.getSubjectX500Principal().getName();
            String cn = CertificateUtils.getCommonName(x509Cert.getSubjectX500Principal());
            
            
            //        12345678901234567890 XXX
            printfln("                     %-20s %s", cn, dn);
            validateCert(alias, x509Cert, objective);
          }
        }
        else if(keyStore.isKeyEntry(alias))
        {
          try
          {
            Key key = keyStore.getKey(alias, storepass);
            
            printfln("%-20s is a %s Private Key", alias, key.getAlgorithm());
            
            Certificate[] certs = keyStore.getCertificateChain(alias);
            
            if(certs == null)
            {
              error("There are no certificates attached to this private key");
            }
            else
            {
              int i=0;
              for(Certificate cert : certs)
              {
                X509Certificate x509Cert = (X509Certificate) cert;
                String dn = x509Cert.getSubjectX500Principal().getName();
                String cn = CertificateUtils.getCommonName(x509Cert.getSubjectX500Principal());
                
                //        12345678901234567890 XXX
                printfln("        cert[%02d] %-20s %s", i++, cn, dn);
                validateCert(alias, x509Cert, objective);
                
                if(isKeyStore && clientCertCommonName_==null)
                  clientCertCommonName_ = cn;
              }   
            }
          }
          catch (UnrecoverableKeyException | KeyStoreException | NoSuchAlgorithmException e)
          {
           return printfln("%-20s is an unreadable Private Key (%s)", alias, e.getMessage());
          }
        }
      }
      
      if(!warn)
      {
        if(isKeyStore)
          objective.setObjectiveStatus(ComponentStatus.OK, "Account Name: %s", clientCertCommonName_);
        else
          objective.setObjectiveStatusOK();
      }
      
      return null;
    }
    catch (KeyStoreException e)
    {
      objective.setObjectiveStatus(ComponentStatus.Failed, "Invalid keystore type \"%s\"", storetype);
      return error(e, "Unable to validate keystore");
    }
    finally 
    {
      println();
    }
  }

  private void validateCert(X509Certificate x509Cert, IObjective objective)
  {
    String cn = CertificateUtils.getCommonName(x509Cert.getSubjectX500Principal());
    
    validateCert(cn, x509Cert, objective);
  }

  private void validateCert(String alias, X509Certificate x509Cert, IObjective objective)
  {
    Date now = new Date();
    
    if(x509Cert.getNotBefore().after(now))
    {
      printfln("                     %-20s %s", ERROR, "Certificate is not valid until " + x509Cert.getNotBefore());
      if(objective != null)
        objective.setObjectiveStatus(ComponentStatus.Error, "Certificate \"%s\" is not valid until %s", alias, x509Cert.getNotBefore());
    }
    
    if(x509Cert.getNotAfter().before(now))
    {
      printfln("                     %-20s %s", ERROR, "Certificate expired on " + x509Cert.getNotBefore());
      if(objective != null)
        objective.setObjectiveStatus(ComponentStatus.Error, "Certificate \"%s\" expired on %s", alias, x509Cert.getNotAfter());

    }

  }

  private String probe(String name, URL url, boolean authenticate, IObjective objective)
  {
    try
    {
      Builder builder = getJCurl()
          .trustAllCertificates(true)
          .trustAllHostnames(true)
          ;
      
      if(authenticate)
        builder.method(HttpMethod.POST);
      
      JCurl jCurl = builder
          .build();
      
      HttpURLConnection connection = jCurl.connect(url);
      
      println(name + " is reachable bypasssing server cert checks, status: " + connection.getResponseCode());
      
      JCurl.Response jcr = jCurl.processResponse(connection);

      Certificate[] certs = jcr.getServerCertificates();

      println("Server cert chain is:");
      for(Certificate cert : certs)
      {
        X509Certificate x509Cert = (X509Certificate) cert;
        println(x509Cert.getSubjectX500Principal().getName());
        validateCert(x509Cert, objective);
      }      
    }
    catch(SSLHandshakeException e)
    {
      if(authenticate)
      {
        // We already succeeded without client auth, so this is a client auth problem.
        if(objective != null)
          objective.setObjectiveStatus(ComponentStatus.Failed, CERTS_ARE_BAD_AUTH);
        
        return error("%s is NOT reachable - Client Cert Rejected%n%s%n", name, CERTS_ARE_BAD_AUTH);
      }
      
      if(objective != null)
        objective.setObjectiveStatus(ComponentStatus.Failed, WE_CANT_TELL);
      
      return error("%s is NOT reachable (SSL problem)%n%s%n", name, WE_CANT_TELL);
    }
    catch(IOException e)
    {
      if(objective != null)
        objective.setObjectiveStatus(ComponentStatus.Failed, WE_CANT_TELL);
      
      return error(e, "%s is NOT reachable%n%s%n", name, WE_CANT_TELL);
    }
    catch (CertificateParsingException e)
    {
      if(objective != null)
        objective.setObjectiveStatus(ComponentStatus.Failed, WE_CANT_TELL);
      
      return error(e, "%s is reachable but we can't parse their certificates.%n%s%n", name, WE_CANT_TELL);
    }
    
    
    try
    {
      Builder builder = getJCurl();
      
      if(authenticate)
        builder.method(HttpMethod.POST);
      
      JCurl jCurl = builder
          .build();
      HttpURLConnection connection = jCurl.connect(url);
      
      if(authenticate)
      {
        if(connection.getResponseCode() == 200)
        {
          if(objective!= null)
            objective.setObjectiveStatus(ComponentStatus.OK, AUTHENTICATED);
          return printf("%s is reachable%n", name, CERTS_ARE_GOOD);
        }
        else if(connection.getResponseCode() == 401)
        {
          if(objective!= null)
            objective.setObjectiveStatus(ComponentStatus.Failed, CERTS_ARE_BAD_ACCOUNT);
          return printfln("%s is reachable, but authentication is rejected%nThe account \"%s\" probably does not exist in this pod.%n%s", name, clientCertCommonName_, CERTS_ARE_BAD_ACCOUNT);
        }
        else
        {
          if(objective!= null)
            objective.setObjectiveStatus(ComponentStatus.Error, CERTS_ARE_BAD_UNKNOWN, connection.getResponseCode());
          return error("%s is reachable, with unexpected status: %d", name, connection.getResponseCode());
        }
      }
      if(objective!= null)
        objective.setObjectiveStatus(ComponentStatus.OK, CERTS_ARE_GOOD_SERVER);
      
      return printf("%s is reachable, status: %d%n", name, connection.getResponseCode(), CERTS_ARE_GOOD_SERVER);
    }
    catch(SSLHandshakeException e)
    {
      if(objective!= null)
        objective.setObjectiveStatus(ComponentStatus.Error, CERTS_ARE_BAD_TRUST);
      
      return error("%s is NOT reachable - SSL Problem%n%s%n", name, CERTS_ARE_BAD_TRUST);
    }
    catch(IOException e)
    {
      if(objective != null)
        objective.setObjectiveStatus(ComponentStatus.Failed, WE_CANT_TELL);
      
      return error(e, "%s is NOT reachable.%n%s", name, WE_CANT_TELL);
    }
    
    
  }
}
