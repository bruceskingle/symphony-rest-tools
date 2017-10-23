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

package org.symphonyoss.symphony.tools.rest.cert.find;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

import org.symphonyoss.s2.common.crypto.cert.CertificateUtils;
import org.symphonyoss.symphony.tools.rest.SrtCommand;
import org.symphonyoss.symphony.tools.rest.console.IConsole;
import org.symphonyoss.symphony.tools.rest.model.ICertificate;
import org.symphonyoss.symphony.tools.rest.model.osmosis.ComponentStatus;
import org.symphonyoss.symphony.tools.rest.util.IObjective;
import org.symphonyoss.symphony.tools.rest.util.command.Flag;
import org.symphonyoss.symphony.tools.rest.util.home.ISrtHome;

public class FindCertificates  extends SrtCommand
{
  private static final String   PROGRAM_NAME = "FindCertificates";

  private String dirName_;
  private IObjective findObjective_;
  
  /**
   * Command line launcher.
   * @param argv Command line arguments.
   */
  public static void main(String[] argv)
  {
    new FindCertificates(argv).run();
  }

  public FindCertificates(IConsole console, ISrtHome srtHome)
  {
    super(PROGRAM_NAME, console, srtHome);
  }

  public FindCertificates(String[] argv)
  {
    super(PROGRAM_NAME, argv);
  }

  @Override
  protected void init()
  {
    super.init();
    
    getParser()
      .withFlag(new Flag<String>("Directory Name", String.class, (v) -> dirName_ = v)
        .withRequired(true)
        )
//      .withFlag(new Flag<String>("Keystore Password", String.class, (v) -> password_ = v, () -> "changeit")
//          .withName("storepass"))
        ;
    
    findObjective_ = createObjective("Find Certificates");
  }

  @Override
  public void execute()
  {
    File dir = new File(dirName_);
    
    if(!dir.exists())
    {
      findObjective_.setObjectiveStatus(ComponentStatus.Failed, "%s does not exist", dir.getAbsolutePath());
      return;
    }
    
    if(dir.isDirectory())
    {
      findInDirectory(dir);
    }
    else
    {
      if(checkFile(dir))
      {
        findObjective_.setObjectiveStatusOK();
      }
      else
      {
        findObjective_.setObjectiveStatus(ComponentStatus.Failed, "%s is not a recognizable certificate file.", dir.getAbsolutePath());
      }
    }
  }

  private boolean checkFile(File file)
  {
    String name = file.getName();
    int i = name.lastIndexOf('.');
    
    if(i>1)
    {
      String extension = name.substring(i).toLowerCase();
      
      switch(extension)
      {
        case ".p12":
        case ".pkcs12":
          return checkFile(file, "PKCS12");
          
        case ".keystore":
        case ".truststore":
        case ".jks":
          return checkFile(file, "jks");
          
        default:
          return false;
      }
    }
    
    return false;
  }

  private boolean checkFile(File file, String type)
  {
    title("Keystore file %s", file.getAbsolutePath());
    
    try
    {
      KeyStore keyStore = KeyStore.getInstance(type);
    
      try(FileInputStream in = new FileInputStream(file))
      {
        keyStore.load(in, null);
            //password);
      }
      
      return checkKeyStore(file, keyStore);
    }
    catch (IOException | NoSuchAlgorithmException | CertificateException | KeyStoreException e)
    {
      error(e, "%s is not a valid keystore", file.getAbsolutePath());
      return false;
    }
    
  }

  private boolean checkKeyStore(File file, KeyStore keyStore) throws KeyStoreException
  {
    List<String>  aliases = new ArrayList<>();
    Enumeration<String> it = keyStore.aliases();
    
    while(it.hasMoreElements())
      aliases.add(it.nextElement());
    
    if(aliases.isEmpty())
    {
      printfln("%s is an empty keystore", file.getAbsolutePath());
      return false;
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
          
          checkCert(file, alias, x509Cert, false);
          String dn = x509Cert.getSubjectX500Principal().getName();
          String cn = CertificateUtils.getCommonName(x509Cert.getSubjectX500Principal());
          
          
          //        12345678901234567890 XXX
          printfln("                     %-20s %s", cn, dn);
        }
      }
      else if(keyStore.isKeyEntry(alias))
      {
        try
        {
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
              
              checkCert(file, alias, x509Cert, i==0);
              
              String dn = x509Cert.getSubjectX500Principal().getName();
              String cn = CertificateUtils.getCommonName(x509Cert.getSubjectX500Principal());
              
              //        12345678901234567890 XXX
              printfln("        cert[%02d] %-20s %s", i++, cn, dn);
            }   
          }
        }
        catch (KeyStoreException e)
        {
         printfln("%-20s is an unreadable Private Key (%s)", alias, e.getMessage());
         return false;
        }
      }
    }
    return true;
  }

  private void checkCert(File file, String alias, X509Certificate x509Cert, boolean privateKeyEntry)
  {
   // TODO: fixme ICertificate cert = getSrtHome().getCertificateManager().getOrCreateCertificate(file, alias, x509Cert, privateKeyEntry);
  }

  private void findInDirectory(File dir)
  {
    // TODO Auto-generated method stub
    
  }
}
