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

package org.symphonyoss.symphony.tools.rest.model;

import static org.junit.Assert.assertEquals;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

import org.junit.BeforeClass;
import org.junit.Test;
import org.symphonyoss.s2.common.crypto.cert.CertificateUtils;
import org.symphonyoss.s2.common.crypto.cipher.CipherSuite;
import org.symphonyoss.s2.common.exception.BadFormatException;

public class CertificateTest
{
  private static final String CERT1 = "-----BEGIN CERTIFICATE-----\n" + 
      "MIIDljCCAn6gAwIBAgIBAzANBgkqhkiG9w0BAQsFADCBkTE7MDkGA1UEAxMyRGlz\n" + 
      "cG9zYWJsZSBUZXN0IEludGVybWVkaWF0ZSBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkx\n" + 
      "JDAiBgNVBAoTG1N5bXBob255IENvbW11bmljYXRpb25zIExMQzEfMB0GA1UECxMW\n" + 
      "Tk9UIEZPUiBQUk9EVUNUSU9OIFVTRTELMAkGA1UEBhMCVVMwHhcNMTYwMTI3MjAx\n" + 
      "MTAzWhcNMjQwMTI3MjAxMTAzWjBoMRIwEAYDVQQDEwlib3QudXNlcjExJDAiBgNV\n" + 
      "BAoTG1N5bXBob255IENvbW11bmljYXRpb25zIExMQzEfMB0GA1UECxMWTk9UIEZP\n" + 
      "UiBQUk9EVUNUSU9OIFVTRTELMAkGA1UEBhMCVVMwggEiMA0GCSqGSIb3DQEBAQUA\n" + 
      "A4IBDwAwggEKAoIBAQC4BPsIYfYPbv7mP2gDp9fc8mrR6sc0L8VFtrk5SoUVMNiS\n" + 
      "FJdVPncJDYhaf1cFxbUnCKtWQW5CZOuR/xRk1+9v6TfyAZe91avhmCUL2VB5JlwD\n" + 
      "Uu5ptxvACR/KfSDkfQZW+HKstnQLOursYXXlF3zHmLBBkLwOBvsioOcYQWpWT1yc\n" + 
      "pzZ7Gqu5YbrSJR3j0jYytvKQCxCxwITCX43Y83jJSwA38fs9Dxb2B8cvWPB/9j7m\n" + 
      "Dt3QB8vVqbXZeH6jkDOkaDyPKBiNTUDzb7XPjrVNczY0NaUcsqrw38JkIWx7oaRr\n" + 
      "0qYrYi5HQsfkYJ7rgs97FIK58HeWoPpbxK3XSXOpAgMBAAGjITAfMB0GA1UdDgQW\n" + 
      "BBS3/MC4in7mgqhhiXJTak1QKiI59jANBgkqhkiG9w0BAQsFAAOCAQEAixA21TpJ\n" + 
      "MozgL7TCBe1vPt1QXsdaciIf+JZmPjf144vabnUL00NhCNblTP30fQqTVP2GgBwn\n" + 
      "pB10AgK32wMbNmkU+oN43cl+YDutWnMHlmk9uS3zhodfgnSpGQyWI6ZEHOQZKiVT\n" + 
      "v7PcIE4xSUhfVOtWjvBT42DsWZTRwCg0m+9jTI+YC+/WrmM4LcmKiz2l7jY4wXJp\n" + 
      "t0MRDaZnSnXHm8URFDxwJpJom8fVqR0QZCjTlqxwBkLUvbjO6rQZq/axcwCrDgUw\n" + 
      "AADPuEdhdOO9TRGRvlgN3lFr7nfXx55dKQmSr1lnE5iuFH1bQi7QiVpKeqE35Uta\n" + 
      "e3rqAsGliPwJ+g==\n" + 
      "-----END CERTIFICATE-----";
  
  @BeforeClass
  public static void init()
  {
    CipherSuite.getAsymmetricCipher(); // Has the side effect of loading BC.
  }
  
  @Test
  public void testSerializeRoundTrip() throws IOException, GeneralSecurityException, InvalidConfigException, BadFormatException
  {
//    X509Certificate x509Certificate = loadCert("/Users/bruce.skingle/symphony/git-bruceskingle/symphony-rest-tools/symphony-rest-tools-products/symphony-rest-tools-cmdline/src/main/certs/test/bot.user1.p12", "PKCS12");
//    
//    System.out.println(CertificateUtils.encode(new X509Certificate[] {x509Certificate}));
    
    CertificateManager manager = null;
    
    Certificate cert = Certificate.newBuilder(CertificateUtils.decode(CERT1)[0]).build(manager);
    Certificate cert2 = new Certificate(manager, cert.toJson());
    
    assertEquals(cert.getName(), cert2.getName());
    assertEquals(cert.getIssuerName(), cert2.getIssuerName());
    assertEquals(cert.getSubjectName(), cert2.getSubjectName());
    
    System.out.println("Cert is " + cert.toJson());
    
    assertEquals(cert.toJson().toString(), cert2.toJson().toString());
  }

  private X509Certificate loadCert(String fileName, String type) throws IOException, GeneralSecurityException
  {
    KeyStore keyStore = KeyStore.getInstance(type);
    
    try(FileInputStream in = new FileInputStream(fileName))
    {
      keyStore.load(in, "changeit".toCharArray());
    }
    
    List<String>  aliases = new ArrayList<>();
    Enumeration<String> it = keyStore.aliases();
    
    while(it.hasMoreElements())
      aliases.add(it.nextElement());
    
    if(aliases.isEmpty())
    {
      throw new IOException(fileName + " is an empty keystore");
    }
    
    for(String alias : aliases)
    {
      if(keyStore.isCertificateEntry(alias))
      {
        java.security.cert.Certificate cert = keyStore.getCertificate(alias);
        
        if(cert == null)
        {
          throw new IOException(alias + " is an unreadable Trusted Certificate");
        }
        else
        {
          return (X509Certificate) cert;
        }
      }
      else if(keyStore.isKeyEntry(alias))
      {
        Key key = keyStore.getKey(alias, "changeit".toCharArray());
        java.security.cert.Certificate[] certs = keyStore.getCertificateChain(alias);
        
        if(certs == null)
        {
          throw new IOException("There are no certificates attached to this private key");
        }
        else
        {
          int i=0;
          for(java.security.cert.Certificate cert : certs)
          {
            return (X509Certificate) cert;
          }   
        }
      }
    }
    throw new IOException("Unable to read a certificate from here");
  }
}
