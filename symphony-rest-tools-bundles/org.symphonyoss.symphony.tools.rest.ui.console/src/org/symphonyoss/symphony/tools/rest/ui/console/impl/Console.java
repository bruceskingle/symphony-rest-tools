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

package org.symphonyoss.symphony.tools.rest.ui.console.impl;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PipedReader;
import java.io.PipedWriter;
import java.io.PrintWriter;
import java.io.Reader;
import java.io.Writer;

import org.eclipse.e4.core.services.log.Logger;
import org.eclipse.e4.ui.di.UISynchronize;
import org.eclipse.jface.text.BadLocationException;
import org.eclipse.jface.text.Document;
import org.eclipse.jface.text.DocumentEvent;
import org.eclipse.jface.text.IDocument;
import org.eclipse.jface.text.IDocumentListener;
import org.symphonyoss.symphony.tools.rest.ui.console.IConsole;

public class Console implements IConsole
{
  final private Logger logger_;
  final private UISynchronize sync_;

  private IDocument document_ = new Document();
  private int outPos_ = 0;
  private PrintWriter out_ = new PrintWriter(new ConsoleWriter());
  private PrintWriter err_ = new PrintWriter(new ConsoleWriter(), true);
  private PipedWriter inputWriter_ = new PipedWriter();
  private BufferedReader in_;
  private boolean writable_ = true;
  private ConsoleManager consoleManager_;
  private boolean open_ = true;
  
  public Console(ConsoleManager consoleManager, Logger logger, UISynchronize sync)
  {
    consoleManager_ = consoleManager;
    logger_ = logger;
    sync_ = sync;
    
    logger_.info("Console started");
    try
    {
      in_ = new BufferedReader(new PipedReader(inputWriter_));
    }
    catch (IOException e)
    {
      logger_.error(e, "Unable to create PipedReader for console input");
      in_ = new BufferedReader(
          new InputStreamReader(
              new ByteArrayInputStream(new byte[0])));
    }
    
    document_.addDocumentListener(new IDocumentListener()
    {
      @Override
      public void documentChanged(DocumentEvent event)
      {
        consoleManager.consoleOutput(Console.this, event);
      }
      
      @Override
      public void documentAboutToBeChanged(DocumentEvent event)
      {}
    });
  }
  
  class ConsoleReader extends BufferedReader
  {
    public ConsoleReader(Reader in)
    {
      super(in);
    }
    
    
  }
  
  public void input(char character)
  {
    try
    {
      inputWriter_.write(character);
      outPos_++;
    }
    catch(IOException e)
    {
      writable_ = false;
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

  @Override
  public BufferedReader getIn()
  {
    return in_;
  }

  public IDocument getDocument()
  {
    return document_;
  }

  class ConsoleWriter extends Writer
  {

    @Override
    public void write(char[] cbuf, int off, int len) throws IOException
    {
      final String str = new StringBuilder().append(cbuf, off, len).toString();
      
      sync_.asyncExec(() ->
      {
        try
        {
          document_.replace(outPos_, 0,
              str);
          outPos_ += len;
        }
        catch (BadLocationException e)
        {
          // TODO Auto-generated catch block
          e.printStackTrace();
        }
      });
    }

    @Override
    public void flush() throws IOException
    {
    }

    @Override
    public void close() throws IOException
    {
      Console.this.close();
    }
    
  }

  public boolean isWritable()
  {
    return writable_;
  }

  @Override
  public void close()
  {
    synchronized (consoleManager_)
    {
      if(open_)
      {
        consoleManager_.consoleClosed(this);
        open_ = false;
      }
    }
  }
}
