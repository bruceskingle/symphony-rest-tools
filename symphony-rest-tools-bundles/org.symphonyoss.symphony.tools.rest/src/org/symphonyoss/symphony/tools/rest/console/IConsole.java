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

import java.io.PrintWriter;
import java.util.Collection;
import java.util.Locale;

import javax.annotation.Nullable;

import org.symphonyoss.symphony.tools.rest.SrtCommand;
import org.symphonyoss.symphony.tools.rest.util.IObjective;
import org.symphonyoss.symphony.tools.rest.util.home.IDefaultsProvider;

/**
 * A Console abstraction for commands, which is implemented for both a traditional terminal 
 * environment and SWT for use in a GUI environment.
 * 
 * Callers are encouraged to use the direct methods on this interface, but methods to return 
 * a PrintWriter connected to the standard output and standard error streams are provided
 * for cases where it is necessary to pass a PrintStream to some other method.
 * 
 *  Note that there is no method to get the standard input directly.
 *  
 *  Commands should define their necessary inputs as switches and flags and the summary
 *  output as objectives. These can be managed in a better way in a GUI environment than
 *  direct calls to input methods.
 *  
 *  Output from the print methods can be expected to appear in a console view in a GUI.
 *  Calls to input methods can be expected to result in pop up modal windows in a GUI.
 *  In a terminal environment all calls result in reads from stdin and writes to stdout.
 *  
 *  All parameters and return values are NON NULL unless annotated otherwise.
 * 
 * @author Bruce Skingle
 *
 */
public interface IConsole
{
  /**
   * Prompt with the given message for a string value.
   * 
   * @param prompt        A prompt message.
   * @param defaultValue  The value to be returned if the user enters an empty response.
   *                      This will be added to the prompt in a terminal environment.
   * @return              A user entered String value.
   */
  String promptString(String prompt, String defaultValue);

  /**
   * Prompt with the given message for a string value.
   * 
   * @param prompt        A prompt message.
   * @return              A user entered String value. A zero length String if a blank response is made.
   */
  String promptString(String prompt);

  /**
   * Prompt with the given message for a boolean value. An empty response is not permitted.
   * 
   * @param prompt        A prompt message.
   * @return              A user entered boolean value.
   */
  boolean promptBoolean(String prompt);

  /**
   * Output a newline.
   */
  void println();

  /**
   * Print the result of toString() on the given object, with a newline.
   * 
   * @param object  Some object.
   * @return The output message without a terminating newline.
   */
  String println(Object object);

  /**
   * Output a message formatted with String.format(format, args).
   * 
   * @param format  A format string.
   * @param args    Zero or more parameters to be formatted.
   * @return        The output message.
   */
  String printf(String format, Object... args);

  /**
   * Output a message formatted with String.format(l, format, args).
   * @param l       A Locale
   * @param format  A format string.
   * @param args    Zero or more parameters to be formatted.
   * @return        The output message.
   */
  String printf(Locale l, String format, Object... args);

  /**
   * Output a message formatted with String.format(format, args), with a newline.
   * 
   * @param format  A format string.
   * @param args    Zero or more parameters to be formatted.
   * @return        The output message without a terminating newline.
   */
  String printfln(String format, Object... args);

  /**
   * Output a message formatted with String.format(l, format, args), with a newline.
   * @param l       A Locale
   * @param format  A format string.
   * @param args    Zero or more parameters to be formatted.
   * @return        The output message without a terminating newline.
   */
  String printfln(Locale l, String format, Object... args);

  /**
   * Output a message formatted with String.format(l, format, args), as a title.
   * @param l       A Locale
   * @param format  A format string.
   * @param args    Zero or more parameters to be formatted.
   * @return        The output message without a terminating newline.
   */
  String title(Locale l, String format, Object... args);

  /**
   * Output a message formatted with String.format(format, args), as a title.
   * 
   * @param format  A format string.
   * @param args    Zero or more parameters to be formatted.
   * @return        The output message without a terminating newline.
   */
  String title(String format, Object... args);
  
  /**
   * Output a message formatted with String.format(l, format, args)
   * to the standard error stream, with a stacktrace and a newline.
   * @param cause   An optional Throwable whose stack trace will be output.
   * @param l       A Locale
   * @param format  A format string.
   * @param args    Zero or more parameters to be formatted.
   * @return        The output message without a terminating newline.
   */
  String error(@Nullable Throwable cause, Locale l, String format, Object... args);
  
  /**
   * Output a message formatted with String.format(format, args)
   * to the standard error stream, with a stacktrace and a newline.
   * @param cause   An optional Throwable whose stack trace will be output.
   * @param format  A format string.
   * @param args    Zero or more parameters to be formatted.
   * @return        The output message without a terminating newline.
   */
  String error(@Nullable Throwable cause, String format, Object... args);

  /**
   * Output a message formatted with String.format(l, format, args)
   * to the standard error stream, with a newline.
   * @param l       A Locale
   * @param format  A format string.
   * @param args    Zero or more parameters to be formatted.
   * @return        The output message without a terminating newline.
   */
  String error(Locale l, String format, Object... args);
  
  /**
   * Output a message formatted with String.format(format, args)
   * to the standard error stream, with a newline.
   * @param format  A format string.
   * @param args    Zero or more parameters to be formatted.
   * @return        The output message without a terminating newline.
   */
  String error(String format, Object... args);

  /**
   * Close all inputs and outputs.
   */
  void close();

  /**
   * Flush stdout and stderr.
   */
  void flush();

  /**
   * Execute the given command.
   * 
   * The user may be prompted to enter some or all switch and flag values (depending on the
   * setting of the interactive (-i) switch). The command will be executed and the results of
   * any objectves will be displayed.
   * 
   * @param srtCommand  A command to execute.
   */
  void execute(SrtCommand srtCommand);

  /**
   * Begin the task of the command. This call may be made only once in the lifetime of a given
   * Console, and indicates the total amount of work units which is expected to be performed.
   * 
   *  In a GUI environment there may be a progress bar indicating how much of the task is complete. 
   *  
   * @param totalWork The total number of (arbitrary) work units to be performed.
   * @param format    A format string.
   * @param args      Zero or more parameters to be formatted.
   * @return          The formatted name.
   */
  String beginTask(int totalWork, String format, Object... args);

  /**
   * Indicates that the task is complete.
   * Causes any progress bar to be filled in completely.
   */
  void taskDone();

  /**
   * In a GUI environment the user may can access to a stop or cancel UI widget. This method
   * indicates if that has happened. Long running tasks should check this frequently and terminate
   * early if appropriate.
   *  
   * @return True if the user has cancelled or aborted the task.
   */
  boolean isTaskCanceled();

  /**
   * Update the name of the task previously passed to beginTask()
   * 
   * @param format  A format string.
   * @param args    Zero or more parameters to be formatted.
   * @return        The formatted name.
   */
  String setTaskName(String format, Object... args);

  /**
   * In a GUI environment displays a sub-task name to the user. May be called multiple times.
   * 
   * @param format  A format string.
   * @param args    Zero or more parameters to be formatted.
   * @return        The formatted name.
   */
  String beginSubTask(String format, Object... args);

  /**
   * Indicates that the given number of work units have been completed.
   * 
   * @param work    The number of additional work units which have been completed.
   *                The sum of all values passed for a task shuld equal the totalWork value passed
   *                in beginTask()
   * @return        True if the user has cancelled or aborted the task.
   */
  boolean taskWorked(int work);

  /**
   * Create an objective for the task. The status of each objective can be reported and will be presented to the user.
   * @param name A name for the objective.
   * 
   * @return An IObjective instance which can be used t report the result of the task.
   */
  IObjective createObjective(String name);

  /**
   * An Iterable over the objectives.
   * This method does not result in a copy of the objectives. Note that the status of the objectives could 
   * be updated from the results of this Iterable and those changes would be reported to the user.
   *  
   * @return All objectives.
   */
  Iterable<IObjective> getObjectives();

  /**
   * An immutable copy of the objectives.
   * Note that the status of the objectives could 
   * be updated from the contents of this Collection and those changes would be reported to the user.
   *  
   * @return All objectives.
   */
  Collection<IObjective> copyObjectives();

  /**
   * Indicates if any objectives have been defined.
   * 
   * @return true if there are any objectives.
   */
  boolean hasObjectives();

  /**
   * Set a defaults provider.
   * 
   * This method is not intended to be called by clients.
   * 
   * @param defaultsProvider  An IDefaultsProvider.
   */
  void setDefaultsProvider(IDefaultsProvider defaultsProvider);

  /**
   * Return the underlying output stream.
   * 
   * Calls to specific output methods should be preferred.
   * 
   * @return  The standard output.
   */
  PrintWriter getOut();

  /**
   * Return the underlying error stream.
   * 
   * Calls to specific output methods should be preferred.
   * 
   * @return  The standard error.
   */
  PrintWriter getErr();
}
