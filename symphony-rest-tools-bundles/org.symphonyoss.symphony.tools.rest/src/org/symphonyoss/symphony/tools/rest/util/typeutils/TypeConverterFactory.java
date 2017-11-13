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

package org.symphonyoss.symphony.tools.rest.util.typeutils;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.util.HashMap;
import java.util.Map;

import javax.annotation.Nonnull;

public class TypeConverterFactory
{
  private static Map<Class<?>, Map<Class<?>, ?>> converterMap_;
  private static Map<Class<?>, ITypeConverter<String, ?>> stringConverterMap_;
  
  static
  {
    converterMap_ = new HashMap<>();
    stringConverterMap_ = new HashMap<>();
    converterMap_.put(String.class, stringConverterMap_);

    stringConverterMap_.put(String.class,   (v) -> v);
    stringConverterMap_.put(Integer.class,  (v) -> Integer.parseInt(v));
    stringConverterMap_.put(Short.class,    (v) -> Short.parseShort(v));
    stringConverterMap_.put(Long.class,     (v) -> Long.parseLong(v));
    stringConverterMap_.put(Double.class,   (v) -> Double.parseDouble(v));
    stringConverterMap_.put(Float.class,    (v) -> Float.parseFloat(v));
    stringConverterMap_.put(Boolean.class,    (v) -> Boolean.parseBoolean(v));
  }
  
  public static <S,T> ITypeConverter<S,T> getConverter(Class<S> sourceType, Class<T> targetType)
  {
    @SuppressWarnings("unchecked")
    Map<Class<?>, ITypeConverter<S,T>> map = 
        (Map<Class<?>, ITypeConverter<S,T>>)converterMap_.get(sourceType);
    
    if(map.containsKey(targetType))
      return map.get(targetType);
    
    try
    {
      Constructor<T> constructor = targetType.getConstructor(sourceType);
      
      ITypeConverter<S,T> converter = (v) ->
      {
        try
        {
          return constructor.newInstance(v);
        }
        catch (InstantiationException | IllegalAccessException | IllegalArgumentException | InvocationTargetException e)
        {
          throw new RuntimeException(e);
        }
      };
      
      map.put(targetType, converter);
      
      return converter;
    }
    catch (NoSuchMethodException | SecurityException e)
    {
      // No String constructor
    }
    
    throw new RuntimeException("Unable to convert from " + sourceType.getName() +
        " to " + targetType.getName());
  }
  
  public @Nonnull String foo()
  {
    return null;
  }
}
