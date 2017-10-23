/*
 * Copyright 2017 Symphony Communication Services, LLC.
 *
 * All Rights Reserved
 */

package org.symphonyoss.symphony.tools.rest.model;

import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import javax.annotation.Nullable;

import org.symphonyoss.symphony.tools.rest.util.IVisitor;

import com.fasterxml.jackson.databind.JsonNode;

public class ModelObjectContainer extends ModelObject implements IModelObjectContainer
{
  private final @Nullable IModelObjectContainer parentContainer_;

  private List<IModelObject>                    childSet_     = new ArrayList<>();
  private IModelObject[]                        children_     = new IModelObject[0];
    
  private CopyOnWriteArrayList<IModelListener>  listeners_    = new CopyOnWriteArrayList<>();
    
  public ModelObjectContainer(IModelObjectContainer parentContainer, String typeName, JsonNode config) throws InvalidConfigException
  {
    super(parentContainer, typeName, config);
    parentContainer_ = parentContainer;
  }

  public ModelObjectContainer(IModelObjectContainer parent, String typeName, String name)
  {
    super(parent, typeName, name);
    parentContainer_ = null;
  }

  public void addChild(IModelObject child)
  {
    if(child == null)
    {
      throw new NullPointerException("Child may not be null");
    }
    
    synchronized (childSet_)
    {
      childSet_.add(child);
      synchronized (children_)
      {
        children_ = childSet_.toArray(new IModelObject[childSet_.size()]);
      }
    }
    
    modelObjectStructureChanged(this);
  }
  
  public void replaceChild(@Nullable IModelObject oldChild, IModelObject newChild)
  {
    if(newChild == null)
    {
      throw new NullPointerException("newChild may not be null");
    }
    
    synchronized (childSet_)
    {
      if(oldChild != null)
        childSet_.remove(oldChild);
      
      childSet_.add(newChild);
      synchronized (children_)
      {
        children_ = childSet_.toArray(new IModelObject[childSet_.size()]);
      }
    }
    
    modelObjectStructureChanged(this);
  }
  
  public void removeChild(IModelObject oldChild)
  {
    synchronized (childSet_)
    {
      if(oldChild != null)
        childSet_.remove(oldChild);
      
      synchronized (children_)
      {
        children_ = childSet_.toArray(new IModelObject[childSet_.size()]);
      }
    }
    
    modelObjectStructureChanged(this);
  }
  
  @Override
  public void visit(IVisitor<IModelObject> visitor)
  {
    super.visit(visitor);
    
    synchronized (children_)
    {
      for(IModelObject component : children_)
        visitor.visit(component);
    }
  }
  
  @Override
  public boolean hasChildren()
  {
    synchronized (children_)
    {
      return children_.length > 0;
    }
  }

  @Override
  public IModelObject[] getChildren()
  {
    synchronized (children_)
    {
      return children_;
    }
  }
  
  /**
   * Adds a simple child ONLY IF THE NAME IS NON-NULL
   * @param typeName  Type of the child
   * @param name      Name of the child
   */
  public void addSimpleChild(String typeName, String name)
  {
    if(name != null)
      addChild(new ModelObject(this, typeName, name));
  }
  
  /**
   * Adds a URL endpoint child ONLY IF THE NAME IS NON-NULL
   * @param typeName  Type of the child
   * @param name      Name of the child
   */
  public void addUrlEndpoint(String typeName, String name, URL url)
  {
    if(url != null)
    {
      addChild(new UrlEndpoint(this, typeName, name, url));
    }
  }
  
  @Override
  public void modelObjectChanged(IModelObject modelObject)
  {
    for(IModelListener listener : listeners_)
      listener.modelObjectChanged(modelObject);
    
    if(parentContainer_ != null)
      parentContainer_.modelObjectChanged(modelObject);
  }
  
  @Override
  public void modelObjectStructureChanged(IModelObject modelObject)
  {
    for(IModelListener listener : listeners_)
      listener.modelObjectStructureChanged(modelObject);
    
    if(parentContainer_ != null)
      parentContainer_.modelObjectStructureChanged(modelObject);
  }

  @Override
  public void addListener(IModelListener listener)
  {
    listeners_.add(listener);
    
  }

  @Override
  public void removeListener(IModelListener listener)
  {
    listeners_.remove(listener);
  }
}
