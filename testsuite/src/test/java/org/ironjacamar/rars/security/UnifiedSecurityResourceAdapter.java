/*
 * IronJacamar, a Java EE Connector Architecture implementation
 * Copyright 2015, Red Hat Inc, and individual contributors
 * as indicated by the @author tags. See the copyright.txt file in the
 * distribution for a full listing of individual contributors.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the Eclipse Public License 1.0 as
 * published by the Free Software Foundation.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the Eclipse
 * Public License for more details.
 *
 * You should have received a copy of the Eclipse Public License
 * along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */
package org.ironjacamar.rars.security;

import javax.resource.ResourceException;
import javax.resource.spi.ActivationSpec;
import javax.resource.spi.BootstrapContext;
import javax.resource.spi.Connector;
import javax.resource.spi.ResourceAdapter;
import javax.resource.spi.ResourceAdapterInternalException;
import javax.resource.spi.TransactionSupport;
import javax.resource.spi.endpoint.MessageEndpointFactory;
import javax.transaction.xa.XAResource;

import org.jboss.logging.Logger;

/**
 * UnifiedSecurityResourceAdapter
 *
 * @version $Revision: $
 */
@Connector(
      reauthenticationSupport = false,
      transactionSupport = TransactionSupport.TransactionSupportLevel.NoTransaction)
public class UnifiedSecurityResourceAdapter implements ResourceAdapter, java.io.Serializable
{

   /**
    * The serial version UID
    */
   private static final long serialVersionUID = 1L;

   /**
    * The logger
    */
   private static Logger log = Logger.getLogger(UnifiedSecurityResourceAdapter.class.getName());

   /**
    * Default constructor
    */
   public UnifiedSecurityResourceAdapter()
   {

   }

   /**
    * This is called during the activation of a message endpoint.
    *
    * @param endpointFactory A message endpoint factory instance.
    * @param spec            An activation spec JavaBean instance.
    * @throws ResourceException generic exception
    */
   public void endpointActivation(MessageEndpointFactory endpointFactory, ActivationSpec spec) throws ResourceException
   {
      log.tracef("endpointActivation(%s, %s)", endpointFactory, spec);

   }

   /**
    * This is called when a message endpoint is deactivated.
    *
    * @param endpointFactory A message endpoint factory instance.
    * @param spec            An activation spec JavaBean instance.
    */
   public void endpointDeactivation(MessageEndpointFactory endpointFactory, ActivationSpec spec)
   {
      log.tracef("endpointDeactivation(%s)", endpointFactory);

   }

   /**
    * This is called when a resource adapter instance is bootstrapped.
    *
    * @param ctx A bootstrap context containing references
    * @throws ResourceAdapterInternalException indicates bootstrap failure.
    */
   public void start(BootstrapContext ctx) throws ResourceAdapterInternalException
   {
      log.tracef("start(%s)", ctx);

   }

   /**
    * This is called when a resource adapter instance is undeployed or
    * during application server shutdown.
    */
   public void stop()
   {
      log.trace("stop()");

   }

   /**
    * This method is called by the application server during crash recovery.
    *
    * @param specs An array of ActivationSpec JavaBeans
    * @return An array of XAResource objects
    * @throws ResourceException generic exception
    */
   public XAResource[] getXAResources(ActivationSpec[] specs) throws ResourceException
   {
      log.tracef("getXAResources(%s)", specs.toString());
      return null;
   }

   /**
    * Returns a hash code value for the object.
    *
    * @return A hash code value for this object.
    */
   @Override
   public int hashCode()
   {
      return 17;
   }

   /**
    * Indicates whether some other object is equal to this one.
    *
    * @param other The reference object with which to compare.
    * @return true if this object is the same as the obj argument, false otherwise.
    */
   @Override
   public boolean equals(Object other)
   {
      if (other == null)
         return false;
      if (other == this)
         return true;
      if (!(other instanceof UnifiedSecurityResourceAdapter))
         return false;
      return true;
   }

}