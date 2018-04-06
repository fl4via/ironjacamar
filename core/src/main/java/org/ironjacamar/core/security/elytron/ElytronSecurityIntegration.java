/*
 * IronJacamar, a Java EE Connector Architecture implementation
 * Copyright 2018, Red Hat Inc, and individual contributors
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
package org.ironjacamar.core.security.elytron;

import org.ironjacamar.core.CoreLogger;
import org.ironjacamar.core.security.picketbox.PicketBoxCallbackHandler;
import org.ironjacamar.core.spi.security.Callback;
import org.ironjacamar.core.spi.security.SecurityContext;
import org.ironjacamar.core.spi.security.SecurityIntegration;

import javax.security.auth.callback.CallbackHandler;

import org.jboss.logging.Logger;

import org.wildfly.security.auth.server.SecurityDomain;

/**
 * An Elytron based {@link SecurityIntegration} implementation.
 *
 * @author Flavia Rainone
 * @author <a href="mailto:sguilhen@redhat.com">Stefan Guilhen</a>
 */
public abstract class ElytronSecurityIntegration implements SecurityIntegration
{

   /**
    * The security identity role.
    */
   static final String SECURITY_IDENTITY_ROLE = "ejb";

   /** Log instance */
   private static CoreLogger log = Logger.getMessageLogger(CoreLogger.class, PicketBoxCallbackHandler.class.getName());

   /*
   private static final String SECURITY_DOMAIN_CAPABILITY =  "org.wildfly.security.security-domain";

   private static final RuntimeCapability<Void> SECURITY_DOMAIN_RUNTIME_CAPABILITY = RuntimeCapability
           .Builder.of(SECURITY_DOMAIN_CAPABILITY, true, SecurityDomain.class)
           .build();
*/
   private final ThreadLocal<SecurityContext> securityContext = new ThreadLocal<>();

   @Override public SecurityContext createSecurityContext(String sd)
   {
      return new ElytronSecurityContext();
   }

   @Override public SecurityContext getSecurityContext()
   {
      return this.securityContext.get();
   }

   @Override public void setSecurityContext(SecurityContext context)
   {
      this.securityContext.set(context);
   }

   @Override public CallbackHandler createCallbackHandler()
   {
      // we need a Callback to retrieve the Elytron security domain that will be used by the CallbackHandler.
      throw log.unsupportedCreateCallbackHandlerMethod();
   }

   @Override public CallbackHandler createCallbackHandler(final Callback callback)
   {
      assert callback != null;
      // TODO switch to use the elytron security domain once the callback has that info available.
      final String securityDomainName = callback.getDomain();
      // get domain reference from the service container and create the callback handler using the domain.
      if (securityDomainName != null)
      {
         SecurityDomain securityDomain = getSecurityDomain(securityDomainName);
         return new ElytronCallbackHandler(securityDomain, callback);
      }
      throw log.invalidCallbackSecurityDomain();
   }

   /**
    * Get a reference to the current {link ServiceContainer}.
    *
    * @return a reference to the current {link ServiceContainer}.
    *
   private ServiceContainer currentServiceContainer() {
   if(WildFlySecurityManager.isChecking()) {
   return AccessController.doPrivileged(CurrentServiceContainer.GET_ACTION);
   }
   return CurrentServiceContainer.getServiceContainer();
   }*/

   /**
    * Returns the security domain corresponding to {@param securityDomainName}.
    * @param securityDomainName the security domain name
    * @return the security domain
    */
   protected abstract SecurityDomain getSecurityDomain(String securityDomainName);
    /*{
       final ServiceContainer container = this.currentServiceContainer();
       final ServiceName securityDomainServiceName = SECURITY_DOMAIN_RUNTIME_CAPABILITY.
       getCapabilityServiceName(securityDomainName);
       final SecurityDomain securityDomain = (SecurityDomain) container.
       getRequiredService(securityDomainServiceName).getValue();
    }*/
}
