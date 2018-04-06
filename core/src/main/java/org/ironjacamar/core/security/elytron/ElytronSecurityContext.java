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

import org.ironjacamar.core.spi.security.SecurityContext;

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.HashSet;
import java.util.Set;

import javax.security.auth.Subject;

import org.wildfly.security.auth.server.SecurityIdentity;
import org.wildfly.security.manager.WildFlySecurityManager;

/**
 * An Elytron based {@link SecurityContext} implementation.
 *
 * @author Flavia Rainone
 * @author <a href="mailto:sguilhen@redhat.com">Stefan Guilhen</a>
 */
public class ElytronSecurityContext implements SecurityContext
{

   private Subject authenticatedSubject;

   @Override public Subject getAuthenticatedSubject()
   {
      return this.authenticatedSubject;
   }

   @Override public void setAuthenticatedSubject(final Subject subject)
   {
      this.authenticatedSubject = subject;
   }

   @Override public String[] getRoles()
   {
      if (this.authenticatedSubject != null)
      {
         // check if the authenticated subject contains a SecurityIdentity in its private credentials.
         Set<SecurityIdentity> authenticatedIdentities = this.getPrivateCredentials(SecurityIdentity.class);
         // iterate through the identities adding all the roles found.
         final Set<String> rolesSet = new HashSet<>();
         for (SecurityIdentity identity : authenticatedIdentities)
         {
            for (String role : identity.getRoles(ElytronSecurityIntegration.SECURITY_IDENTITY_ROLE))
            {
               rolesSet.add(role);
            }
         }
         return rolesSet.toArray(new String[rolesSet.size()]);
      }
      return new String[0];
   }

   /**
    * Runs the work contained in {@code work} as an authenticated Identity.
    *
    * @param work executes the work
    */
   public void runWork(Runnable work)
   {
      // if we have an authenticated subject we check if
      // it contains a security identity and use the identity to run the work.
      if (this.authenticatedSubject != null)
      {
         Set<SecurityIdentity> authenticatedIdentities = this.getPrivateCredentials(SecurityIdentity.class);
         if (!authenticatedIdentities.isEmpty())
         {
            SecurityIdentity identity = authenticatedIdentities.iterator().next();
            identity.runAs(work);
            return;
         }
      }
      // no authenticated subject found or the subject didn't have a security identity - just run the work.
      work.run();
   }

   /**
    * Return the private credentials of the specified type
    * @param credentialClass the credential type
    * @param <T> the credential type
    * @return a set containing all private credentials of the requested type
    */
   protected <T> Set<T> getPrivateCredentials(Class<T> credentialClass)
   {
      if (!WildFlySecurityManager.isChecking())
      {
         return this.authenticatedSubject.getPrivateCredentials(credentialClass);
      }
      else
      {
         return AccessController.doPrivileged(
            (PrivilegedAction<Set<T>>) () -> this.authenticatedSubject.getPrivateCredentials(credentialClass));
      }
   }

}
