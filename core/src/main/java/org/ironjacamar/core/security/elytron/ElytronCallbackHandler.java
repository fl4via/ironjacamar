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

import java.io.IOException;
import java.io.Serializable;
import java.security.AccessController;
import java.security.Principal;
import java.security.PrivilegedAction;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.resource.spi.security.PasswordCredential;
import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.message.callback.CallerPrincipalCallback;
import javax.security.auth.message.callback.GroupPrincipalCallback;
import javax.security.auth.message.callback.PasswordValidationCallback;

import org.jboss.logging.Logger;

import org.wildfly.security.auth.principal.NamePrincipal;
import org.wildfly.security.auth.server.RealmUnavailableException;
import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.auth.server.SecurityIdentity;
import org.wildfly.security.auth.server.ServerAuthenticationContext;
import org.wildfly.security.authz.RoleMapper;
import org.wildfly.security.authz.Roles;
import org.wildfly.security.evidence.PasswordGuessEvidence;
import org.wildfly.security.manager.WildFlySecurityManager;

/**
 * An Elytron based {@link CallbackHandler} implementation designed for the JCA security inflow. It uses the information
 * obtained from the {@link javax.security.auth.callback.Callback}s to authenticate and authorize the identity supplied
 * by the resource adapter and inserts the {@link SecurityIdentity} representing the authorized identity in the
 * subject's private credentials set.
 *
 * @author Flavia Rainone
 * @author <a href="mailto:sguilhen@redhat.com">Stefan Guilhen</a>
 */
public class ElytronCallbackHandler implements CallbackHandler, Serializable
{
   /** Log instance */
   private static CoreLogger log = Logger.getMessageLogger(CoreLogger.class, PicketBoxCallbackHandler.class.getName());

   /** Trace */
   private static boolean trace = log.isTraceEnabled();

   private final SecurityDomain securityDomain;

   private final Callback mappings;

   private Subject executionSubject;

   /**
    * Constructor
    * @param securityDomain the Elytron security domain used to establish the caller principal.
    * @param mappings The mappings.
    */
   public ElytronCallbackHandler(final SecurityDomain securityDomain, final Callback mappings)
   {
      this.securityDomain = securityDomain;
      this.mappings = mappings;
   }

   /**
    * {@inheritDoc}
    */
   public void handle(javax.security.auth.callback.Callback[] callbacks)
      throws UnsupportedCallbackException, IOException
   {
      if (trace)
         log.elytronHandlerHandle(Arrays.toString(callbacks));

      // work wrapper calls the callback handler a second time with default callback values after the handler was
      // invoked by the RA. We must check if the execution subject already contains an identity and allow for
      // replacement of the identity with values found in the default callbacks only if the subject has no identity
      // yet or if the identity is the anonymous one.
      if (this.executionSubject != null)
      {
         final SecurityIdentity subjectIdentity = this
            .getPrivateCredential(this.executionSubject, SecurityIdentity.class);
         if (subjectIdentity != null && !subjectIdentity.isAnonymous())
         {
            return;
         }
      }

      if (callbacks != null && callbacks.length > 0)
      {
         if (this.mappings != null && this.mappings.isMappingRequired())
         {
            mapCallbacks(callbacks);
         }

         GroupPrincipalCallback groupPrincipalCallback = null;
         CallerPrincipalCallback callerPrincipalCallback = null;
         PasswordValidationCallback passwordValidationCallback = null;

         for (javax.security.auth.callback.Callback callback : callbacks)
         {
            if (callback instanceof GroupPrincipalCallback)
            {
               groupPrincipalCallback = (GroupPrincipalCallback) callback;
               if (this.executionSubject == null)
               {
                  this.executionSubject = groupPrincipalCallback.getSubject();
               }
               else if (!this.executionSubject.equals(groupPrincipalCallback.getSubject()))
               {
                  // TODO merge the contents of the subjects?
               }
            }
            else if (callback instanceof CallerPrincipalCallback)
            {
               callerPrincipalCallback = (CallerPrincipalCallback) callback;
               if (this.executionSubject == null)
               {
                  this.executionSubject = callerPrincipalCallback.getSubject();
               }
               else if (!this.executionSubject.equals(callerPrincipalCallback.getSubject()))
               {
                  // TODO merge the contents of the subjects?
               }
            }
            else if (callback instanceof PasswordValidationCallback)
            {
               passwordValidationCallback = (PasswordValidationCallback) callback;
               if (this.executionSubject == null)
               {
                  this.executionSubject = passwordValidationCallback.getSubject();
               }
               else if (!this.executionSubject.equals(passwordValidationCallback.getSubject()))
               {
                  // TODO merge the contents of the subjects?
               }
            }
            else
            {
               throw new UnsupportedCallbackException(callback);
            }
         }
         this.handleInternal(callerPrincipalCallback, groupPrincipalCallback, passwordValidationCallback);
      }
   }

   private void mapCallbacks(javax.security.auth.callback.Callback[] callbacks)
   {
      if (trace)
         log.tracef("handle(%s)", Arrays.toString(callbacks));

      if (callbacks != null && callbacks.length > 0)
      {
         if (mappings != null)
         {
            List<javax.security.auth.callback.Callback> l = new ArrayList<javax.security.auth.callback.Callback>(
               callbacks.length);

            for (int i = 0; i < callbacks.length; i++)
            {
               javax.security.auth.callback.Callback callback = callbacks[i];

               if (callback instanceof CallerPrincipalCallback)
               {
                  CallerPrincipalCallback callerPrincipalCallback = (CallerPrincipalCallback) callback;
                  String name = null;
                  Principal p = null;

                  Principal callerPrincipal = callerPrincipalCallback.getPrincipal();
                  if (callerPrincipal != null)
                     name = callerPrincipal.getName();

                  if (name == null && callerPrincipalCallback.getName() != null)
                     name = callerPrincipalCallback.getName();

                  if (name != null)
                     p = mappings.mapPrincipal(name);

                  if (p != null)
                  {
                     l.add(new CallerPrincipalCallback(callerPrincipalCallback.getSubject(), p));
                  }
                  else
                  {
                     l.add(callback);
                  }
               }
               else if (callback instanceof GroupPrincipalCallback)
               {
                  GroupPrincipalCallback groupPrincipalCallback = (GroupPrincipalCallback) callback;

                  if (groupPrincipalCallback.getGroups() != null && groupPrincipalCallback.getGroups().length > 0)
                  {
                     List<String> gs = new ArrayList<String>(groupPrincipalCallback.getGroups().length);

                     for (String g : groupPrincipalCallback.getGroups())
                     {
                        String s = mappings.mapGroup(g);

                        if (s != null)
                        {
                           gs.add(s);
                        }
                        else
                        {
                           gs.add(g);
                        }
                     }

                     l.add(new GroupPrincipalCallback(groupPrincipalCallback.getSubject(),
                        gs.toArray(new String[gs.size()])));
                  }
                  else
                  {
                     l.add(callback);
                  }
               }
               else
               {
                  l.add(callback);
               }
            }

            callbacks = l.toArray(new javax.security.auth.callback.Callback[l.size()]);
         }
      }
   }

   /**
    * Internal handling of callbacks.
    *
    * @param callerPrincipalCallback     the caller principal callback
    * @param groupPrincipalCallback      the group principal callback
    * @param passwordValidationCallback  password validation callback
    * @throws IOException if an unexpected IO error occurs during authentication
    */
   protected void handleInternal(final CallerPrincipalCallback callerPrincipalCallback,
      final GroupPrincipalCallback groupPrincipalCallback, final PasswordValidationCallback passwordValidationCallback)
      throws IOException
   {

      if (this.executionSubject == null)
      {
         throw log.executionSubjectNotSetInHandler();
      }
      SecurityIdentity identity = this.securityDomain.getAnonymousSecurityIdentity();

      // establish the caller principal using the info from the callback.
      Principal callerPrincipal = null;
      if (callerPrincipalCallback != null)
      {
         Principal callbackPrincipal = callerPrincipalCallback.getPrincipal();
         callerPrincipal = callbackPrincipal != null ?
            new NamePrincipal(callbackPrincipal.getName()) :
            callerPrincipalCallback.getName() != null ? new NamePrincipal(callerPrincipalCallback.getName()) : null;
      }

      // a null principal is the ra contract for requiring the use of the unauthenticated identity
      // - no point in attempting to authenticate.
      if (callerPrincipal != null)
      {
         // check if we have a username/password pair to authenticate - first try the password validation callback.
         if (passwordValidationCallback != null)
         {
            final String username = passwordValidationCallback.getUsername();
            final char[] password = passwordValidationCallback.getPassword();
            try
            {
               identity = this.authenticate(username, password);
               // add a password credential to the execution subject and set the successful result in the callback.
               this.addPrivateCredential(this.executionSubject, new PasswordCredential(username, password));
               passwordValidationCallback.setResult(true);
            }
            catch (SecurityException e)
            {
               passwordValidationCallback.setResult(false);
               return;
            }
         }
         else
         {
            // identity not established using the callback
            // - check if the execution subject contains a password credential.
            PasswordCredential passwordCredential = this
               .getPrivateCredential(this.executionSubject, PasswordCredential.class);
            if (passwordCredential != null)
            {
               try
               {
                  identity = this.authenticate(passwordCredential.getUserName(), passwordCredential.getPassword());
               }
               catch (SecurityException e)
               {
                  return;
               }
            }
            else
            {
               identity = securityDomain.createAdHocIdentity(callerPrincipal);
            }
         }

         // at this point we either have an authenticated identity or an anonymous one.
         // We must now check if the caller principal is different from the identity principal and switch to the
         // caller principal identity if needed.
         if (!callerPrincipal.equals(identity.getPrincipal()))
         {
            identity = identity.createRunAsIdentity(callerPrincipal.getName());
         }

         // if we have new roles coming from the group callback, set a new mapper in the identity.
         if (groupPrincipalCallback != null)
         {
            String[] groups = groupPrincipalCallback.getGroups();
            if (groups != null)
            {
               Set<String> roles = new HashSet<>(Arrays.asList(groups));
               // TODO what category should we use here?
               identity = identity.withRoleMapper(ElytronSecurityIntegration.SECURITY_IDENTITY_ROLE,
                  RoleMapper.constant(Roles.fromSet(roles)));
            }
         }
      }

      // set the authenticated identity as a private credential in the subject.
      this.executionSubject.getPrincipals().add(identity.getPrincipal());
      this.addPrivateCredential(executionSubject, identity);
   }

   /**
    * Authenticate the user with the given credential against the configured Elytron security domain.
    *
    * @param username the user being authenticated.
    * @param credential the credential used as evidence to verify the user's identity.
    * @return the authenticated and authorized {@link SecurityIdentity}.
    * @throws IOException if an error occurs while authenticating the user.
    */
   private SecurityIdentity authenticate(final String username, final char[] credential) throws IOException
   {
      final ServerAuthenticationContext context = this.securityDomain.createNewAuthenticationContext();
      final PasswordGuessEvidence evidence = new PasswordGuessEvidence(credential != null ? credential : null);
      try
      {
         context.setAuthenticationName(username);
         if (context.verifyEvidence(evidence))
         {
            if (context.authorize())
            {
               context.succeed();
               return context.getAuthorizedIdentity();
            }
            else
            {
               context.fail();
               throw new SecurityException("Authorization failed");
            }
         }
         else
         {
            context.fail();
            throw new SecurityException("Authentication failed");
         }
      }
      catch (IllegalArgumentException | IllegalStateException | RealmUnavailableException e)
      {
         context.fail();
         throw e;
      }
      finally
      {
         if (!context.isDone())
         {
            context.fail();
         }
         evidence.destroy();
      }
   }

   /**
    * Returns the private credential with the specified type
    *
    * @param subject         the subject
    * @param credentialClass the credential type
    * @param <T> the credential type
    * @return the requested private credential for the subject
    */
   protected <T> T getPrivateCredential(final Subject subject, final Class<T> credentialClass)
   {
      T credential = null;
      if (subject != null)
      {
         Set<T> credentialSet;
         if (!WildFlySecurityManager.isChecking())
         {
            credentialSet = subject.getPrivateCredentials(credentialClass);
         }
         else
         {
            credentialSet = AccessController
               .doPrivileged((PrivilegedAction<Set<T>>) () -> subject.getPrivateCredentials(credentialClass));
         }
         if (!credentialSet.isEmpty())
         {
            credential = credentialSet.iterator().next();
         }
      }
      return credential;
   }

   /**
    * Add the specified credential to the subject's private credentials set.
    *
    * @param subject the {@link Subject} to add the credential to.
    * @param credential a reference to the credential.
    */
   protected void addPrivateCredential(final Subject subject, final Object credential)
   {
      if (!WildFlySecurityManager.isChecking())
      {
         subject.getPrivateCredentials().add(credential);
      }
      else
      {
         AccessController.doPrivileged((PrivilegedAction<Void>) () ->
         {
            subject.getPrivateCredentials().add(credential);
            return null;
         });
      }
   }

   /**
    * {@inheritDoc}
    */
   @Override public String toString()
   {
      StringBuilder sb = new StringBuilder();

      sb.append("ElytronCallbackHandler@").append(Integer.toHexString(System.identityHashCode(this)));
      sb.append("[mappings=").append(mappings);
      sb.append("]");

      return sb.toString();
   }
}
