/*
 * IronJacamar, a Java EE Connector Architecture implementation
 * Copyright 2014, Red Hat Inc, and individual contributors
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

package org.ironjacamar.core;

import javax.security.auth.Subject;

import org.jboss.logging.BasicLogger;
import org.jboss.logging.annotations.Cause;
import org.jboss.logging.annotations.LogMessage;
import org.jboss.logging.annotations.Message;
import org.jboss.logging.annotations.MessageLogger;

import static org.jboss.logging.Logger.Level.ERROR;
import static org.jboss.logging.Logger.Level.INFO;
import static org.jboss.logging.Logger.Level.WARN;

/**
 * The core logger.
 *
 * Message ids ranging from 000000 to 009999 inclusively.
 */
@MessageLogger(projectCode = "IJ2")
public interface CoreLogger extends BasicLogger
{

   // WORK MANAGER (200)

   /**
    * SecurityContext setup failed
    * @param description throwable description
    * @param t The exception
    */
   @LogMessage(level = ERROR)
   @Message(id = 201, value = "SecurityContext setup failed: %s")
   public void securityContextSetupFailed(String description, @Cause Throwable t);

   /**
    * SecurityContext setup failed since CallbackSecurity was null
    */
   @LogMessage(level = ERROR)
   @Message(id = 202, value = "SecurityContext setup failed since CallbackSecurity was null")
   public void securityContextSetupFailedCallbackSecurityNull();

   // CORE (300)

   /**
    * Error during beforeCompletion
    * @param cl AbstractConnectionListener instance
    * @param t The exception
    */
   @LogMessage(level = WARN)
   @Message(id = 314, value = "Error during beforeCompletion: %s")
   public void beforeCompletionErrorOccured(Object cl, @Cause Throwable t);

   /**
    * Active handles
    * @param pool The name of the pool
    * @param number The number of active handles
    */
   @LogMessage(level = ERROR)
   @Message(id = 315, value = "Pool %s has %d active handles")
   public void activeHandles(String pool, int number);

   /**
    * Active handle
    * @param handle The handle
    * @param e The trace
    */
   @LogMessage(level = ERROR)
   @Message(id = 316, value = "Handle allocation: %s")
   public void activeHandle(Object handle, @Cause Exception e);

   /**
    * TxConnectionListener boundary
    * @param e The trace
    */
   @LogMessage(level = ERROR)
   @Message(id = 317, value = "Transaction boundary")
   public void txConnectionListenerBoundary(@Cause Exception e);

   // NAMING (700)

   /**
    * Exception during unbind
    * @param t The exception
    */
   @LogMessage(level = WARN)
   @Message(id = 701, value = "Exception during unbind")
   public void exceptionDuringUnbind(@Cause Throwable t);

   // RECOVERY (900)

   /**
    * Error during connection close
    * @param t The exception
    */
   @LogMessage(level = WARN)
   @Message(id = 901, value = "Error during connection close")
   public void exceptionDuringConnectionClose(@Cause Throwable t);

   /**
    * Error during inflow crash recovery
    * @param rar The resource adapter class name
    * @param as The activation spec
    * @param t The exception
    */
   @LogMessage(level = ERROR)
   @Message(id = 902, value = "Error during inflow crash recovery for '%s' (%s)")
   public void exceptionDuringCrashRecoveryInflow(String rar, Object as, @Cause Throwable t);
   
   /**
    * Error creating Subject for crash recovery
    * @param jndiName The JNDI name
    * @param reason The reason
    * @param t The exception
    */
   @LogMessage(level = ERROR)
   @Message(id = 903, value = "Error creating Subject for crash recovery: %s (%s)")
   public void exceptionDuringCrashRecoverySubject(String jndiName, String reason, @Cause Throwable t);
   
   /**
    * No security domain defined for crash recovery
    * @param jndiName The JNDI name
    */
   @LogMessage(level = WARN)
   @Message(id = 904, value = "No security domain defined for crash recovery: %s")
   public void noCrashRecoverySecurityDomain(String jndiName);

   /**
    * Subject for crash recovery was null
    * @param jndiName The JNDI name
    */
   @LogMessage(level = WARN)
   @Message(id = 905, value = "Subject for crash recovery was null: %s")
   public void nullSubjectCrashRecovery(String jndiName);

   /**
    * Error during crash recovery
    * @param jndiName The JNDI name
    * @param reason The reason
    * @param t The exception
    */
   @LogMessage(level = ERROR)
   @Message(id = 906, value = "Error during crash recovery: %s (%s)")
   public void exceptionDuringCrashRecovery(String jndiName, String reason, @Cause Throwable t);

   // SECURITY (1000)

   /**
    * No users.properties were found
    */
   @LogMessage(level = WARN)
   @Message(id = 1001, value = "No users.properties were found")
   public void noUsersPropertiesFound();

   /**
    * Error while loading users.properties
    * @param t The exception
    */
   @LogMessage(level = ERROR)
   @Message(id = 1002, value = "Error while loading users.properties")
   public void errorWhileLoadingUsersProperties(@Cause Throwable t);

   /**
    * No roles.properties were found
    */
   @LogMessage(level = WARN)
   @Message(id = 1003, value = "No roles.properties were found")
   public void noRolesPropertiesFound();

   /**
    * Error while loading roles.properties
    * @param t The exception
    */
   @LogMessage(level = ERROR)
   @Message(id = 1004, value = "Error while loading roles.properties")
   public void errorWhileLoadingRolesProperties(@Cause Throwable t);

   /**
    * No callback.properties were found
    */
   @LogMessage(level = WARN)
   @Message(id = 1005, value = "No callback.properties were found")
   public void noCallbackPropertiesFound();

   /**
    * Error while loading callback.properties
    * @param t The exception
    */
   @LogMessage(level = ERROR)
   @Message(id = 1006, value = "Error while loading callback.properties")
   public void errorWhileLoadingCallbackProperties(@Cause Throwable t);


   // TRANSCATION (1100)

   /**
    * Prepare called on a local tx
    */
   @LogMessage(level = WARN)
   @Message(id = 1101, value = "Prepare called on a local tx. Use of local transactions on a JTA " +
         "transaction with more than one branch may result in inconsistent data in some cases of failure")
   public void prepareCalledOnLocaltx();

   // ELYTRON

   /**
    * Notify that Elytron is handling callbacks.
    *
    * @param callbacks callbacks
    */
   @LogMessage(level = INFO)
   @Message(id = 1102, value = "Elytron handler handle: %s")
   void elytronHandlerHandle(String callbacks);

   /**
    * Execution subject is missing.
    *
    * @return the security exception
    */
   @Message(id = 1103, value = "Execution subject was not provided to the callback handler")
   SecurityException executionSubjectNotSetInHandler();

   /**
    * Missing callback with security domain info.
    * @return the unsupported operation exception
    */
   @Message(id = 1104, value = "Callback with security domain is required - use createCallbackHandler"
      + "(Callback callback) instead")
   UnsupportedOperationException unsupportedCreateCallbackHandlerMethod();

   /**
    * Callback missing security domain reference.
    * @return the illegal argument exception
    */
   @Message(id = 1105, value = "Supplied callback doesn't contain a security domain reference")
   IllegalArgumentException invalidCallbackSecurityDomain();

   /**
    * Message informing about subject and identity.
    * @param subject  the subject
    * @param identity the identity
    * @return the message
    */
   @Message(id = 1106, value = "Subject=%s\nSubject identity=%s")
   String subject(Subject subject, String identity);
}
