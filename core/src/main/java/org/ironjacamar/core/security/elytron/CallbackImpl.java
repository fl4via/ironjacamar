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

import java.util.Map;

/**
 * Extension of CallbackImpl with added support for Elytron.
 *
 * @author Flavia Rainone
 */
public class CallbackImpl extends org.ironjacamar.core.security.CallbackImpl
{

   private boolean elytronEnabled;

   /**
    * Create Callback.
    *
    * @param mappingRequired  mapping required
    * @param domain           domain
    * @param elytronEnabled   indicates if elytron is enabled
    * @param defaultPrincipal the default principal
    * @param defaultGroups    default groups
    * @param principals       mapping of principals
    * @param groups           mapping of groups
    */
   public CallbackImpl(boolean mappingRequired, String domain, boolean elytronEnabled, String defaultPrincipal,
      String[] defaultGroups, Map<String, String> principals, Map<String, String> groups)
   {
      super(mappingRequired, domain, defaultPrincipal, defaultGroups, principals, groups);
      this.elytronEnabled = elytronEnabled;
   }

   /**
    * Indicates if Elytron integration is enabled.
    * @return {@code true} if Elytron integration is enabled
    */
   public boolean isElytronEnabled()
   {
      return elytronEnabled;
   }
}
