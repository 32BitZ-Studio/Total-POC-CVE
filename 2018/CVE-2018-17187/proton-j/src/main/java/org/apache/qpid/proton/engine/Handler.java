/*
 *
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 *
 */
package org.apache.qpid.proton.engine;

import java.util.Iterator;


/**
 * Handler
 *
 */

public interface Handler
{
    /**
     * Handle the event in this instance. This is the second half of
     * {@link Event#dispatch(Handler)}. The method must invoke a concrete onXxx
     * method for the given event, or invoke it's {@link #onUnhandled(Event)}
     * method if the {@link EventType} of the event is not recognized by the
     * handler.
     * <p>
     * <b>Note:</b> The handler is not supposed to invoke the
     * {@link #handle(Event)} method on it's {@link #children()}, that is the
     * responsibility of the {@link Event#dispatch(Handler)}
     *
     * @see BaseHandler
     * @param e
     *            The event to handle
     */
    void handle(Event e);

    void onUnhandled(Event e);

    void add(Handler child);

    Iterator<Handler> children();
}
