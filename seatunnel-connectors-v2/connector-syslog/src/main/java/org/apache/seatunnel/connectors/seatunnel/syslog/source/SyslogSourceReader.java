/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.seatunnel.connectors.seatunnel.syslog.source;

import org.apache.seatunnel.api.source.Boundedness;
import org.apache.seatunnel.api.source.Collector;
import org.apache.seatunnel.api.table.type.SeaTunnelRow;
import org.apache.seatunnel.connectors.seatunnel.common.source.AbstractSingleSplitReader;
import org.apache.seatunnel.connectors.seatunnel.common.source.SingleSplitReaderContext;
import org.apache.seatunnel.connectors.seatunnel.syslog.config.SyslogConfig;
import org.apache.seatunnel.connectors.seatunnel.syslog.exception.SyslogConnectorErrorCode;
import org.apache.seatunnel.connectors.seatunnel.syslog.exception.SyslogConnectorException;

import lombok.extern.slf4j.Slf4j;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Slf4j
public class SyslogSourceReader extends AbstractSingleSplitReader<SeaTunnelRow> {

    /**
     * RFC 3164 pattern: <PRI>TIMESTAMP HOSTNAME APP_NAME[PID]: MESSAGE
     *
     * <p>Groups: 1=PRI, 2=TIMESTAMP, 3=HOSTNAME, 4=APP_NAME, 5=PID (optional), 6=MESSAGE
     */
    private static final Pattern RFC3164_PATTERN =
            Pattern.compile(
                    "^<(\\d{1,3})>"
                            + "(\\w{3}\\s+\\d{1,2}\\s+\\d{2}:\\d{2}:\\d{2})"
                            + "\\s+(\\S+)"
                            + "\\s+(\\S+?)(?:\\[(\\w+)\\])?:?\\s*"
                            + "(.*)$");

    /** Accept timeout in milliseconds — allows the reader to notice a close() call. */
    private static final int ACCEPT_TIMEOUT_MS = 500;

    private final SyslogConfig config;
    private final SingleSplitReaderContext context;
    private ServerSocket serverSocket;

    SyslogSourceReader(SyslogConfig config, SingleSplitReaderContext context) {
        this.config = config;
        this.context = context;
    }

    @Override
    public void open() throws Exception {
        InetAddress bindAddress = InetAddress.getByName(config.getHost());
        try {
            serverSocket = new ServerSocket(config.getPort(), 50, bindAddress);
            serverSocket.setSoTimeout(ACCEPT_TIMEOUT_MS);
            log.info("Syslog source listening on {}:{}", config.getHost(), config.getPort());
        } catch (IOException e) {
            throw new SyslogConnectorException(
                    SyslogConnectorErrorCode.SERVER_BIND_FAILED,
                    "Cannot bind to " + config.getHost() + ":" + config.getPort(),
                    e);
        }
    }

    @Override
    public void close() throws IOException {
        if (serverSocket != null && !serverSocket.isClosed()) {
            serverSocket.close();
        }
    }

    @Override
    public void pollNext(Collector<SeaTunnelRow> output) throws Exception {
        while (!serverSocket.isClosed()) {
            try {
                Socket clientSocket = serverSocket.accept();
                log.debug(
                        "Accepted syslog connection from {}",
                        clientSocket.getRemoteSocketAddress());
                processConnection(clientSocket, output);
                if (Boundedness.BOUNDED.equals(context.getBoundedness())) {
                    context.signalNoMoreElement();
                    return;
                }
            } catch (SocketTimeoutException e) {
                // no incoming connection within the timeout window — loop again
            }
        }
    }

    /**
     * Reads newline-delimited syslog messages from a client connection and emits parsed rows.
     * Closes the client socket when the connection is terminated by the sender.
     */
    private void processConnection(Socket clientSocket, Collector<SeaTunnelRow> output) {
        try (Socket socket = clientSocket;
                BufferedReader reader =
                        new BufferedReader(new InputStreamReader(socket.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                SeaTunnelRow row = parseRfc3164(line);
                if (row != null) {
                    output.collect(row);
                } else {
                    log.warn("Skipping malformed syslog line: {}", line);
                }
            }
        } catch (IOException e) {
            log.warn("Error reading from syslog client connection: {}", e.getMessage());
        }
    }

    /**
     * Parses a single RFC 3164 syslog message into a SeaTunnelRow.
     *
     * <p>Output columns: facility (INT), severity (INT), timestamp (STRING), hostname (STRING),
     * app_name (STRING), proc_id (STRING), message (STRING).
     *
     * @param line raw syslog line
     * @return parsed row, or null if the line does not match RFC 3164 format
     */
    static SeaTunnelRow parseRfc3164(String line) {
        if (line == null || line.isEmpty()) {
            return null;
        }
        Matcher matcher = RFC3164_PATTERN.matcher(line);
        if (!matcher.matches()) {
            return null;
        }

        int pri = Integer.parseInt(matcher.group(1));
        int facility = pri >> 3;
        int severity = pri & 0x07;
        String timestamp = matcher.group(2).trim();
        String hostname = matcher.group(3);
        String appName = matcher.group(4);
        String procId = matcher.group(5) != null ? matcher.group(5) : "";
        String message = matcher.group(6);

        return new SeaTunnelRow(
                new Object[] {facility, severity, timestamp, hostname, appName, procId, message});
    }
}
