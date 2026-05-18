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

import org.apache.seatunnel.api.configuration.ReadonlyConfig;
import org.apache.seatunnel.api.source.Collector;
import org.apache.seatunnel.api.table.type.SeaTunnelRow;
import org.apache.seatunnel.connectors.seatunnel.syslog.config.SyslogConfig;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

public class SyslogSourceReaderTest {

    @Test
    public void testParseRfc3164_standard() {
        // Example from RFC 3164 section 5.4
        String line =
                "<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8";
        SeaTunnelRow row = SyslogSourceReader.parseRfc3164(line);

        Assertions.assertNotNull(row);
        // PRI=34 => facility=4 (auth), severity=2 (CRITICAL)
        Assertions.assertEquals(4, row.getField(0));
        Assertions.assertEquals(2, row.getField(1));
        Assertions.assertEquals("Oct 11 22:14:15", row.getField(2));
        Assertions.assertEquals("mymachine", row.getField(3));
        Assertions.assertEquals("su", row.getField(4));
        Assertions.assertEquals("", row.getField(5));
        Assertions.assertEquals("'su root' failed for lonvick on /dev/pts/8", row.getField(6));
    }

    @Test
    public void testParseRfc3164_withProcId() {
        String line =
                "<165>Aug 24 05:14:15 192.0.2.1 myproc[10]: %% It's time to make the doughnuts.";
        SeaTunnelRow row = SyslogSourceReader.parseRfc3164(line);

        Assertions.assertNotNull(row);
        // PRI=165 => facility=20 (local4), severity=5 (NOTICE)
        Assertions.assertEquals(20, row.getField(0));
        Assertions.assertEquals(5, row.getField(1));
        Assertions.assertEquals("Aug 24 05:14:15", row.getField(2));
        Assertions.assertEquals("192.0.2.1", row.getField(3));
        Assertions.assertEquals("myproc", row.getField(4));
        Assertions.assertEquals("10", row.getField(5));
        Assertions.assertEquals("%% It's time to make the doughnuts.", row.getField(6));
    }

    @Test
    public void testParseRfc3164_singleDigitDay() {
        // Day with leading space (RFC 3164 uses space-padding for single-digit days)
        String line = "<13>Jan  5 10:00:00 host1 kernel: some kernel message";
        SeaTunnelRow row = SyslogSourceReader.parseRfc3164(line);

        Assertions.assertNotNull(row);
        Assertions.assertEquals(1, row.getField(0)); // facility=1 (user)
        Assertions.assertEquals(5, row.getField(1)); // severity=5 (NOTICE)
        Assertions.assertEquals("host1", row.getField(3));
        Assertions.assertEquals("kernel", row.getField(4));
        Assertions.assertEquals("some kernel message", row.getField(6));
    }

    @Test
    public void testParseRfc3164_nullInput() {
        Assertions.assertNull(SyslogSourceReader.parseRfc3164(null));
    }

    @Test
    public void testParseRfc3164_emptyInput() {
        Assertions.assertNull(SyslogSourceReader.parseRfc3164(""));
    }

    @Test
    public void testParseRfc3164_malformedNoPri() {
        // Missing PRI field
        String line = "Oct 11 22:14:15 mymachine su: message";
        Assertions.assertNull(SyslogSourceReader.parseRfc3164(line));
    }

    @Test
    public void testParseRfc3164_severityExtraction() {
        // PRI=0 => facility=0 (kern), severity=0 (EMERGENCY)
        String line = "<0>Jan  1 00:00:00 router kernel: panic";
        SeaTunnelRow row = SyslogSourceReader.parseRfc3164(line);
        Assertions.assertNotNull(row);
        Assertions.assertEquals(0, row.getField(0));
        Assertions.assertEquals(0, row.getField(1));
    }

    @Test
    public void testReaderLifecycle_endToEndOverTcp() throws Exception {
        int port;
        try (ServerSocket probe = new ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))) {
            port = probe.getLocalPort();
        }

        Map<String, Object> options = new HashMap<>();
        options.put("host", "127.0.0.1");
        options.put("port", port);
        SyslogConfig config = new SyslogConfig(ReadonlyConfig.fromMap(options));

        SyslogSourceReader reader = new SyslogSourceReader(config, null);
        BlockingQueue<SeaTunnelRow> emitted = new LinkedBlockingQueue<>();
        Collector<SeaTunnelRow> collector =
                new Collector<SeaTunnelRow>() {
                    private final Object lock = new Object();

                    @Override
                    public void collect(SeaTunnelRow record) {
                        emitted.add(record);
                    }

                    @Override
                    public Object getCheckpointLock() {
                        return lock;
                    }
                };

        ExecutorService executor = Executors.newSingleThreadExecutor();
        Future<?> readerFuture = null;
        try {
            reader.open();
            readerFuture =
                    executor.submit(
                            () -> {
                                try {
                                    reader.pollNext(collector);
                                } catch (Exception ignored) {
                                    // SocketException on close() is expected
                                }
                            });

            String line =
                    "<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8";
            try (Socket client = new Socket("127.0.0.1", port);
                    OutputStream out = client.getOutputStream()) {
                out.write((line + "\n").getBytes(StandardCharsets.UTF_8));
                out.flush();
            }

            SeaTunnelRow row = emitted.poll(5, TimeUnit.SECONDS);
            Assertions.assertNotNull(row, "Reader did not emit a row within 5 seconds");
            Assertions.assertEquals(4, row.getField(0));
            Assertions.assertEquals(2, row.getField(1));
            Assertions.assertEquals("Oct 11 22:14:15", row.getField(2));
            Assertions.assertEquals("mymachine", row.getField(3));
            Assertions.assertEquals("su", row.getField(4));
            Assertions.assertEquals("", row.getField(5));
            Assertions.assertEquals("'su root' failed for lonvick on /dev/pts/8", row.getField(6));
        } finally {
            reader.close();
            if (readerFuture != null) {
                try {
                    readerFuture.get(5, TimeUnit.SECONDS);
                } catch (Exception ignored) {
                    // best-effort wait for the background poll loop to exit
                }
            }
            executor.shutdownNow();
            executor.awaitTermination(5, TimeUnit.SECONDS);
        }
    }
}
