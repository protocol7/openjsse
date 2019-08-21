package org.openjsse.sun.security.ssl;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.text.MessageFormat;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;

import org.openjsse.sun.security.ssl.SSLExtension.ExtensionConsumer;
import org.openjsse.sun.security.ssl.SSLExtension.SSLExtensionSpec;
import org.openjsse.sun.security.ssl.SSLHandshake.HandshakeMessage;

final class QUICTransParamsExtension {
    static final HandshakeProducer networkProducer =
            new QUICTransParamsProducer();
    static final ExtensionConsumer onLoadConsumer =
            new QUICTransParamsConsumer();
    static final SSLStringizer stringizer =
            new QUICTransParamsStringizer();

    enum TransportParameterId {
        original_connection_id(0),
        idle_timeout(1),
        stateless_reset_token(2),
        max_packet_size(3),
        initial_max_data(4),
        initial_max_stream_data_bidi_local(5),
        initial_max_stream_data_bidi_remote(6),
        initial_max_stream_data_uni(7),
        initial_max_streams_bidi(8),
        initial_max_streams_uni(9),
        ack_delay_exponent(10),
        max_ack_delay(11),
        disable_migration(12),
        preferred_address(13),
        active_connection_id_limit(14);

        static final TransportParameterId[] idMap = new TransportParameterId[16];

        static {
            for (TransportParameterId value : values()) {
                idMap[value.id] = value;
            }
        }

        static TransportParameterId get(int id) {
            TransportParameterId out = idMap[id];
            if (out == null) {
                throw new IllegalArgumentException("Unknown QUIC Transport Param: " + id);
            }
            return out;
        }

        final int id;

        TransportParameterId(int id) {
            this.id = id;
        }
    }

    static void copyTransParamsTo(HandshakeContext hc, SSLSession session) {
        QUICTransParamsSpec spec = (QUICTransParamsSpec) hc.handshakeExtensions.get(SSLExtension.SH_QUIC_TRANS_PARAMS);

        if (spec == null) {
            spec = (QUICTransParamsSpec) hc.handshakeExtensions.get(SSLExtension.CH_QUIC_TRANS_PARAMS);
        }

        if (spec != null) {
            for (HashMap.Entry<TransportParameterId, Object> entry : spec.params.entrySet()) {
                session.putValue(entry.getKey().toString(), entry.getValue());
            }
        }
    }

    static final class QUICTransParamsSpec implements SSLExtensionSpec {
        final HashMap<TransportParameterId, Object> params = new HashMap<>();

        {
            params.put(TransportParameterId.disable_migration, false);
            params.put(TransportParameterId.active_connection_id_limit, 0L);
        }

        QUICTransParamsSpec() {
            // blank
        }

        void copyParamsFrom(Map<String, Object> stringParams) {
            for (TransportParameterId param : TransportParameterId.values()) {
                Object value = stringParams.get(param.name());
                if (value != null) {
                    params.put(param, value);
                }
            }
        }

        void consume(ByteBuffer buffer) throws IOException {
            while (buffer.hasRemaining()) {
                TransportParameterId key = TransportParameterId.get(Record.getInt16(buffer));
                Object value;
                switch (key) {
                    case original_connection_id: {
                        byte[] bytes = new byte[Record.getInt8(buffer)];
                        buffer.get(bytes);
                        value = bytes;
                        break;
                    }
                    case stateless_reset_token: {
                        byte[] bytes = new byte[16];
                        buffer.get(bytes);
                        value = bytes;
                        break;
                    }
                    case disable_migration:
                        value = true;
                        break;
                    case preferred_address: //TODO: Preferred Address format
                        throw new UnsupportedOperationException();
                    default:
                        value = Record.getVariableInt(buffer);
                }
                params.put(key, value);
            }
        }

        byte[] produce() throws IOException {
            ByteBuffer buffer = ByteBuffer.allocate(2048);

            for (HashMap.Entry<TransportParameterId, Object> entry : params.entrySet()) {
                if (entry.getKey() == TransportParameterId.disable_migration
                        && !Boolean.TRUE.equals(entry.getValue())) {
                    continue;
                }

                Record.putInt16(buffer, entry.getKey().id);
                switch (entry.getKey()) {
                    case original_connection_id: {
                        byte[] bytes = (byte[])entry.getValue();
                        Record.putInt8(buffer, bytes.length);
                        buffer.put(bytes);
                        break;
                    }
                    case stateless_reset_token: {
                        byte[] bytes = (byte[])entry.getValue();
                        assert bytes.length == 16;
                        buffer.put(bytes);
                        break;
                    }
                    case disable_migration:
                        break;
                    case preferred_address: //TODO: Preferred Address format
                        throw new UnsupportedOperationException();
                    default:
                        Record.putVariableInt(buffer, (long)entry.getValue());
                }
            }

            buffer.flip();

            byte[] out = new byte[buffer.remaining()];
            buffer.get(out);
            return out;
        }

        @Override
        public String toString() {
            MessageFormat rowFormat = new MessageFormat(
                    "\"{0}\": {1}\n", Locale.ENGLISH);

            StringBuilder builder = new StringBuilder(1024);
            for (HashMap.Entry entry : params.entrySet()) {
                builder.append(rowFormat.format(
                        new Object[]{entry.getKey(), entry.getValue()}));

            }

            return Utilities.indent(builder.toString());
        }
    }

    private static final
            class QUICTransParamsConsumer implements ExtensionConsumer {
        // Prevent instantiation of this class.
        private QUICTransParamsConsumer() {
            // blank
        }

        @Override
        public void consume(ConnectionContext context,
                HandshakeMessage message,
                ByteBuffer buffer) throws IOException {
            HandshakeContext hc = (HandshakeContext)context;
            QUICTransParamsSpec spec;

            if (context instanceof ServerHandshakeContext) {
                spec = (QUICTransParamsSpec)
                        hc.handshakeExtensions.get(SSLExtension.SH_QUIC_TRANS_PARAMS);
            } else {
                spec = (QUICTransParamsSpec)
                        hc.handshakeExtensions.get(SSLExtension.CH_QUIC_TRANS_PARAMS);
            }

            if (spec == null) {
                spec = new QUICTransParamsSpec();
            }

            spec.consume(buffer);

            if (context instanceof ServerHandshakeContext) {
                hc.handshakeExtensions.put(SSLExtension.SH_QUIC_TRANS_PARAMS, spec);
            } else {
                hc.handshakeExtensions.put(SSLExtension.CH_QUIC_TRANS_PARAMS, spec);
            }
        }
    }

    private static final
            class QUICTransParamsProducer implements HandshakeProducer {
        // Prevent instantiation of this class.
        private QUICTransParamsProducer() {
            // blank
        }

        @Override
        public byte[] produce(ConnectionContext context,
                HandshakeMessage message) throws IOException {
            HandshakeContext hc = (HandshakeContext)context;
            QUICTransParamsSpec spec;

            if (context instanceof ServerHandshakeContext) {
                spec = (QUICTransParamsSpec)
                        hc.handshakeExtensions.get(SSLExtension.SH_QUIC_TRANS_PARAMS);
            } else {
                spec = (QUICTransParamsSpec)
                        hc.handshakeExtensions.get(SSLExtension.CH_QUIC_TRANS_PARAMS);
            }

            if (spec == null) {
                spec = new QUICTransParamsSpec();
            }

            spec.copyParamsFrom(hc.sslConfig.quicTransParams);

            if (context instanceof ServerHandshakeContext) {
                hc.handshakeExtensions.put(SSLExtension.SH_QUIC_TRANS_PARAMS, spec);
            } else {
                hc.handshakeExtensions.put(SSLExtension.CH_QUIC_TRANS_PARAMS, spec);
            }

            return spec.produce();
        }
    }

    private static final
            class QUICTransParamsStringizer implements SSLStringizer {
        @Override
        public String toString(ByteBuffer buffer) {
            try {
                QUICTransParamsSpec spec = new QUICTransParamsSpec();
                spec.consume(buffer);
                return spec.toString();
            } catch (IOException ioe) {
                // For debug logging only, so please swallow exceptions.
                return ioe.getMessage();
            }
        }
    }
}
