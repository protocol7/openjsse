package org.openjsse.sun.security.ssl;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.text.MessageFormat;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

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

    static void copyTransParamsTo(HandshakeContext hc, SSLSession session) {
        QUICTransParamsSpec spec = (QUICTransParamsSpec) hc.handshakeExtensions.get(
                hc instanceof ServerHandshakeContext ?
                        SSLExtension.CH_QUIC_TRANS_PARAMS :
                        SSLExtension.EE_QUIC_TRANS_PARAMS);

        assert session.isValid();
        if (spec != null) {
            ((SSLSessionImpl) session).setQUICTransParams(ByteBuffer.wrap(spec.data).asReadOnlyBuffer());
        }
    }

    static final class QUICTransParamsSpec implements SSLExtensionSpec {
        byte[] data = null;

        QUICTransParamsSpec() {
            // blank
        }

        void consume(ByteBuffer buffer) {
            data = new byte[buffer.remaining()];
            buffer.get(data);
        }

        byte[] produce() throws IOException {
            return data.clone();
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
                        hc.handshakeExtensions.get(SSLExtension.CH_QUIC_TRANS_PARAMS);
            } else {
                spec = (QUICTransParamsSpec)
                        hc.handshakeExtensions.get(SSLExtension.EE_QUIC_TRANS_PARAMS);
            }

            if (spec == null) {
                spec = new QUICTransParamsSpec();
            }

            spec.consume(buffer);

            if (context instanceof ServerHandshakeContext) {
                hc.handshakeExtensions.put(SSLExtension.CH_QUIC_TRANS_PARAMS, spec);
            } else {
                hc.handshakeExtensions.put(SSLExtension.EE_QUIC_TRANS_PARAMS, spec);
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

            if (hc.sslConfig.quicTransParams == null) {
                return null;
            }

            if (context instanceof ServerHandshakeContext) {
                spec = (QUICTransParamsSpec)
                        hc.handshakeExtensions.get(SSLExtension.EE_QUIC_TRANS_PARAMS);
            } else {
                spec = (QUICTransParamsSpec)
                        hc.handshakeExtensions.get(SSLExtension.CH_QUIC_TRANS_PARAMS);
            }

            if (spec == null) {
                spec = new QUICTransParamsSpec();
            }

            spec.consume(hc.sslConfig.quicTransParams.duplicate());

            if (context instanceof ServerHandshakeContext) {
                hc.handshakeExtensions.put(SSLExtension.EE_QUIC_TRANS_PARAMS, spec);
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
            byte [] data = new byte[buffer.remaining()];
            buffer.get(data);
            return "data = {" + Utilities.toHexString(data) + "}";
        }
    }
}
