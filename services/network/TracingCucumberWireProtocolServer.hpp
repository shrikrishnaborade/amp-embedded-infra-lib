#ifndef SERVICES_TRACING_CUCUMBER_WIRE_PROTOCOL_SERVER_HPP
#define SERVICES_TRACING_CUCUMBER_WIRE_PROTOCOL_SERVER_HPP

#include "services/network/CucumberWireProtocolServer.hpp"
#include "services/tracer/Tracer.hpp"
#include "services/tracer/TracingOutputStream.hpp"

namespace services
{
    class TracingCucumberWireProtocolConnectionObserver
        : public CucumberWireProtocolConnectionObserver
    {
    public:
        TracingCucumberWireProtocolConnectionObserver(services::Tracer& tracer);

        // Implementation of ConnectionObserver
        virtual void SendStreamAvailable(infra::SharedPtr<infra::StreamWriter>&& writer) override;
        virtual void DataReceived() override;

    private:
        class TracingWriter
        {
        public:
            TracingWriter(infra::SharedPtr<infra::StreamWriter>&& writer, services::Tracer& tracer);

            infra::StreamWriter& Writer();

        private:
            infra::SharedPtr<infra::StreamWriter> writer;
            TracingStreamWriter tracingWriter;
        };

    private:
        services::Tracer& tracer;
        infra::SharedOptional<TracingWriter> tracingWriter;
    };

    class TracingCucumberWireProtocolServer
        : public services::SingleConnectionListener
    {
    public:
        TracingCucumberWireProtocolServer(services::ConnectionFactory& connectionFactory, uint16_t port, services::Tracer& tracer);

    private:
        services::Tracer& tracer;
        infra::Creator<services::ConnectionObserver, TracingCucumberWireProtocolConnectionObserver, void(services::IPAddress address)> connectionCreator;
    };
}

#endif
