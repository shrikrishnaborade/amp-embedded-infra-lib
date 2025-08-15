#ifndef PPP_OVER_SERIAL_PORT_ADAPTER_HPP
#define PPP_OVER_SERIAL_PORT_ADAPTER_HPP

#include "infra/event/QueueForOneReaderOneIrqWriter.hpp"
#include "infra/stream/OutputStream.hpp"
#include "infra/timer/Timer.hpp"
#include "infra/util/AutoResetFunction.hpp"
#include "infra/util/BoundedString.hpp"
#include "infra/util/ByteRange.hpp"
#include "lwip/lwip_pppos/PppInterface.hpp"
#include "lwip/netif.h"
#include "netif/ppp/pppos.h"
#include "services/tracer/StreamWriterOnSerialCommunication.hpp"
#include "services/tracer/Tracer.hpp"

namespace services
{
    class PppFacade
        : public Ppp
    {
    public:
        PppFacade(services::Tracer& tracer, hal::SerialCommunication& usart, netif& pppos_netif, infra::MemoryRange<uint8_t> initialLcpData);
        ~PppFacade();

        // Ppp
        void Connect() override;
        void Disconnect() override;

    private:
        services::Tracer& tracer;
        hal::SerialCommunication& usart;
        netif& ppposNetif;
        ppp_pcb* ppp;
        infra::AutoResetFunction<void(bool)> onDone;

        std::array<uint8_t, 4096u> txBuffer;
        infra::QueueForOneReaderOneIrqWriter<uint8_t>::WithStorage<4096u> receivedData;
        services::StreamWriterOnSerialCommunication streamWriterOnSerialCommunication;
        infra::DataOutputStream::WithErrorPolicy writeStream;
        infra::ByteRange initialLcpData;
        infra::TimerSingleShot waitTimer;

        void TrySend();
        static uint32_t WriteData(ppp_pcb* pcb, const void* data, uint32_t len, void* ctx);
        static void LinkStatus(ppp_pcb* pcb, int errorCode, void* ctx);

        void LinkStatusIndication(ppp_pcb* pcb, int errorCode);
        uint32_t Write(ppp_pcb* pcb, const void* data, uint32_t len);
        void HandleReceivedData(infra::ConstByteRange data);
    };
}

#endif
