#include "services/tracer/StreamWriterOnSerialCommunication.hpp"
#include <chrono>

namespace services
{
    StreamWriterOnSerialCommunication::StreamWriterOnSerialCommunication(infra::ByteRange bufferStorage, hal::SerialCommunication& communication, infra::Duration timeout)
        : buffer(bufferStorage)
        , communication(communication)
        , timeout(timeout)
    {}

    void StreamWriterOnSerialCommunication::Insert(infra::ConstByteRange range, infra::StreamErrorPolicy& errorPolicy)
    {
        range.shrink_from_back_to(buffer.Available());
        buffer.Push(range);

        if (timeout != std::chrono::milliseconds(0))
        {
            if (txTimeoutTimer.Armed())
            {
                txTimeoutTimer.Cancel();
            }
            txTimeoutTimer.Start(timeout, [this]()
                {
                    TrySend();
                });
        }
        else
        {
            TrySend();
        }
    }

    std::size_t StreamWriterOnSerialCommunication::Available() const
    {
        return std::numeric_limits<size_t>::max();
    }

    void StreamWriterOnSerialCommunication::TrySend()
    {
        if (!buffer.Empty() && !communicating)
        {
            communicating = true;

            uint32_t size = buffer.ContiguousRange().size();
            communication.SendData(buffer.ContiguousRange(), [this, size]()
                {
                    CommunicationDone(size);
                });
        }
    }

    void StreamWriterOnSerialCommunication::CommunicationDone(uint32_t size)
    {
        communicating = false;
        buffer.Pop(size);

        TrySend();
    }
}
