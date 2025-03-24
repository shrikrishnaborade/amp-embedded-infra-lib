
#include "lwip/lwip_pppos/DialUpModem.hpp"
#include "hal/interfaces/SerialCommunication.hpp"
#include "infra/stream/StreamManipulators.hpp"
#include "infra/util/Observer.hpp"
#include "infra/util/Optional.hpp"
#include "lwip/lwip_pppos/PppFacade.hpp"
#include "lwip/lwip_pppos/PppInterface.hpp"
#include "lwip/lwip_pppos/ialUpModemStatus.hpp"
#include <chrono>
#include <cstddef>
#include <cstdlib>

namespace services
{
    DialUpModem::DialUpModem(services::Tracer& tracer, hal::SerialCommunication& modemUart)
        : tracer(tracer)
        , modemUart(modemUart)
        , state(infra::InPlaceType<StateIdle>(), *this)
    {}

    void DialUpModem::Disconnect()
    {
        tracer.Trace() << "DialUpModem: Disconnect";
        state->Disconnect();
    }

    void DialUpModem::Dial()
    {
        tracer.Trace() << "DialUpModem: Dial";
        state->Connect();
    }

    /// PPP connection observer
    void DialUpModem::Connected()
    {
        tracer.Trace() << "DialUpModem: ev ppp connected" << infra::endl;
        state->PppConnected();
    }

    /// PPP connection observer
    void DialUpModem::Disconnected()
    {
        tracer.Trace() << "DialUpModem: ev ppp disconnected" << infra::endl;
        state->PppDisconnected();
    }

    /// PPP connection observer
    void DialUpModem::Error(PppError error)
    {
        tracer.Trace() << "DialUpModem: ev ppp error: ";
        switch (error)
        {
            case PppError::Success:
                tracer.Continue() << "success";
                break;
            case PppError::ConnectionTimeout:
                tracer.Continue() << "connection timeout";
                break;
            case PppError::DisconnectFromPeer:
                tracer.Continue() << "Peer node has disocnnected the PPP link";
                break;
            case PppError::AuthenticationFailure:
                tracer.Continue() << "authentication failure";
                break;
            case PppError::ProtocolFailure:
                tracer.Continue() << "protocol failure";
                break;
            case PppError::Unknown:
                tracer.Continue() << "unknown";
                break;
            default:
                assert(false);
        }
        state->PppError();
    }

    DialUpModem::StateBase::StateBase(DialUpModem& parent)
        : parent(parent)
    {}

    DialUpModem::StateIdle::StateIdle(DialUpModem& parent)
        : StateBase(parent)
    {}

    void DialUpModem::StateIdle::Connect()
    {
        parent.InitiateConnect();
        parent.ToState<StateConnecting>();
    }

    DialUpModem::StateConnecting::StateConnecting(DialUpModem& parent)
        : StateBase(parent)
    {}

    void DialUpModem::StateConnecting::PppConnected()
    {
        parent.ToState<StateConnected>();
    }

    void DialUpModem::StateConnecting::PppDisconnected()
    {
        parent.ToState<StateDisconnected>();
    }

    void DialUpModem::StateConnecting::PppError()
    {
        parent.ToState<StateConnectionError>();
    }

    DialUpModem::StateConnected::StateConnected(DialUpModem& parent)
        : StateBase(parent)
    {
        parent.DialConnection::NotifyObservers([this](auto& obs)
            {
                obs.Connected();
            });
    }

    void DialUpModem::StateConnected::Disconnect()
    {
        parent.ToState<StateDisconnecting>();
    }

    void DialUpModem::StateConnected::PppError()
    {
        parent.ToState<StateConnectionError>();
    }

    DialUpModem::StateDisconnecting::StateDisconnecting(DialUpModem& parent)
        : StateBase(parent)
    {
        parent.pppState->Disconnect();
    }

    void DialUpModem::StateDisconnecting::PppDisconnected()
    {
        parent.ToState<StateDisconnected>();
    }

    DialUpModem::StateDisconnected::StateDisconnected(DialUpModem& parent)
        : StateBase(parent)
    {
        parent.DialConnection::SubjectType::NotifyObservers([this](auto& obs)
            {
                obs.Disconnected();
            });

        parent.DestroyPppMode();
        parent.ToState<StateIdle>();
    }

    DialUpModem::StateConnectionError::StateConnectionError(DialUpModem& parent)
        : StateBase(parent)
    {
        parent.DialConnection::SubjectType::NotifyObservers([this](auto& obs)
            {
                obs.Error(DialConnectionError::Unknown);
            });

        parent.DestroyPppMode();
        parent.ToState<StateIdle>();

        // TODO: Impleement retries to re-dial the connection
        parent.state->Connect();
    }

    void DialUpModem::InitiateConnect()
    {
        tracer.Trace() << "Dial-up modem: InitiateConnect";

        netif_set_default(&pppNetIf);

        CreatePppMode();
        pppState->Connect();
    }

    void DialUpModem::DestroyPppMode()
    {
        tracer.Trace() << "Dial-up modem: DestroyPppMode";

        PppObserver::Detach();
        pppState = infra::none;
    }

    void DialUpModem::CreatePppMode()
    {
        tracer.Trace() << "Dial-up modem: CreatePppMode";

        pppState.Emplace(this->tracer, modemUart, this->pppNetIf, infra::StringAsByteRange(this->additionalData));
        PppObserver::Attach(*pppState);
    }
};
